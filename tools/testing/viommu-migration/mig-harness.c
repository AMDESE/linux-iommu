// SPDX-License-Identifier: GPL-2.0-only
/*
 * Exercise IOMMU_VIOMMU_MIG_STATE against a real AMD vIOMMU without a guest.
 *
 * Stands in for the parts of QEMU that a migration needs: allocate an IOAS as
 * nesting parent, bind a VFIO device to it, allocate an AMD vIOMMU on top, then
 * drive the migration state machine. No guest OS is involved, so the drain, the
 * log freeze and the completion fence can be checked on hardware long before
 * the QEMU side exists.
 *
 * Needs real hardware: an AMD IOMMU reporting the vIOMMU feature, and a VF
 * bound to vfio-pci. It is therefore not a kselftest and is not built by the
 * selftests Makefile. The mock-backed tests that do run anywhere live in
 * tools/testing/selftests/iommu/iommufd.c.
 *
 * Usage: mig-harness [mode] [pci-address]
 *
 *   default              state machine, fence, save, log capture, restore,
 *                        malformed payloads, ring destroy and commit-restore
 *   --probe              measure whether the command ring head pointer can
 *                        advance past a COMPLETION_WAIT before that command's
 *                        semaphore store is visible
 *   --abandon            exit midway through a migration, so that teardown has
 *                        to unwind it without an ABORT
 *   --drain              call PREPARE_SAVE on a ring with commands still in
 *                        flight
 *   --status             measure which guest status register bits hardware
 *                        sets and which a write can set or clear
 *   --status-raise-only  status probe, completion wait only, no register
 *                        writes
 *   --status-write-only  status probe, register writes only, no completion
 *                        wait
 *   --dirty              measure whether the nesting parent's dirty tracking
 *                        observes the writes the IOMMU makes itself, arming it
 *                        before the vIOMMU is allocated
 *   --dirty-late         the same measurement, arming after the vIOMMU is
 *                        allocated, which is the order a VMM would use
 *   --nested             combines with either dirty mode: put the device on a
 *                        nested domain first, so the DTE under test is the one
 *                        set_dte_nested() writes rather than a plain stage-2
 *                        one. The device is attached to the parent before the
 *                        nested domain replaces it, the order a VMM uses, which
 *                        leaves it on the parent's dev_list either way
 *   --nested-cold        as --nested, but the device never passes through the
 *                        parent, so it is on no dev_list and only the nested
 *                        list can carry a toggle to it. With --dirty-late the
 *                        attach samples tracking as off, which leaves that
 *                        walk as the one thing that can arm the DTE
 *   --grow               attach the device to a nested domain, then map at
 *                        rising IOVAs so the nest parent's table has to grow a
 *                        level, and report whether the nested DTE survives
 *                        amd_iommu_change_top() rebuilding it
 *   --reattach           attach to a nested domain, back to the nest parent,
 *                        and to the nested domain again, reporting the DTE at
 *                        each step
 *
 * --status-raise-only and --status-write-only isolate which half of the status
 * probe provokes a given IOMMU page fault.
 *
 * Default: 0000:e1:00.1
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include <linux/iommufd.h>
#include <linux/vfio.h>

/* Guest-visible register offsets within the VF MMIO page */
#define VF_CMD_HEAD	0x00
#define VF_CMD_TAIL	0x08
#define VF_EVT_HEAD	0x10
#define VF_EVT_TAIL	0x18
#define VF_STATUS	0x20

#define MAP_LEN		(2 * 1024 * 1024)

/*
 * AMD encodes the ring size as a power of two of 16-byte entries, so 8 means
 * 256 entries of 4096 bytes total. The semaphore lives past the end of the ring
 * so that planting commands never overwrites it.
 */
#define RING_LEN_ENCODED	8
#define RING_BYTES		(16U << RING_LEN_ENCODED)
#define RING_ENTRIES		(RING_BYTES / CMD_ENTRY_BYTES)
#define SEM_OFF			RING_BYTES
#define SEM_EXPECTED		0x123456789abcULL

/*
 * An event log ring, past the semaphore and page aligned because the base is
 * programmed as a page frame number. Deliberately a different size from the
 * command ring, so that a payload which decoded one ring's size register and
 * reported it for another would not go unnoticed.
 */
#define EVT_OFF			8192
#define EVT_LEN_ENCODED		5
#define EVT_BYTES		(16U << EVT_LEN_ENCODED)

/* A PPR log ring on its own page, used only by the destroy test */
#define PPR_OFF			12288
#define PPR_LEN_ENCODED		4
#define PPR_BYTES		(16U << PPR_LEN_ENCODED)

/* Inside the vIOMMU's address space but deliberately never mapped */
#define UNMAPPED_IOVA		0x40000000ULL

/*
 * The completion wait as the AMD driver builds it: the store address split
 * across the first two words with the store flag in the low bits it cannot use,
 * the opcode in the top nibble of the second, and the stored value last.
 */
#define CMD_COMPL_WAIT		0x01
#define CMD_COMPL_WAIT_STORE	0x01
#define CMD_COMPL_WAIT_INT	0x02
#define CMD_ENTRY_BYTES		16

/* Host Access Dirty in DTE[0], the bits that arm dirty tracking for a device */
#define DTE_FLAG_HAD		(3ULL << 7)

/*
 * The fields that tell a nested DTE from a plain stage-2 one. GV and the mode
 * live in DTE[0], the vIOMMU enable and the guest device ID in DTE[3]. Only
 * set_dte_nested() writes the latter two, so their absence means something
 * rebuilt the entry from the parent domain.
 */
#define DTE_FLAG_GV		(1ULL << 55)
#define DTE_MODE_MASK		(7ULL << 9)
#define DTE_MODE_SHIFT		9
#define DTE_VIOMMU_EN		(1ULL << 15)
#define DTE_VIOMMU_GDEVICEID	(0xffffULL << 16)

/*
 * The smallest guest DTE the driver will accept: valid and translation valid,
 * no guest CR3 so the GCR3 checks do not apply, and a zero paging mode meaning
 * four levels. Enough to reach set_dte_nested(), which is all this needs.
 */
#define GDTE_FLAG_V		(1ULL << 0)
#define GDTE_FLAG_TV		(1ULL << 1)
#define GDTE_DOMID		1
#define GDEVICE_ID		1

/* Bits of the status register at VF_STATUS */
#define STATUS_EVT_OVERFLOW	(1u << 0)
#define STATUS_EVT_LOG_INT	(1u << 1)
#define STATUS_COMWAIT_INT	(1u << 2)
#define STATUS_PPR_OVERFLOW	(1u << 5)
#define STATUS_PPR_INT		(1u << 6)

struct env {
	int iommufd;
	int cdev;
	uint32_t ioas_id;
	uint32_t dev_id;
	uint32_t parent_id;	/* nesting parent, the hwpt dirty tracking runs on */
	uint32_t viommu_id;
	uint32_t vdevice_id;
	uint32_t nested_id;	/* nested hwpt, zero unless --nested */
	uint32_t hw_queue_id;
	void *buf;		/* userspace view of the ring and semaphore */
	uint64_t iova;		/* same memory in the vIOMMU's address space */
	void *vfmmio;		/* the guest's own IOMMU register page */
};

static int failures;

static void ok(const char *what)
{
	printf("  ok      %s\n", what);
}

static void fail(const char *what, const char *detail)
{
	printf("  FAIL    %s: %s\n", what, detail);
	failures++;
}

static void die(const char *what)
{
	fprintf(stderr, "fatal: %s: %s\n", what, strerror(errno));
	exit(1);
}

/*
 * Report the errno an ioctl failed with, or 0 on success, so a caller can check
 * for an expected refusal as easily as for success.
 */
static int try_ioctl(int fd, unsigned long req, void *arg)
{
	if (ioctl(fd, req, arg))
		return errno ? errno : EIO;
	return 0;
}

static void expect(int fd, unsigned long req, void *arg, int want,
		   const char *what)
{
	char detail[128];
	int got = try_ioctl(fd, req, arg);

	if (got == want) {
		ok(what);
		return;
	}
	snprintf(detail, sizeof(detail), "expected %s, got %s",
		 want ? strerror(want) : "success",
		 got ? strerror(got) : "success");
	fail(what, detail);
}

/* /sys/bus/pci/devices/<pci>/vfio-dev/vfioN -> /dev/vfio/devices/vfioN */
static int open_vfio_cdev(const char *pci)
{
	char path[256], name[NAME_MAX + 1] = "";
	struct dirent *de;
	DIR *d;
	int fd;

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/vfio-dev", pci);
	d = opendir(path);
	if (!d) {
		fprintf(stderr,
			"fatal: %s missing. Bind the device to vfio-pci first:\n"
			"  echo vfio-pci > /sys/bus/pci/devices/%s/driver_override\n"
			"  echo %s > /sys/bus/pci/devices/%s/driver/unbind\n"
			"  echo %s > /sys/bus/pci/drivers_probe\n",
			path, pci, pci, pci, pci);
		exit(1);
	}
	while ((de = readdir(d)))
		if (!strncmp(de->d_name, "vfio", 4))
			snprintf(name, sizeof(name), "%s", de->d_name);
	closedir(d);

	if (!name[0]) {
		fprintf(stderr, "fatal: no vfio-dev entry under %s\n", path);
		exit(1);
	}

	snprintf(path, sizeof(path), "/dev/vfio/devices/%s", name);
	fd = open(path, O_RDWR);
	if (fd < 0)
		die(path);
	return fd;
}

static bool set_dirty_tracking(struct env *e, bool on);

/*
 * Move the device onto a nested domain, the way a guest driver programming its
 * own DTE would. The vdevice comes first because set_dte_nested() resolves the
 * guest device ID through it and refuses the attach without one.
 */
static void attach_nested(struct env *e)
{
	struct iommu_vdevice_alloc vdev = { .size = sizeof(vdev) };
	struct iommu_hwpt_alloc hwpt = { .size = sizeof(hwpt) };
	struct vfio_device_attach_iommufd_pt attach = {
		.argsz = sizeof(attach),
	};
	struct iommu_hwpt_amd_guest gdte = {
		.dte[0] = GDTE_FLAG_V | GDTE_FLAG_TV,
		.dte[1] = GDTE_DOMID,
	};

	vdev.viommu_id = e->viommu_id;
	vdev.dev_id = e->dev_id;
	vdev.virt_id = GDEVICE_ID;
	if (try_ioctl(e->iommufd, IOMMU_VDEVICE_ALLOC, &vdev))
		die("IOMMU_VDEVICE_ALLOC");
	e->vdevice_id = vdev.out_vdevice_id;

	hwpt.dev_id = e->dev_id;
	hwpt.pt_id = e->viommu_id;
	hwpt.data_type = IOMMU_HWPT_DATA_AMD_GUEST;
	hwpt.data_len = sizeof(gdte);
	hwpt.data_uptr = (uintptr_t)&gdte;
	if (try_ioctl(e->iommufd, IOMMU_HWPT_ALLOC, &hwpt))
		die("IOMMU_HWPT_ALLOC (nested)");
	e->nested_id = hwpt.out_hwpt_id;

	attach.pt_id = e->nested_id;
	if (try_ioctl(e->cdev, VFIO_DEVICE_ATTACH_IOMMUFD_PT, &attach))
		die("VFIO_DEVICE_ATTACH_IOMMUFD_PT (nested)");
}

static void setup(struct env *e, const char *pci, bool track_dirty,
		  bool arm_late, bool nested, bool cold)
{
	struct iommu_ioas_alloc ioas = { .size = sizeof(ioas) };
	struct iommu_viommu_amd amd = {};
	struct iommu_viommu_alloc valloc = { .size = sizeof(valloc) };
	struct iommu_hwpt_alloc hwpt = { .size = sizeof(hwpt) };
	struct vfio_device_bind_iommufd bind = { .argsz = sizeof(bind) };
	struct vfio_device_attach_iommufd_pt attach = {
		.argsz = sizeof(attach),
	};
	struct iommu_ioas_map map = { .size = sizeof(map) };

	e->iommufd = open("/dev/iommu", O_RDWR);
	if (e->iommufd < 0)
		die("/dev/iommu");

	if (try_ioctl(e->iommufd, IOMMU_IOAS_ALLOC, &ioas))
		die("IOMMU_IOAS_ALLOC");
	e->ioas_id = ioas.out_ioas_id;

	/* Guest RAM stand-in, holding the command ring and the semaphore */
	e->buf = mmap(NULL, MAP_LEN, PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (e->buf == MAP_FAILED)
		die("mmap");
	memset(e->buf, 0, MAP_LEN);

	map.ioas_id = ioas.out_ioas_id;
	map.user_va = (uintptr_t)e->buf;
	map.length = MAP_LEN;
	map.flags = IOMMU_IOAS_MAP_READABLE | IOMMU_IOAS_MAP_WRITEABLE;
	if (try_ioctl(e->iommufd, IOMMU_IOAS_MAP, &map))
		die("IOMMU_IOAS_MAP");
	e->iova = map.iova;

	e->cdev = open_vfio_cdev(pci);

	bind.iommufd = e->iommufd;
	if (try_ioctl(e->cdev, VFIO_DEVICE_BIND_IOMMUFD, &bind))
		die("VFIO_DEVICE_BIND_IOMMUFD");
	e->dev_id = bind.out_devid;

	/*
	 * The vIOMMU needs a nesting parent, not the IOAS directly, because
	 * guest-posted addresses resolve through stage 2.
	 */
	hwpt.dev_id = bind.out_devid;
	hwpt.pt_id = ioas.out_ioas_id;
	hwpt.flags = IOMMU_HWPT_ALLOC_NEST_PARENT;
	if (track_dirty)
		hwpt.flags |= IOMMU_HWPT_ALLOC_DIRTY_TRACKING;
	if (try_ioctl(e->iommufd, IOMMU_HWPT_ALLOC, &hwpt))
		die(track_dirty ? "IOMMU_HWPT_ALLOC (nest parent, dirty)"
				: "IOMMU_HWPT_ALLOC (nest parent)");
	e->parent_id = hwpt.out_hwpt_id;

	/*
	 * Skipped under --nested-cold. attach_device() is what links a device
	 * onto the domain's dev_list, and nested_attach_device() neither adds
	 * to that list nor removes from it, so skipping this is what decides
	 * whether the device the toggle has to reach is on the list at all.
	 */
	if (!cold) {
		attach.pt_id = hwpt.out_hwpt_id;
		if (try_ioctl(e->cdev, VFIO_DEVICE_ATTACH_IOMMUFD_PT, &attach))
			die("VFIO_DEVICE_ATTACH_IOMMUFD_PT");
	}

	/*
	 * Deliberately before the vIOMMU exists. The IOMMU translates its own
	 * accesses to the guest's buffers through a translate DTE of its own,
	 * which copies the domain's dirty_tracking as that DTE is programmed.
	 * Nothing revisits it afterwards, because it never joins the domain's
	 * device list, so enabling tracking later would arm the assigned
	 * device and leave the IOMMU's own writes unarmed.
	 */
	if (track_dirty && !arm_late && !set_dirty_tracking(e, true))
		die("IOMMU_HWPT_SET_DIRTY_TRACKING");

	valloc.type = IOMMU_VIOMMU_TYPE_AMD;
	valloc.dev_id = bind.out_devid;
	valloc.hwpt_id = hwpt.out_hwpt_id;
	valloc.data_uptr = (uintptr_t)&amd;
	valloc.data_len = sizeof(amd);
	if (try_ioctl(e->iommufd, IOMMU_VIOMMU_ALLOC, &valloc))
		die("IOMMU_VIOMMU_ALLOC (AMD)");
	e->viommu_id = valloc.out_viommu_id;

	/* The guest's own view of its IOMMU registers */
	e->vfmmio = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
			 e->iommufd, amd.out_vfmmio_mmap_offset);
	if (e->vfmmio == MAP_FAILED)
		die("mmap VF MMIO");

	/*
	 * After the vIOMMU exists, since the nested domain is allocated from
	 * it. With --dirty this lands after tracking was armed, so the DTE is
	 * built from a domain already tracking; with --dirty-late it lands
	 * before, so the DTE is built with HAD clear and only a later toggle
	 * can arm it.
	 */
	if (nested)
		attach_nested(e);

	printf("  ioas=%u dev=%u nest_parent=%u viommu=%u iova=%#llx\n",
	       ioas.out_ioas_id, bind.out_devid, hwpt.out_hwpt_id,
	       e->viommu_id, (unsigned long long)e->iova);
	if (nested)
		printf("  nested hwpt=%u vdevice=%u gdeviceid=%u gdomid=%u,"
		       " reached %s\n", e->nested_id, e->vdevice_id, GDEVICE_ID,
		       GDTE_DOMID,
		       cold ? "without ever attaching to the parent"
			    : "by replacing an attach to the parent");
}

/*
 * LT-001. The capability describes the IOMMU behind this device, so it is
 * queried per device rather than per vIOMMU, and it is what QEMU's migration
 * blocker gates on. On a kernel without the AMD capable() case it reads back
 * clear even though every migration ioctl below works, which is the state the
 * feature was developed in.
 */
static void test_capability(struct env *e)
{
	struct iommu_hw_info info = { .size = sizeof(info) };

	printf("\ncapability:\n");

	info.dev_id = e->dev_id;
	if (try_ioctl(e->iommufd, IOMMU_GET_HW_INFO, &info)) {
		fail("IOMMU_GET_HW_INFO", strerror(errno));
		return;
	}

	if (info.out_capabilities & IOMMU_HW_CAP_VIOMMU_MIGRATION)
		ok("IOMMU_HW_CAP_VIOMMU_MIGRATION is advertised");
	else
		fail("IOMMU_HW_CAP_VIOMMU_MIGRATION",
		     "not advertised; kernel predates patch 10");
}

static uint32_t alloc_ring(struct env *e, uint32_t type, uint64_t ring_off,
			   uint32_t len_encoded, uint32_t flags)
{
	struct iommu_hw_queue_alloc hwq = { .size = sizeof(hwq) };

	hwq.viommu_id = e->viommu_id;
	hwq.type = type;
	hwq.nesting_parent_iova = e->iova + ring_off;
	hwq.length = len_encoded;
	hwq.flags = flags;
	if (try_ioctl(e->iommufd, IOMMU_HW_QUEUE_ALLOC, &hwq))
		die("IOMMU_HW_QUEUE_ALLOC");
	return hwq.out_hw_queue_id;
}

static void alloc_cmd_ring(struct env *e, uint32_t flags)
{
	e->hw_queue_id = alloc_ring(e, IOMMU_HW_QUEUE_TYPE_AMD_CMD, 0,
				    RING_LEN_ENCODED, flags);

	printf("  hw_queue=%u ring=%#llx %u bytes (%u entries), sem at %#llx\n",
	       e->hw_queue_id, (unsigned long long)e->iova, RING_BYTES,
	       RING_ENTRIES, (unsigned long long)(e->iova + SEM_OFF));
}

static uint32_t reg32(struct env *e, unsigned off)
{
	return *(volatile uint32_t *)((char *)e->vfmmio + off);
}

static void write_reg32(struct env *e, unsigned off, uint32_t val)
{
	*(volatile uint32_t *)((char *)e->vfmmio + off) = val;
}

/* The kernel reads and writes these registers with readq/writeq */
static void write_reg64(struct env *e, unsigned off, uint64_t val)
{
	*(volatile uint64_t *)((char *)e->vfmmio + off) = val;
}

static volatile uint64_t *sem_ptr(struct env *e)
{
	return (volatile uint64_t *)((char *)e->buf + SEM_OFF);
}

static void *slot(struct env *e, uint32_t ring_off)
{
	return (char *)e->buf + (ring_off % RING_BYTES);
}

static void plant_completion_wait(void *ring_slot, uint64_t store_iova,
				  uint64_t store_data, bool store)
{
	uint32_t *cmd = ring_slot;

	cmd[0] = (uint32_t)store_iova | (store ? CMD_COMPL_WAIT_STORE : 0);
	cmd[1] = (uint32_t)(store_iova >> 32) | (CMD_COMPL_WAIT << 28);
	cmd[2] = (uint32_t)store_data;
	cmd[3] = (uint32_t)(store_data >> 32);
}

/*
 * A completion wait that also asks for the completion interrupt, which is what
 * makes hardware set ComWaitInt in the status register. The store is kept as
 * well, so the same command reports independently that hardware executed it.
 */
static void plant_completion_wait_int(void *ring_slot, uint64_t store_iova,
				      uint64_t store_data)
{
	uint32_t *cmd = ring_slot;

	cmd[0] = (uint32_t)store_iova | CMD_COMPL_WAIT_STORE | CMD_COMPL_WAIT_INT;
	cmd[1] = (uint32_t)(store_iova >> 32) | (CMD_COMPL_WAIT << 28);
	cmd[2] = (uint32_t)store_data;
	cmd[3] = (uint32_t)(store_data >> 32);
}

static void plant_other_command(void *ring_slot)
{
	uint32_t *cmd = ring_slot;

	memset(cmd, 0, CMD_ENTRY_BYTES);
	/* INVALIDATE_DEVTAB_ENTRY, so anything but a completion wait */
	cmd[1] = 0x02u << 28;
}

static void mig_to(struct env *e, uint32_t op, uint32_t timeout_ms, int want,
		   const char *what)
{
	struct iommu_viommu_mig_state cmd = {
		.size = sizeof(cmd),
		.viommu_id = e->viommu_id,
		.op = op,
		.timeout_ms = timeout_ms,
	};

	expect(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd, want, what);
}

static void mig(struct env *e, uint32_t op, int want, const char *what)
{
	mig_to(e, op, 5000, want, what);
}

static void test_state_machine(struct env *e)
{
	puts("\nmigration state machine (no command ring):");

	/*
	 * SAVE before PREPARE_SAVE is an illegal transition and must be refused
	 * by the core rather than reaching the driver.
	 */
	mig(e, IOMMU_VIOMMU_MIG_OP_SAVE, EINVAL,
	    "SAVE before PREPARE_SAVE is refused");

	/*
	 * With no ring allocated the guest command buffer is disabled, so the
	 * drain has nothing outstanding and this should succeed at once.
	 */
	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0,
	    "PREPARE_SAVE with no command ring");
	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, EINVAL,
	    "PREPARE_SAVE twice is refused");

	mig(e, IOMMU_VIOMMU_MIG_OP_GET_SIZE, 0, "GET_SIZE succeeds");

	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "ABORT after PREPARE_SAVE");

	/* Abort must leave the vIOMMU able to start over, logs thawed */
	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0,
	    "PREPARE_SAVE again after ABORT");
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "ABORT again");
}

/*
 * Drive the fence down each of its paths by dictating the ring contents.
 * Hardware never executes any of this: head and tail stay equal so nothing is
 * fetched, while the fence reads the ring out of memory regardless.
 */
static void test_fence(struct env *e)
{
	void *last = slot(e, RING_BYTES - CMD_ENTRY_BYTES);
	volatile uint64_t *sem = sem_ptr(e);

	puts("\ncompletion fence, ring contents supplied by this process:");

	/*
	 * A wait whose store has landed. The expected value is deliberately not
	 * zero, so succeeding here means the fence read the very bytes written
	 * below rather than zeroed or unrelated memory.
	 */
	memset(e->buf, 0, RING_BYTES);
	*sem = SEM_EXPECTED;
	plant_completion_wait(last, e->iova + SEM_OFF, SEM_EXPECTED, true);
	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0,
	    "fence passes when the semaphore store has landed");
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after a passing fence");

	/* One short of the expected value: the store has not landed */
	*sem = SEM_EXPECTED - 1;
	mig_to(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 250, ETIMEDOUT,
	       "fence times out when the store is outstanding");

	/* A later value must still count as having passed */
	*sem = SEM_EXPECTED + 1000;
	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0,
	    "fence passes when the semaphore has moved past");
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after a passed-by fence");

	/* A wait that stores nothing has nothing to observe */
	*sem = 0;
	plant_completion_wait(last, e->iova + SEM_OFF, SEM_EXPECTED, false);
	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0,
	    "wait without a store needs no fence");
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after a storeless wait");

	/* No completion wait anywhere in the ring */
	memset(e->buf, 0, RING_BYTES);
	plant_other_command(last);
	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0,
	    "ring with no completion wait needs no fence");
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after a waitless ring");

	/*
	 * A wait behind a newer plain command is deliberately not fenced. The
	 * head pointer was measured never to pass a wait before its store is
	 * visible, so head reaching tail past the plain command already proves
	 * the older wait completed. The semaphore is left short of its expected
	 * value here, so a build that still looked backwards would time out.
	 */
	*sem = SEM_EXPECTED - 1;
	plant_completion_wait((char *)last - CMD_ENTRY_BYTES,
			      e->iova + SEM_OFF, SEM_EXPECTED, true);
	plant_other_command(last);
	mig_to(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 250, 0,
	       "wait behind a newer plain command is not fenced");
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after an unfenced wait");

	/* A store address that is not mapped must be reported, not ignored */
	memset(e->buf, 0, RING_BYTES);
	plant_completion_wait(last, UNMAPPED_IOVA, SEM_EXPECTED, true);
	mig_to(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 250, ENOENT,
	       "unmapped store address is reported");
}

static uint64_t elapsed_us(struct timespec *a, struct timespec *b)
{
	return (b->tv_sec - a->tv_sec) * 1000000 +
	       (b->tv_nsec - a->tv_nsec) / 1000;
}

/*
 * Everywhere else the ring is already idle when PREPARE_SAVE is called, so the
 * drain sees head == tail immediately and returns without ever waiting. Submit
 * a nearly full ring of completion waits and call in on top of it, so the drain
 * has to spin while hardware works through them.
 *
 * That the drain waited is measured rather than assumed: the call is timed
 * against the same call on an idle ring. It cannot return early, because on
 * return the ring must be empty and every store must be visible.
 */
#define DRAIN_BATCH	(RING_ENTRIES - 1)

static void test_drain(struct env *e)
{
	volatile uint64_t *sem = sem_ptr(e);
	struct timespec t0, t1;
	uint64_t idle_us, busy_us;
	uint32_t tail, head_at_call;
	char detail[128];

	puts("\ndrain with commands in flight:");

	/* Baseline: the same call with nothing outstanding */
	clock_gettime(CLOCK_MONOTONIC, &t0);
	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0,
	    "PREPARE_SAVE on an idle ring");
	clock_gettime(CLOCK_MONOTONIC, &t1);
	idle_us = elapsed_us(&t0, &t1);
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after the idle call");

	memset(e->buf, 0, RING_BYTES);
	*sem = 0;
	for (unsigned i = 0; i < DRAIN_BATCH; i++)
		plant_completion_wait(slot(e, i * CMD_ENTRY_BYTES),
				      e->iova + SEM_OFF, i + 1, true);
	tail = (DRAIN_BATCH * CMD_ENTRY_BYTES) % RING_BYTES;

	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	write_reg32(e, VF_CMD_TAIL, tail);
	head_at_call = reg32(e, VF_CMD_HEAD) & 0x7fff0;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0,
	    "PREPARE_SAVE drains a ring with work in flight");
	clock_gettime(CLOCK_MONOTONIC, &t1);
	busy_us = elapsed_us(&t0, &t1);

	/* The point of the drain: nothing outstanding once it returns */
	if ((reg32(e, VF_CMD_HEAD) & 0x7fff0) == tail && *sem >= DRAIN_BATCH) {
		ok("ring empty and every store visible on return");
	} else {
		snprintf(detail, sizeof(detail),
			 "head=%#x tail=%#x sem=%llu of %u",
			 reg32(e, VF_CMD_HEAD) & 0x7fff0, tail,
			 (unsigned long long)*sem, DRAIN_BATCH);
		fail("ring empty and every store visible on return", detail);
	}
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after the busy call");

	printf("\n  %u commands submitted, head was at %#x when the call was made\n",
	       DRAIN_BATCH, head_at_call);
	printf("  idle call %llu us, busy call %llu us\n",
	       (unsigned long long)idle_us, (unsigned long long)busy_us);
	if (head_at_call == tail)
		puts("  NOTE: ring had already drained before the call, so the\n"
		     "  drain loop was not entered. Result says nothing.");
	else if (busy_us > idle_us * 2)
		puts("  the busy call took markedly longer, so the drain waited");
	else
		puts("  NOTE: no clear difference in duration; the drain may not\n"
		     "  have had to wait.");
}

/*
 * Save a quiesced vIOMMU and check the payload against what this process itself
 * programmed. The ring's base, size and flags came from the hardware queue
 * allocated above and the pointers were written through the register page, so
 * every field has a known-correct value to compare against.
 */
/*
 * Aliased from the header rather than spelled out, so that renumbering a
 * section bit cannot leave the harness checking the payload against values the
 * kernel stopped using.
 */
#define SECTION_HW_QUEUE	IOMMU_VIOMMU_MIG_SECTION_HW_QUEUE
#define SECTION_EVTLOG		IOMMU_VIOMMU_MIG_SECTION_EVTLOG
#define SECTION_STATUS		IOMMU_VIOMMU_MIG_SECTION_STATUS

/*
 * The write-one-to-clear status bits. The run bits at 3, 4, 7 and 8 are the
 * hardware-owned ones a destination must not program, so they must not appear in
 * the field the payload offers for programming.
 */
#define STATUS_STICKY_MASK	0x667u
#define STATUS_RUN_MASK		0x198u

struct tlv {
	uint32_t type;
	uint32_t length;
};

struct hw_queue_section {
	uint32_t record_size;
	uint32_t nr_records;
};

struct mig_status {
	uint64_t sticky;
	uint64_t raw;
};

struct log_segment {
	uint32_t offset;
	uint32_t length;
};

struct log_section {
	uint32_t ring_bytes;
	uint32_t nr_segments;
};

struct hw_queue_rec {
	uint32_t type;
	uint32_t index;
	uint64_t base_gpa;
	uint32_t length_bytes;
	uint32_t size_encoded;
	uint32_t queue_flags;
	uint32_t head;
	uint32_t tail;
	uint32_t record_flags;
};

static void check_u64(const char *what, uint64_t got, uint64_t want)
{
	char detail[128];

	if (got == want) {
		ok(what);
		return;
	}
	snprintf(detail, sizeof(detail), "got %#llx, wanted %#llx",
		 (unsigned long long)got, (unsigned long long)want);
	fail(what, detail);
}

/*
 * Walk the TLV sections for one of them, following the length of each rather
 * than assuming an order, which is how a reader that does not know every section
 * type has to do it.
 */
static const void *find_section(const void *payload, uint32_t len, uint32_t type,
				uint32_t *out_length)
{
	uint32_t off;

	for (off = 0; off + sizeof(struct tlv) <= len;) {
		const struct tlv *t =
			(const struct tlv *)((const char *)payload + off);
		uint32_t data = off + sizeof(*t);

		if (data + t->length > len)
			break;
		if (t->type == type) {
			if (out_length)
				*out_length = t->length;
			return (const char *)payload + data;
		}
		off = data + ((t->length + 7) & ~7u);
	}
	return NULL;
}

static void test_save(struct env *e, uint32_t expect_tail)
{
	struct iommu_viommu_mig_header hdr = {};
	struct iommu_viommu_mig_state cmd = {
		.size = sizeof(cmd),
		.viommu_id = e->viommu_id,
		.hdr_uptr = (uintptr_t)&hdr,
		.hdr_len = sizeof(hdr),
	};
	const struct hw_queue_section *sec = NULL;
	const struct hw_queue_rec *cmdq = NULL;
	const struct mig_status *st;
	uint32_t needed;
	void *payload;
	char detail[128];
	int got;

	puts("\nsaving a quiesced vIOMMU:");

	/*
	 * The fence tests leave whatever command they last planted in the ring,
	 * including one aimed at unmapped memory. Clear it, so that the quiesce
	 * below settles instead of reporting that ring.
	 */
	memset(e->buf, 0, RING_BYTES);

	cmd.op = IOMMU_VIOMMU_MIG_OP_GET_SIZE;
	if (try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd)) {
		fail("GET_SIZE reports a payload size", strerror(errno));
		return;
	}
	needed = cmd.data_len;
	printf("  payload size %u bytes\n", needed);

	payload = calloc(1, needed ? needed : 1);
	if (!payload)
		die("calloc");

	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0, "PREPARE_SAVE before save");

	/*
	 * Too small must be refused without consuming the prepared state, so
	 * that a VMM can resize and retry rather than restart the migration.
	 */
	cmd.op = IOMMU_VIOMMU_MIG_OP_SAVE;
	cmd.data_uptr = (uintptr_t)payload;
	cmd.data_len = needed - 1;
	got = try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd);
	if (got == EMSGSIZE)
		ok("SAVE into too small a buffer is refused");
	else
		fail("SAVE into too small a buffer is refused",
		     got ? strerror(got) : "succeeded");

	cmd.data_len = needed;
	got = try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd);
	if (got) {
		fail("SAVE after a refused SAVE still works", strerror(got));
		free(payload);
		return;
	}
	ok("SAVE after a refused SAVE still works");

	check_u64("header reports payload size", cmd.data_len, needed);
	check_u64("header format version", hdr.blob_format_version, 1);
	check_u64("header advertises the hardware queue section",
		  hdr.section_mask & SECTION_HW_QUEUE, SECTION_HW_QUEUE);
	check_u64("header payload_size matches what was written",
		  hdr.payload_size, needed);
	check_u64("header reports the command ring extent", hdr.cmdbuf_bytes,
		  RING_BYTES);

	/*
	 * No log ring has been allocated at this point, so there is nothing for
	 * the log sections to carry and the counters stay at zero.
	 */
	check_u64("no log rings, so no log contents",
		  hdr.evtlog_bytes | hdr.pprlog_bytes, 0);

	sec = find_section(payload, needed, SECTION_HW_QUEUE, NULL);
	if (!sec) {
		fail("payload contains a hardware queue section", "not found");
		free(payload);
		return;
	}
	ok("payload contains a hardware queue section");

	check_u64("section describes three rings", sec->nr_records, 3);
	check_u64("section record size matches this build",
		  sec->record_size, sizeof(struct hw_queue_rec));

	for (uint32_t i = 0; i < sec->nr_records; i++) {
		const struct hw_queue_rec *r =
			(const struct hw_queue_rec *)((const char *)(sec + 1) +
						      i * sec->record_size);

		printf("    ring type=%u base=%#llx len=%u enc=%u flags=%#x "
		       "head=%#x tail=%#x rec=%#x\n", r->type,
		       (unsigned long long)r->base_gpa, r->length_bytes,
		       r->size_encoded, r->queue_flags, r->head, r->tail,
		       r->record_flags);
		if (r->type == IOMMU_HW_QUEUE_TYPE_AMD_CMD)
			cmdq = r;
	}

	if (!cmdq) {
		fail("a record describes the command ring", "no CMD record");
		free(payload);
		return;
	}
	ok("a record describes the command ring");

	check_u64("command ring base matches what was allocated",
		  cmdq->base_gpa, e->iova);
	check_u64("command ring size decodes correctly", cmdq->length_bytes,
		  RING_BYTES);
	check_u64("command ring encoded size is preserved",
		  cmdq->size_encoded, RING_LEN_ENCODED);
	check_u64("command ring enable flag survives",
		  cmdq->queue_flags & IOMMU_HW_QUEUE_FLAG_AMD_CMDBUF_EN,
		  IOMMU_HW_QUEUE_FLAG_AMD_CMDBUF_EN);
	check_u64("command ring is marked programmed",
		  cmdq->record_flags & 1, 1);
	check_u64("command ring tail matches the register", cmdq->tail,
		  expect_tail);
	check_u64("command ring head matches its tail", cmdq->head,
		  expect_tail);

	/*
	 * The rings this process never allocated must come back marked absent
	 * rather than as zero-length enabled rings.
	 */
	for (uint32_t i = 0; i < sec->nr_records; i++) {
		const struct hw_queue_rec *r =
			(const struct hw_queue_rec *)((const char *)(sec + 1) +
						      i * sec->record_size);

		if (r->type == IOMMU_HW_QUEUE_TYPE_AMD_CMD)
			continue;
		snprintf(detail, sizeof(detail),
			 "ring type %u reports itself unprogrammed", r->type);
		check_u64(detail, r->record_flags & 1, 0);

		/*
		 * And with nothing to describe, an absent ring must not claim a
		 * size: a zero size register decodes to a 16-byte ring, which is
		 * a real size a guest could have asked for.
		 */
		snprintf(detail, sizeof(detail),
			 "ring type %u claims no size or pointers", r->type);
		check_u64(detail,
			  r->length_bytes | r->size_encoded | r->base_gpa |
			  r->head | r->tail | r->queue_flags, 0);
	}

	st = find_section(payload, needed, SECTION_STATUS, NULL);
	if (st) {
		ok("payload contains a status section");
		check_u64("status sticky bits are the clearable ones",
			  st->sticky, st->raw & STATUS_STICKY_MASK);
		check_u64("status offers no hardware-owned run bits",
			  st->sticky & STATUS_RUN_MASK, 0);
	} else {
		fail("payload contains a status section", "not found");
	}
	check_u64("header advertises the status section",
		  hdr.section_mask & SECTION_STATUS, SECTION_STATUS);

	mig(e, IOMMU_VIOMMU_MIG_OP_SAVE, EINVAL, "SAVE twice is refused");
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after a save");

	free(payload);
}

/*
 * Allocate an event log ring holding a known pattern and check that the payload
 * brings those exact bytes back.
 *
 * This ring is the one case where guest RAM migration cannot be relied on: the
 * IOMMU writes it itself, and whether the nesting parent's dirty tracking
 * observes those writes is unproven. So the payload has to carry the contents,
 * and this is the check that it carries the right bytes and describes where they
 * belong rather than merely reserving room for them.
 */
static void test_log_capture(struct env *e)
{
	struct iommu_viommu_mig_header hdr = {};
	struct iommu_viommu_mig_state cmd = {
		.size = sizeof(cmd),
		.viommu_id = e->viommu_id,
		.hdr_uptr = (uintptr_t)&hdr,
		.hdr_len = sizeof(hdr),
	};
	unsigned char *ring = (unsigned char *)e->buf + EVT_OFF;
	const struct hw_queue_section *hwq;
	const struct log_section *log;
	const struct log_segment *seg;
	unsigned char want[EVT_BYTES];
	uint32_t needed, id, seclen;
	void *payload;

	puts("\ncapturing event log contents:");

	/*
	 * A pattern rather than a constant, so that a copy which repeated one
	 * chunk or started at the wrong offset would not match.
	 */
	for (uint32_t i = 0; i < EVT_BYTES; i++)
		want[i] = (unsigned char)(i * 7 + 0x5a);
	memcpy(ring, want, EVT_BYTES);

	id = alloc_ring(e, IOMMU_HW_QUEUE_TYPE_AMD_EVT, EVT_OFF,
			EVT_LEN_ENCODED, IOMMU_HW_QUEUE_FLAG_AMD_EVT_LOG_EN);
	printf("  hw_queue=%u evtlog=%#llx %u bytes\n", id,
	       (unsigned long long)(e->iova + EVT_OFF), EVT_BYTES);

	cmd.op = IOMMU_VIOMMU_MIG_OP_GET_SIZE;
	if (try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd)) {
		fail("GET_SIZE with a log ring", strerror(errno));
		return;
	}
	needed = cmd.data_len;
	printf("  payload size %u bytes, %u of them log contents\n", needed,
	       EVT_BYTES);

	payload = calloc(1, needed);
	if (!payload)
		die("calloc");

	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0, "PREPARE_SAVE with a log ring");

	cmd.op = IOMMU_VIOMMU_MIG_OP_SAVE;
	cmd.data_uptr = (uintptr_t)payload;
	cmd.data_len = needed;
	if (try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd)) {
		fail("SAVE with a log ring", strerror(errno));
		free(payload);
		return;
	}
	ok("SAVE with a log ring");

	check_u64("header advertises the event log section",
		  hdr.section_mask & SECTION_EVTLOG, SECTION_EVTLOG);
	check_u64("header counts the log bytes carried", hdr.evtlog_bytes,
		  EVT_BYTES);
	check_u64("no PPR ring, so no PPR contents", hdr.pprlog_bytes, 0);

	/* The ring must also show up as programmed now, at its own size */
	hwq = find_section(payload, needed, SECTION_HW_QUEUE, NULL);
	if (hwq) {
		for (uint32_t i = 0; i < hwq->nr_records; i++) {
			const struct hw_queue_rec *r =
				(const struct hw_queue_rec *)
				((const char *)(hwq + 1) + i * hwq->record_size);

			if (r->type != IOMMU_HW_QUEUE_TYPE_AMD_EVT)
				continue;
			check_u64("event ring is marked programmed",
				  r->record_flags & 1, 1);
			check_u64("event ring base matches what was allocated",
				  r->base_gpa, e->iova + EVT_OFF);
			check_u64("event ring keeps its own size, not the command ring's",
				  r->length_bytes, EVT_BYTES);
			check_u64("event ring enable flag survives",
				  r->queue_flags &
				  IOMMU_HW_QUEUE_FLAG_AMD_EVT_LOG_EN,
				  IOMMU_HW_QUEUE_FLAG_AMD_EVT_LOG_EN);
		}
	}

	log = find_section(payload, needed, SECTION_EVTLOG, &seclen);
	if (!log) {
		fail("payload contains an event log section", "not found");
		free(payload);
		return;
	}
	ok("payload contains an event log section");

	check_u64("log section reports the ring size", log->ring_bytes,
		  EVT_BYTES);
	check_u64("log section carries one segment", log->nr_segments, 1);
	check_u64("log section is as long as its segment plus header", seclen,
		  sizeof(*log) + sizeof(*seg) + EVT_BYTES);

	seg = (const struct log_segment *)(log + 1);
	check_u64("segment starts at the base of the ring", seg->offset, 0);
	check_u64("segment covers the whole ring", seg->length, EVT_BYTES);

	/*
	 * The bytes follow the last segment descriptor, which is where the
	 * segment offsets are relative to the ring rather than to the payload.
	 */
	if (!memcmp((const char *)seg + sizeof(*seg) * log->nr_segments, want,
		    EVT_BYTES))
		ok("log contents are the bytes that were in the ring");
	else
		fail("log contents are the bytes that were in the ring",
		     "payload differs from the ring");

	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after a log save");
	free(payload);
}

/*
 * Save a payload, disturb everything it described, then restore it and check
 * the disturbance was undone.
 *
 * The event ring carries the pointer test rather than the command ring, because
 * nothing generates events here: its head and tail can be written and read back
 * without hardware acting on them, where moving the command tail would set
 * hardware fetching. Its contents carry the write-back test for the same reason.
 */
static void test_restore(struct env *e)
{
	struct iommu_viommu_mig_header hdr = {};
	struct iommu_viommu_mig_state cmd = {
		.size = sizeof(cmd),
		.viommu_id = e->viommu_id,
		.hdr_uptr = (uintptr_t)&hdr,
		.hdr_len = sizeof(hdr),
	};
	unsigned char *ring = (unsigned char *)e->buf + EVT_OFF;
	unsigned char want[EVT_BYTES];
	const uint32_t saved_head = 2 * CMD_ENTRY_BYTES;
	const uint32_t saved_tail = 5 * CMD_ENTRY_BYTES;
	uint32_t needed;
	void *payload;
	int got;

	puts("\nrestoring a payload onto a disturbed vIOMMU:");

	for (uint32_t i = 0; i < EVT_BYTES; i++)
		want[i] = (unsigned char)(i * 11 + 0x3c);
	memcpy(ring, want, EVT_BYTES);

	write_reg32(e, VF_EVT_HEAD, saved_head);
	write_reg32(e, VF_EVT_TAIL, saved_tail);

	cmd.op = IOMMU_VIOMMU_MIG_OP_GET_SIZE;
	if (try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd)) {
		fail("GET_SIZE before restore test", strerror(errno));
		return;
	}
	needed = cmd.data_len;
	payload = calloc(1, needed);
	if (!payload)
		die("calloc");

	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0, "PREPARE_SAVE for restore");

	cmd.op = IOMMU_VIOMMU_MIG_OP_SAVE;
	cmd.data_uptr = (uintptr_t)payload;
	cmd.data_len = needed;
	if (try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd)) {
		fail("SAVE for restore", strerror(errno));
		free(payload);
		return;
	}
	ok("SAVE for restore");

	/* Back to a clean slate, which is where a destination starts */
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "ABORT back to no migration");

	/* Now make everything the payload described wrong */
	write_reg32(e, VF_EVT_HEAD, 9 * CMD_ENTRY_BYTES);
	write_reg32(e, VF_EVT_TAIL, 1 * CMD_ENTRY_BYTES);
	memset(ring, 0xa5, EVT_BYTES);
	check_u64("event head was disturbed", reg32(e, VF_EVT_HEAD) & 0x7fff0,
		  9 * CMD_ENTRY_BYTES);

	cmd.op = IOMMU_VIOMMU_MIG_OP_RESTORE;
	cmd.data_uptr = (uintptr_t)payload;
	cmd.data_len = needed;
	got = try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd);
	if (got) {
		fail("RESTORE accepts the payload", strerror(got));
		free(payload);
		return;
	}
	ok("RESTORE accepts the payload");

	check_u64("event head is back", reg32(e, VF_EVT_HEAD) & 0x7fff0,
		  saved_head);
	check_u64("event tail is back", reg32(e, VF_EVT_TAIL) & 0x7fff0,
		  saved_tail);

	if (!memcmp(ring, want, EVT_BYTES))
		ok("event log contents are back");
	else
		fail("event log contents are back", "ring still disturbed");

	mig(e, IOMMU_VIOMMU_MIG_OP_RESTORE, EINVAL, "RESTORE twice is refused");
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after a restore");

	free(payload);
}

/*
 * A payload is whatever userspace hands over, so every one of these is a
 * malformed blob the kernel has to reject rather than act on.
 */
static void restore_rejects(struct env *e, void *payload, uint32_t len,
			    const char *what, int want)
{
	struct iommu_viommu_mig_header hdr = {};
	struct iommu_viommu_mig_state cmd = {
		.size = sizeof(cmd),
		.viommu_id = e->viommu_id,
		.hdr_uptr = (uintptr_t)&hdr,
		.hdr_len = sizeof(hdr),
		.op = IOMMU_VIOMMU_MIG_OP_RESTORE,
	};
	char detail[128];
	int got;

	/* The header the payload was saved with, minus the payload edits */
	hdr.blob_format_version = 1;
	hdr.min_reader_version = 1;
	hdr.blob_type = IOMMU_VIOMMU_TYPE_AMD;
	hdr.payload_size = len;

	cmd.data_uptr = (uintptr_t)payload;
	cmd.data_len = len;
	got = try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd);
	if (got == want) {
		ok(what);
	} else {
		snprintf(detail, sizeof(detail), "got %s, wanted %s",
			 got ? strerror(got) : "success", strerror(want));
		fail(what, detail);
	}

	/* A rejected restore must leave nothing behind to abort */
	if (!got)
		mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after it was accepted");
}

/* The command ring's record within a payload, for the tests that corrupt it */
static struct hw_queue_rec *find_cmd_record(void *payload, uint32_t len)
{
	struct hw_queue_section *hwq = (struct hw_queue_section *)
		find_section(payload, len, SECTION_HW_QUEUE, NULL);

	if (!hwq)
		return NULL;

	for (uint32_t i = 0; i < hwq->nr_records; i++) {
		struct hw_queue_rec *r = (struct hw_queue_rec *)
			((char *)(hwq + 1) + i * hwq->record_size);

		if (r->type == IOMMU_HW_QUEUE_TYPE_AMD_CMD)
			return r;
	}
	return NULL;
}

/* The status section's header, for the tests that give it a bad type */
static struct tlv *find_status_tlv(void *payload, uint32_t len)
{
	const void *data = find_section(payload, len, SECTION_STATUS, NULL);

	return data ? (struct tlv *)((char *)data - sizeof(struct tlv)) : NULL;
}

static void test_restore_rejects(struct env *e)
{
	struct iommu_viommu_mig_header hdr = {};
	struct iommu_viommu_mig_state cmd = {
		.size = sizeof(cmd),
		.viommu_id = e->viommu_id,
		.hdr_uptr = (uintptr_t)&hdr,
		.hdr_len = sizeof(hdr),
	};
	struct hw_queue_rec *rec;
	struct tlv *status_tlv;
	uint32_t needed, off;
	void *good, *bad;

	puts("\nrefusing malformed payloads:");

	cmd.op = IOMMU_VIOMMU_MIG_OP_GET_SIZE;
	if (try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd)) {
		fail("GET_SIZE before reject tests", strerror(errno));
		return;
	}
	needed = cmd.data_len;
	good = calloc(1, needed);
	bad = calloc(1, needed);
	if (!good || !bad)
		die("calloc");

	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0, "PREPARE_SAVE for rejects");
	cmd.op = IOMMU_VIOMMU_MIG_OP_SAVE;
	cmd.data_uptr = (uintptr_t)good;
	cmd.data_len = needed;
	if (try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd)) {
		fail("SAVE for rejects", strerror(errno));
		goto out;
	}
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "ABORT before the reject tests");

	/* Sanity: the unmodified payload is accepted, so a rejection below is
	 * caused by the edit and not by something else about the payload.
	 */
	memcpy(bad, good, needed);
	restore_rejects(e, bad, needed, "the unedited payload is accepted", 0);

	/* A payload cut short mid-section */
	memcpy(bad, good, needed);
	restore_rejects(e, bad, needed - 8, "a truncated payload is refused",
			EINVAL);

	/* A section claiming more bytes than the payload holds */
	memcpy(bad, good, needed);
	((struct tlv *)bad)->length = needed;
	restore_rejects(e, bad, needed,
			"a section longer than the payload is refused", EINVAL);

	/* Nothing the kernel recognises, so no rings to restore */
	memcpy(bad, good, needed);
	for (off = 0; off + sizeof(struct tlv) <= needed;) {
		struct tlv *t = (struct tlv *)((char *)bad + off);

		if (t->type == SECTION_HW_QUEUE)
			t->type = 1u << 30;
		off += sizeof(*t) + ((t->length + 7) & ~7u);
	}
	restore_rejects(e, bad, needed,
			"a payload with no ring section is refused", EINVAL);

	/* A ring at an address this destination did not allocate */
	memcpy(bad, good, needed);
	rec = find_cmd_record(bad, needed);
	if (!rec) {
		fail("found a command ring record to corrupt", "not found");
		goto out;
	}
	rec->base_gpa += 0x1000;
	restore_rejects(e, bad, needed,
			"a ring base that does not match is refused", EINVAL);

	/* A ring of a size this destination did not allocate */
	memcpy(bad, good, needed);
	find_cmd_record(bad, needed)->size_encoded += 1;
	restore_rejects(e, bad, needed,
			"a ring size that does not match is refused", EINVAL);

	/* A ring the source never programmed, that this destination has */
	memcpy(bad, good, needed);
	find_cmd_record(bad, needed)->record_flags = 0;
	restore_rejects(e, bad, needed,
			"a ring the source did not have is refused", EINVAL);

	/* A head pointer past the end of the ring */
	memcpy(bad, good, needed);
	find_cmd_record(bad, needed)->head = RING_BYTES;
	restore_rejects(e, bad, needed,
			"a head pointer past the ring end is refused", EINVAL);

	/* A head pointer inside an entry rather than at one */
	memcpy(bad, good, needed);
	find_cmd_record(bad, needed)->head = 4;
	restore_rejects(e, bad, needed,
			"a misaligned head pointer is refused", EINVAL);

	/* More records than there are rings */
	memcpy(bad, good, needed);
	((struct hw_queue_section *)find_section(bad, needed, SECTION_HW_QUEUE,
						 NULL))->nr_records = 64;
	restore_rejects(e, bad, needed,
			"more ring records than rings is refused", EINVAL);

	/* A record size smaller than the fields the format defines */
	memcpy(bad, good, needed);
	((struct hw_queue_section *)find_section(bad, needed, SECTION_HW_QUEUE,
						 NULL))->record_size = 8;
	restore_rejects(e, bad, needed,
			"an undersized ring record is refused", EINVAL);

	/*
	 * Two sections of the same type. Each copy is valid on its own, so the
	 * only thing wrong here is that the payload says the same thing twice
	 * and leaves which one takes effect up to the order they sit in. It is
	 * the status section that gets duplicated rather than the ring section,
	 * because nothing but the rule against repeats objects to two of it.
	 */
	{
		const struct tlv *st = find_status_tlv(good, needed);
		uint32_t sec_bytes;
		void *dup;

		if (!st) {
			fail("found a status section to duplicate",
			     "not found");
			goto out;
		}
		sec_bytes = sizeof(*st) + ((st->length + 7) & ~7u);
		dup = calloc(1, needed + sec_bytes);
		if (!dup)
			die("calloc");
		memcpy(dup, good, needed);
		memcpy((char *)dup + needed, st, sec_bytes);
		restore_rejects(e, dup, needed + sec_bytes,
				"a repeated section is refused", EINVAL);
		free(dup);
	}

	/*
	 * A section type is one bit of the section enum. These retype the
	 * status section rather than the ring section, so the payload is still
	 * describing its rings and the type is the only thing wrong with it.
	 */
	memcpy(bad, good, needed);
	status_tlv = find_status_tlv(bad, needed);
	if (!status_tlv) {
		fail("found a status section to retype", "not found");
		goto out;
	}
	status_tlv->type = SECTION_HW_QUEUE | SECTION_STATUS;
	restore_rejects(e, bad, needed,
			"a section type with two bits set is refused", EINVAL);

	memcpy(bad, good, needed);
	find_status_tlv(bad, needed)->type = 0;
	restore_rejects(e, bad, needed,
			"a section type of zero is refused", EINVAL);

	/*
	 * A payload whose oldest acceptable reader is newer than this kernel.
	 * Fields it would skip could be load-bearing, so it must refuse the
	 * whole thing rather than restore the parts it recognises.
	 */
	memcpy(bad, good, needed);
	hdr.blob_format_version = 2;
	hdr.min_reader_version = 2;
	hdr.blob_type = IOMMU_VIOMMU_TYPE_AMD;
	hdr.payload_size = needed;
	cmd.op = IOMMU_VIOMMU_MIG_OP_RESTORE;
	cmd.data_uptr = (uintptr_t)bad;
	cmd.data_len = needed;
	off = try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd);
	if (off == EOPNOTSUPP) {
		ok("a payload needing a newer reader is refused");
	} else {
		fail("a payload needing a newer reader is refused",
		     off ? strerror(off) : "accepted");
		if (!off)
			mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort");
	}

	/*
	 * A header depending on a feature this kernel does not implement.
	 * Unlike an unknown section, which a reader is meant to skip, a feature
	 * flag is something the payload needs the destination to do, so the
	 * core refuses it before the driver is given the payload at all.
	 */
	memcpy(bad, good, needed);
	memset(&hdr, 0, sizeof(hdr));
	hdr.blob_format_version = 1;
	hdr.min_reader_version = 1;
	hdr.blob_type = IOMMU_VIOMMU_TYPE_AMD;
	hdr.payload_size = needed;
	hdr.feature_flags = 1;
	cmd.op = IOMMU_VIOMMU_MIG_OP_RESTORE;
	cmd.data_uptr = (uintptr_t)bad;
	cmd.data_len = needed;
	off = try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd);
	if (off == EOPNOTSUPP) {
		ok("a payload needing an unknown feature is refused");
	} else {
		fail("a payload needing an unknown feature is refused",
		     off ? strerror(off) : "accepted");
		if (!off)
			mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort");
	}

out:
	free(good);
	free(bad);
}

/*
 * Can the guest status register be put back at all?
 *
 * The overflow and interrupt bits are documented write-one-to-clear, which the
 * host driver's recovery path relies on: it clears an overflow by writing the bit
 * back. If that is all a write can do then a destination cannot reinstate a bit
 * the source had set, and the sticky field the payload carries is unrestorable
 * through this register however faithfully it was saved.
 *
 * The register lives at offset 0x20 of the per-GID page this process has mapped,
 * which is the same physical location the kernel reaches as
 * VIOMMU_VF_MMIO_BASE(iommu, gid) + VIOMMU_VF_MMIO_OFF(MMIO_STATUS_OFFSET). So
 * writing it here is writing what a restore would write.
 *
 * A bare sweep of writes proves little on a register that reads zero throughout,
 * since a bit that will not set is indistinguishable from an offset that ignores
 * writes or a bit that is not implemented. So first make hardware set a bit,
 * which establishes that the offset is live and responsive, and only then ask
 * what writes can do to it.
 */
static uint32_t probe_tail;

/*
 * Execute one completion wait carrying the interrupt flag, and report whether
 * ComWaitInt appeared. The command's store lands in the semaphore, which says
 * independently of any status bit whether hardware ran the command at all.
 */
static bool raise_comwait_int(struct env *e, uint64_t seq)
{
	volatile uint64_t *sem = sem_ptr(e);
	struct timespec t0, now;

	*sem = 0;
	plant_completion_wait_int(slot(e, probe_tail), e->iova + SEM_OFF, seq);
	probe_tail = (probe_tail + CMD_ENTRY_BYTES) % RING_BYTES;

	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	write_reg32(e, VF_CMD_TAIL, probe_tail);

	clock_gettime(CLOCK_MONOTONIC, &t0);
	do {
		if (reg32(e, VF_STATUS) & STATUS_COMWAIT_INT)
			return true;
		clock_gettime(CLOCK_MONOTONIC, &now);
	} while (elapsed_us(&t0, &now) < 500000);

	return false;
}

static void probe_status(struct env *e, bool raise_only, bool write_only)
{
	static const struct {
		uint32_t bit;
		const char *name;
	} sticky[] = {
		{ STATUS_EVT_OVERFLOW, "EvtOverflow" },
		{ STATUS_EVT_LOG_INT, "EvtLogInt" },
		{ STATUS_PPR_OVERFLOW, "PprOverflow" },
		{ STATUS_PPR_INT, "PprInt" },
	};
	volatile uint64_t *sem = sem_ptr(e);
	unsigned settable = 0;
	bool live, cleared32, cleared64;
	uint32_t was, after;

	puts("\nstatus register probe, offset 0x20 of the guest register page:");
	printf("  status reads %#x\n", reg32(e, VF_STATUS));

	/*
	 * Isolation modes, to attribute the IOMMU page faults this probe
	 * provokes to one half of it or the other.
	 */
	if (write_only) {
		puts("  writes only, no completion wait:");
		for (unsigned i = 0; i < sizeof(sticky) / sizeof(sticky[0]); i++) {
			write_reg32(e, VF_STATUS, sticky[i].bit);
			write_reg64(e, VF_STATUS, sticky[i].bit);
		}
		write_reg32(e, VF_STATUS, STATUS_COMWAIT_INT);
		printf("  status now %#x\n", reg32(e, VF_STATUS));
		return;
	}
	if (raise_only) {
		puts("  one completion wait with the interrupt flag, no writes:");
		memset(e->buf, 0, RING_BYTES);
		live = raise_comwait_int(e, SEM_EXPECTED);
		printf("  ComWaitInt %s, store %s, status now %#x\n",
		       live ? "set" : "not set",
		       *sem == SEM_EXPECTED ? "landed" : "did NOT land",
		       reg32(e, VF_STATUS));
		return;
	}

	/*
	 * Establish that this offset is live by making hardware set a bit in it,
	 * rather than inferring anything from a register that only ever reads
	 * zero.
	 */
	puts("\n  making hardware set ComWaitInt, via a completion wait that\n"
	     "  asks for the completion interrupt:");
	memset(e->buf, 0, RING_BYTES);
	live = raise_comwait_int(e, SEM_EXPECTED);
	printf("    command executed (store landed): %s\n",
	       *sem == SEM_EXPECTED ? "yes" : "NO");
	printf("    ComWaitInt: %s, status now %#x\n",
	       live ? "SET by hardware" : "not set", reg32(e, VF_STATUS));

	if (!live) {
		puts("\n  INCONCLUSIVE: nothing ever set a bit at this offset, so\n"
		     "  a write that fails to set one says nothing about whether\n"
		     "  the bit is write-one-to-clear, unimplemented, or simply\n"
		     "  not reflected in this page.");
		if (*sem != SEM_EXPECTED)
			puts("  The store did not land either, so hardware did not\n"
			     "  execute the command and the probe proved nothing.");
		return;
	}
	puts("    so this offset is live and reflects hardware activity");

	/* Clear direction, at the width the kernel uses and at 32 bits */
	was = reg32(e, VF_STATUS);
	write_reg32(e, VF_STATUS, STATUS_COMWAIT_INT);
	after = reg32(e, VF_STATUS);
	cleared32 = (was & STATUS_COMWAIT_INT) && !(after & STATUS_COMWAIT_INT);
	printf("\n  clearing ComWaitInt with a 32-bit write: %#x -> %#x  %s\n",
	       was, after, cleared32 ? "cleared" : "NOT cleared");

	raise_comwait_int(e, SEM_EXPECTED + 1);
	was = reg32(e, VF_STATUS);
	write_reg64(e, VF_STATUS, STATUS_COMWAIT_INT);
	after = reg32(e, VF_STATUS);
	cleared64 = (was & STATUS_COMWAIT_INT) && !(after & STATUS_COMWAIT_INT);
	printf("  clearing ComWaitInt with a 64-bit write: %#x -> %#x  %s\n",
	       was, after, cleared64 ? "cleared" : "NOT cleared");

	/*
	 * Set direction, now against a register known to be live. Both widths,
	 * because the kernel would use writeq and a 32-bit result need not
	 * generalise.
	 */
	puts("\n  trying to set each remaining sticky bit:");
	for (unsigned i = 0; i < sizeof(sticky) / sizeof(sticky[0]); i++) {
		was = reg32(e, VF_STATUS);
		write_reg32(e, VF_STATUS, sticky[i].bit);
		after = reg32(e, VF_STATUS);
		if ((after & sticky[i].bit) && !(was & sticky[i].bit))
			settable++;
		printf("    %-12s (%#05x) 32-bit: %#x -> %#x  %s\n",
		       sticky[i].name, sticky[i].bit, was, after,
		       (after & sticky[i].bit) && !(was & sticky[i].bit) ?
		       "SET" : "no change");

		was = reg32(e, VF_STATUS);
		write_reg64(e, VF_STATUS, sticky[i].bit);
		after = reg32(e, VF_STATUS);
		if ((after & sticky[i].bit) && !(was & sticky[i].bit))
			settable++;
		printf("    %-12s (%#05x) 64-bit: %#x -> %#x  %s\n",
		       sticky[i].name, sticky[i].bit, was, after,
		       (after & sticky[i].bit) && !(was & sticky[i].bit) ?
		       "SET" : "no change");
	}

	puts("");
	if (settable) {
		printf("  RESULT: %u write(s) set a sticky bit, so a restore can\n"
		       "  reinstate one directly.\n", settable);
	} else if (cleared32 || cleared64) {
		puts("  RESULT: the register is live, a write of a set bit clears\n"
		     "  it, and no write could set one. The sticky bits are\n"
		     "  therefore write-one-to-clear, and a restore cannot put\n"
		     "  back a bit the source had set. What the payload carries\n"
		     "  is a record for the destination's VMM or guest to act\n"
		     "  on, not something the kernel can program back.");
	} else {
		puts("  RESULT: the register is live, but a write neither set nor\n"
		     "  cleared a bit, so writes at this offset appear to be\n"
		     "  ignored entirely. A restore cannot reinstate a bit, and\n"
		     "  cannot clear one either.");
	}
}

/*
 * Leave a migration half-finished and exit, which is what happens when the VMM
 * dies between PREPARE_SAVE and the end of the migration. Destroying the vIOMMU
 * has to unwind on its own: thaw the logs it froze and release the guest memory
 * access it took, with no ABORT to prompt it. Nothing here can be asserted from
 * inside this process, since the interesting part happens as it exits; the check
 * is that a later run still passes.
 */
static void abandon_prepared(struct env *e)
{
	volatile uint64_t *sem = sem_ptr(e);

	puts("\nabandoning a prepared migration:");

	memset(e->buf, 0, RING_BYTES);
	*sem = SEM_EXPECTED;
	plant_completion_wait(slot(e, RING_BYTES - CMD_ENTRY_BYTES),
			      e->iova + SEM_OFF, SEM_EXPECTED, true);
	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0, "PREPARE_SAVE succeeded");
	puts("  exiting with the vIOMMU still prepared and logs frozen");
}

/*
 * Does the head pointer advance past a COMPLETION_WAIT before that command's
 * store is visible?
 *
 * The whole completion fence rests on the answer. If head only advances once a
 * command retires, then head == tail already proves every wait has stored and
 * the fence is unnecessary. If head advances on fetch, a wait can be behind the
 * head pointer with its store still outstanding, and skipping the fence risks a
 * destination guest waiting forever on a store that never lands.
 *
 * Submit a batch of completion waits storing an increasing sequence to one
 * semaphore, then sample the head register and the semaphore. Read head first:
 * if head has reached tail and the semaphore read afterwards is still short of
 * the final value, then it was also short at the earlier moment head was read,
 * because the sequence only moves forward. That ordering makes a positive
 * observation sound.
 *
 * A batch rather than a single wait, because each wait must let all older ones
 * complete first. That serialised backlog widens any gap between "everything
 * has been fetched" and "the last store has landed", which is what makes the
 * gap observable at all.
 */
#define PROBE_BATCH	200
#define PROBE_TRIALS	2000
#define PROBE_TIMEOUT_S	2

static void probe_head_vs_store(struct env *e)
{
	uint64_t seq = 0;
	uint32_t tail = 0;
	int caught = 0, drained_late = 0, stalled = 0;
	uint64_t worst_gap = 0;
	volatile uint64_t *sem = sem_ptr(e);
	/*
	 * A negative result only means something if the intermediate state was
	 * actually sampled. Count how often head was seen short of tail, and
	 * how much of the batch was still outstanding when it was first seen,
	 * so a run that never had the resolution to catch anything says so.
	 */
	uint64_t samples_busy = 0;
	int trials_blind = 0;
	uint64_t first_seen_min = PROBE_BATCH;

	printf("\nhead-vs-store probe: %d trials of %d completion waits\n",
	       PROBE_TRIALS, PROBE_BATCH);

	if (reg32(e, VF_CMD_HEAD) != reg32(e, VF_CMD_TAIL)) {
		fail("probe precondition", "ring is not idle");
		return;
	}

	for (int trial = 0; trial < PROBE_TRIALS; trial++) {
		uint64_t final = seq + PROBE_BATCH;
		struct timespec t0, now;
		uint32_t head;
		uint64_t seen;
		bool done = false;

		for (int i = 0; i < PROBE_BATCH; i++)
			plant_completion_wait(slot(e, tail + i * CMD_ENTRY_BYTES),
					      e->iova + SEM_OFF, seq + i + 1,
					      true);

		tail = (tail + PROBE_BATCH * CMD_ENTRY_BYTES) % RING_BYTES;

		/* Publish the batch, which is what starts hardware fetching */
		__atomic_thread_fence(__ATOMIC_SEQ_CST);
		write_reg32(e, VF_CMD_TAIL, tail);

		clock_gettime(CLOCK_MONOTONIC, &t0);
		for (uint64_t iter = 0;; iter++) {
			/* head first, then the semaphore: see above */
			head = reg32(e, VF_CMD_HEAD) & 0x7fff0;
			seen = *sem;

			if (head != tail) {
				samples_busy++;
				/*
				 * How far into the batch the first sample
				 * landed. If this is always the whole batch,
				 * sampling started before hardware got going
				 * and the window was covered.
				 */
				if (!iter) {
					uint64_t left = final - seen;

					if (left < first_seen_min)
						first_seen_min = left;
				}
			} else if (!iter) {
				trials_blind++;
			}

			if (head == tail) {
				if (seen < final) {
					caught++;
					if (final - seen > worst_gap)
						worst_gap = final - seen;
				} else {
					drained_late++;
				}
				done = true;
				break;
			}
			clock_gettime(CLOCK_MONOTONIC, &now);
			if (now.tv_sec - t0.tv_sec > PROBE_TIMEOUT_S)
				break;
		}

		if (!done) {
			stalled++;
			printf("  trial %d: head never reached tail "
			       "(head=%#x tail=%#x sem=%llu want=%llu)\n",
			       trial, head, tail, (unsigned long long)seen,
			       (unsigned long long)final);
			if (stalled > 3)
				break;
		}

		/* Let the batch finish before reusing those ring slots */
		clock_gettime(CLOCK_MONOTONIC, &t0);
		while (*sem < final) {
			clock_gettime(CLOCK_MONOTONIC, &now);
			if (now.tv_sec - t0.tv_sec > PROBE_TIMEOUT_S) {
				printf("  trial %d: semaphore stuck at %llu, "
				       "wanted %llu\n", trial,
				       (unsigned long long)*sem,
				       (unsigned long long)final);
				stalled++;
				break;
			}
		}
		seq = final;
	}

	printf("\n  status register now %#llx\n",
	       (unsigned long long)*(volatile uint64_t *)
				    ((char *)e->vfmmio + VF_STATUS));
	printf("  head reached tail with the store still outstanding: %d\n",
	       caught);
	printf("  head reached tail with every store already visible:  %d\n",
	       drained_late);
	printf("  batches that never drained:                          %d\n",
	       stalled);
	if (caught)
		printf("  largest number of stores still outstanding:          "
		       "%llu of %d\n", (unsigned long long)worst_gap,
		       PROBE_BATCH);

	printf("\n  sampling resolution:\n");
	printf("    samples that saw head short of tail:   %llu (%.0f per batch)\n",
	       (unsigned long long)samples_busy,
	       (double)samples_busy / PROBE_TRIALS);
	printf("    batches already drained on first read: %d\n", trials_blind);
	printf("    fewest stores left at first read:      %llu of %d\n",
	       (unsigned long long)first_seen_min, PROBE_BATCH);

	puts("");
	if (stalled)
		puts("  INCONCLUSIVE: hardware did not execute the batches.");
	else if (trials_blind * 4 > PROBE_TRIALS)
		puts("  INCONCLUSIVE: too many batches finished before the\n"
		     "  first sample, so the window was mostly not observed.");
	else if (caught)
		puts("  RESULT: head advances on fetch, not on retirement.\n"
		     "  head == tail does NOT prove a wait has stored, so the\n"
		     "  completion fence is required.");
	else
		puts("  RESULT: no case observed where head reached tail with a\n"
		     "  store outstanding. Consistent with head advancing only\n"
		     "  on retirement, but absence of an observation across a\n"
		     "  sampling window is weaker than a positive one.");
}

/*
 * Read back one ring's record from a fresh payload, or NULL if the save did not
 * describe that ring at all. The record is copied out because the payload it
 * came from is freed here.
 */
static bool save_ring_record(struct env *e, uint32_t type,
			     struct hw_queue_rec *out, const char *what)
{
	struct iommu_viommu_mig_header hdr = {};
	struct iommu_viommu_mig_state cmd = {
		.size = sizeof(cmd),
		.viommu_id = e->viommu_id,
		.hdr_uptr = (uintptr_t)&hdr,
		.hdr_len = sizeof(hdr),
	};
	const struct hw_queue_section *sec;
	bool found = false;
	uint32_t needed;
	void *payload;

	cmd.op = IOMMU_VIOMMU_MIG_OP_GET_SIZE;
	if (try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd)) {
		fail(what, strerror(errno));
		return false;
	}
	needed = cmd.data_len;

	payload = calloc(1, needed);
	if (!payload)
		die("calloc");

	cmd.op = IOMMU_VIOMMU_MIG_OP_SAVE;
	cmd.data_uptr = (uintptr_t)payload;
	cmd.data_len = needed;
	if (try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd)) {
		fail(what, strerror(errno));
		free(payload);
		return false;
	}

	sec = find_section(payload, needed, SECTION_HW_QUEUE, NULL);
	for (uint32_t i = 0; sec && i < sec->nr_records; i++) {
		const struct hw_queue_rec *r =
			(const struct hw_queue_rec *)((const char *)(sec + 1) +
						      i * sec->record_size);

		if (r->type != type)
			continue;
		*out = *r;
		found = true;
		break;
	}

	free(payload);
	return found;
}

/*
 * Destroying a hardware queue has to disarm the register that points at its
 * ring. AMD queues are allocated in GPA mode, so the core pins nothing and frees
 * nothing on destruction: without the driver's own destroy hook the control
 * register would keep its base and enable bits, leaving hardware pointed at
 * guest memory the VMM is entitled to reuse the moment it frees the object.
 *
 * That register is not readable from userspace, but the save path reads it, so a
 * save taken after the destroy reports what the register actually holds. A ring
 * that still comes back programmed here is a ring hardware can still reach.
 */
static void test_queue_destroy(struct env *e)
{
	struct iommu_destroy destroy = { .size = sizeof(destroy) };
	struct hw_queue_rec rec;
	uint32_t id;

	puts("\ndestroying a ring disarms it:");

	id = alloc_ring(e, IOMMU_HW_QUEUE_TYPE_AMD_PPR, PPR_OFF,
			PPR_LEN_ENCODED, IOMMU_HW_QUEUE_FLAG_AMD_PPRLOG_EN);
	printf("  hw_queue=%u pprlog=%#llx %u bytes\n", id,
	       (unsigned long long)(e->iova + PPR_OFF), PPR_BYTES);

	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0, "PREPARE_SAVE for destroy");

	if (!save_ring_record(e, IOMMU_HW_QUEUE_TYPE_AMD_PPR, &rec,
			      "save with the PPR ring")) {
		fail("save describes the PPR ring", "no record");
		return;
	}
	ok("save describes the PPR ring");
	check_u64("PPR ring is programmed before the destroy",
		  rec.record_flags & 1, 1);
	check_u64("PPR ring base matches what was allocated", rec.base_gpa,
		  e->iova + PPR_OFF);

	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort before the destroy");

	destroy.id = id;
	expect(e->iommufd, IOMMU_DESTROY, &destroy, 0, "the ring is destroyed");

	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0,
	    "PREPARE_SAVE after the destroy");

	if (!save_ring_record(e, IOMMU_HW_QUEUE_TYPE_AMD_PPR, &rec,
			      "save after the destroy")) {
		fail("save still describes the PPR ring slot", "no record");
		return;
	}
	ok("save still describes the PPR ring slot");
	check_u64("the destroyed ring is no longer programmed",
		  rec.record_flags & 1, 0);
	check_u64("the destroyed ring keeps no base, size or enable",
		  rec.base_gpa | rec.length_bytes | rec.size_encoded |
		  rec.queue_flags, 0);

	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after the destroy");
}

static void destroy_obj(struct env *e, uint32_t id, const char *what)
{
	struct iommu_destroy destroy = { .size = sizeof(destroy), .id = id };

	expect(e->iommufd, IOMMU_DESTROY, &destroy, 0, what);
}

/* PREPARE_SAVE and save into a fresh buffer, which the caller frees */
static void *prepare_and_save(struct env *e, uint32_t *out_len,
			      const char *what)
{
	struct iommu_viommu_mig_header hdr = {};
	struct iommu_viommu_mig_state cmd = {
		.size = sizeof(cmd),
		.viommu_id = e->viommu_id,
		.hdr_uptr = (uintptr_t)&hdr,
		.hdr_len = sizeof(hdr),
	};
	void *payload;

	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0, "PREPARE_SAVE");

	cmd.op = IOMMU_VIOMMU_MIG_OP_GET_SIZE;
	if (try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd)) {
		fail(what, strerror(errno));
		return NULL;
	}

	payload = calloc(1, cmd.data_len);
	if (!payload)
		die("calloc");

	*out_len = cmd.data_len;
	cmd.op = IOMMU_VIOMMU_MIG_OP_SAVE;
	cmd.data_uptr = (uintptr_t)payload;
	if (try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd)) {
		fail(what, strerror(errno));
		free(payload);
		return NULL;
	}
	ok(what);

	return payload;
}

/*
 * Restore and stay there, unlike restore_rejects(), because the commit tests
 * need the sequence still open afterwards.
 */
static bool do_restore(struct env *e, void *payload, uint32_t len,
		       const char *what)
{
	struct iommu_viommu_mig_header hdr = {
		.blob_format_version = 1,
		.min_reader_version = 1,
		.blob_type = IOMMU_VIOMMU_TYPE_AMD,
		.payload_size = len,
	};
	struct iommu_viommu_mig_state cmd = {
		.size = sizeof(cmd),
		.viommu_id = e->viommu_id,
		.hdr_uptr = (uintptr_t)&hdr,
		.hdr_len = sizeof(hdr),
		.op = IOMMU_VIOMMU_MIG_OP_RESTORE,
		.data_uptr = (uintptr_t)payload,
		.data_len = len,
	};
	int got = try_ioctl(e->iommufd, IOMMU_VIOMMU_MIG_STATE, &cmd);

	if (got) {
		fail(what, strerror(got));
		return false;
	}
	ok(what);
	return true;
}

/* The PPR log enable, as the payload spells it and as this test looks for it */
#define PPR_ARM_FLAG	IOMMU_HW_QUEUE_FLAG_AMD_PPRLOG_EN

/*
 * Arming a ring is the commit's job, and only for rings that are still the ones
 * the restore checked.
 *
 * The enable bits sit in a register userspace cannot read, so every check here
 * reads them back through a save, which is the one path that reports them. The
 * PPR ring carries the test because nothing else uses it, and because it can be
 * destroyed and re-created freely to imitate what a destination does.
 */
static void test_commit_restore(struct env *e)
{
	struct hw_queue_rec rec;
	uint32_t needed, id;
	void *payload;

	puts("\narming a restored vIOMMU:");

	mig(e, IOMMU_VIOMMU_MIG_OP_COMMIT_RESTORE, EINVAL,
	    "COMMIT_RESTORE before RESTORE is refused");

	/* A ring with its log enabled, so the payload has a bit worth arming */
	id = alloc_ring(e, IOMMU_HW_QUEUE_TYPE_AMD_PPR, PPR_OFF,
			PPR_LEN_ENCODED, PPR_ARM_FLAG);
	printf("  hw_queue=%u pprlog=%#llx %u bytes, log enabled\n", id,
	       (unsigned long long)(e->iova + PPR_OFF), PPR_BYTES);

	payload = prepare_and_save(e, &needed, "SAVE with the ring enabled");
	if (!payload)
		return;
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after that save");

	/*
	 * Re-create the ring the way a destination does: same base and size,
	 * enable bits masked off.
	 */
	destroy_obj(e, id, "the enabled ring is destroyed");
	id = alloc_ring(e, IOMMU_HW_QUEUE_TYPE_AMD_PPR, PPR_OFF,
			PPR_LEN_ENCODED, 0);

	/* A restore on its own must leave the ring disarmed */
	if (!do_restore(e, payload, needed, "RESTORE accepts the payload"))
		goto out;
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort without committing");
	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0, "PREPARE_SAVE to look");
	if (save_ring_record(e, IOMMU_HW_QUEUE_TYPE_AMD_PPR, &rec,
			     "save after the uncommitted restore"))
		check_u64("the restore armed nothing", rec.queue_flags, 0);
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after looking");

	/* Committing is what arms it */
	if (!do_restore(e, payload, needed, "RESTORE again"))
		goto out;
	mig(e, IOMMU_VIOMMU_MIG_OP_COMMIT_RESTORE, 0,
	    "COMMIT_RESTORE succeeds");
	mig(e, IOMMU_VIOMMU_MIG_OP_COMMIT_RESTORE, EINVAL,
	    "COMMIT_RESTORE twice is refused");
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after the commit");
	mig(e, IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE, 0, "PREPARE_SAVE to check");
	if (save_ring_record(e, IOMMU_HW_QUEUE_TYPE_AMD_PPR, &rec,
			     "save after the commit")) {
		check_u64("the commit armed the PPR log",
			  rec.queue_flags & PPR_ARM_FLAG, PPR_ARM_FLAG);
		check_u64("the commit left the base alone", rec.base_gpa,
			  e->iova + PPR_OFF);
		check_u64("the commit left the size alone", rec.length_bytes,
			  PPR_BYTES);
	}
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after checking");

	/* A ring destroyed between the restore and the commit must stop it */
	if (!do_restore(e, payload, needed, "RESTORE before a destroy"))
		goto out;
	destroy_obj(e, id, "the ring is destroyed mid-sequence");
	mig(e, IOMMU_VIOMMU_MIG_OP_COMMIT_RESTORE, EINVAL,
	    "COMMIT_RESTORE refuses a ring that has gone");
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after the refusal");
	free(payload);

	/* And so must a ring appearing that the source never had */
	payload = prepare_and_save(e, &needed, "SAVE with no PPR ring");
	if (!payload)
		return;
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after that save");

	if (!do_restore(e, payload, needed, "RESTORE with no PPR ring"))
		goto out;
	id = alloc_ring(e, IOMMU_HW_QUEUE_TYPE_AMD_PPR, PPR_OFF,
			PPR_LEN_ENCODED, PPR_ARM_FLAG);
	mig(e, IOMMU_VIOMMU_MIG_OP_COMMIT_RESTORE, EINVAL,
	    "COMMIT_RESTORE refuses a ring that appeared");
	mig(e, IOMMU_VIOMMU_MIG_OP_ABORT, 0, "abort after that refusal");
	destroy_obj(e, id, "the extra ring is destroyed");

out:
	free(payload);
}

/*
 * R-016, IT-011 and LT-021: does the nesting parent's dirty tracking observe
 * the writes the IOMMU makes itself?
 *
 * Informational only. D-004 already copies the log contents into the payload
 * because the answer was unknown, so correctness does not rest on it either
 * way. What the answer decides is whether that copy could ever be dropped in
 * favour of migrating the pages as ordinary guest RAM.
 *
 * Two probes, both writes hardware makes into guest memory through the nesting
 * parent, landing on pages of their own so the bitmap can tell them apart: the
 * completion wait semaphore store as the control, and an event log entry as the
 * subject. The control is what makes a negative result readable, since dirty
 * tracking reports nothing for a page nobody wrote: "the log page is clean" on
 * its own cannot separate untracked log writes from tracking that never worked.
 */
#define DIRTY_GRAIN	4096
#define DIRTY_WORDS	(MAP_LEN / DIRTY_GRAIN / 64)

static bool set_dirty_tracking(struct env *e, bool on)
{
	struct iommu_hwpt_set_dirty_tracking cmd = {
		.size = sizeof(cmd),
		.flags = on ? IOMMU_HWPT_DIRTY_TRACKING_ENABLE : 0,
		.hwpt_id = e->parent_id,
	};

	return try_ioctl(e->iommufd, IOMMU_HWPT_SET_DIRTY_TRACKING, &cmd) == 0;
}

/* Reads the bitmap for the whole mapped range, clearing as it goes so that the
 * next probe starts from a page nobody has written yet.
 */
static bool read_dirty(struct env *e, uint64_t *bits)
{
	struct iommu_hwpt_get_dirty_bitmap cmd = {
		.size = sizeof(cmd),
		.hwpt_id = e->parent_id,
		.iova = e->iova,
		.length = MAP_LEN,
		.page_size = DIRTY_GRAIN,
		.data = (uintptr_t)bits,
	};

	memset(bits, 0, DIRTY_WORDS * sizeof(*bits));
	return try_ioctl(e->iommufd, IOMMU_HWPT_GET_DIRTY_BITMAP, &cmd) == 0;
}

static bool page_dirty(const uint64_t *bits, uint64_t off)
{
	uint64_t i = off / DIRTY_GRAIN;

	return (bits[i / 64] >> (i % 64)) & 1;
}

static void report_dirty(const uint64_t *bits, const char *what)
{
	unsigned n = 0;

	printf("    pages reported dirty after %s:", what);
	for (uint64_t i = 0; i < DIRTY_WORDS * 64; i++) {
		if ((bits[i / 64] >> (i % 64)) & 1) {
			printf(" %llu", (unsigned long long)i);
			n++;
		}
	}
	puts(n ? "" : " none");
}

/*
 * Ask hardware to write one entry into the guest event log, through the
 * driver's INSERT_GUEST_EVENT debugfs hook, and report whether it landed.
 *
 * That hook is addressed by GID, which nothing exposes to userspace, so try the
 * low ones on each IOMMU until the guest event log tail moves. Acceptable only
 * because this mode runs alone on the host: a GID belonging to another guest
 * would collect a spurious event.
 */
static bool inject_guest_event(struct env *e)
{
	uint32_t before = reg32(e, VF_EVT_TAIL);

	for (unsigned idx = 0; idx < 16; idx++) {
		char path[80];
		int fd;

		snprintf(path, sizeof(path),
			 "/sys/kernel/debug/iommu/amd/iommu%02u/guest_event", idx);
		fd = open(path, O_WRONLY);
		if (fd < 0)
			continue;

		for (unsigned gid = 1; gid < 16; gid++) {
			struct timespec t0, now;
			char buf[8];
			int len;

			len = snprintf(buf, sizeof(buf), "%u", gid);
			if (write(fd, buf, len) < 0)
				continue;

			clock_gettime(CLOCK_MONOTONIC, &t0);
			do {
				if (reg32(e, VF_EVT_TAIL) != before) {
					printf("    injected on iommu%02u as gid %u,"
					       " tail %#x -> %#x\n", idx, gid,
					       before, reg32(e, VF_EVT_TAIL));
					close(fd);
					return true;
				}
				clock_gettime(CLOCK_MONOTONIC, &now);
			} while (elapsed_us(&t0, &now) < 20000);
		}
		close(fd);
	}
	return false;
}

/*
 * The device's DTE, through the driver's debugfs dump, so that the HAD bits can
 * be read back. Returns false if the dump is unavailable or unparsable.
 *
 * This is the control that makes a clean bitmap mean something. The driver arms
 * dirty tracking by setting HAD in the DTE of every device on the domain, so
 * seeing those bits set is what separates "the IOMMU's writes are not tracked"
 * from "tracking was never turned on".
 */
static bool dte_words(const char *pci, uint64_t out[4])
{
	char line[256];
	FILE *f;
	int fd;

	fd = open("/sys/kernel/debug/iommu/amd/devid", O_WRONLY);
	if (fd < 0)
		return false;
	if (write(fd, pci, strlen(pci)) < 0) {
		close(fd);
		return false;
	}
	close(fd);

	f = fopen("/sys/kernel/debug/iommu/amd/devtbl", "r");
	if (!f)
		return false;

	while (fgets(line, sizeof(line), f)) {
		unsigned long long q[4];

		if (sscanf(line, "%*s %llx %llx %llx %llx", &q[3], &q[2], &q[1],
			   &q[0]) == 4) {
			for (int i = 0; i < 4; i++)
				out[i] = q[i];
			fclose(f);
			return true;
		}
	}
	fclose(f);
	return false;
}

static bool dte_word0(const char *pci, uint64_t *out)
{
	uint64_t dte[4];

	if (!dte_words(pci, dte))
		return false;
	*out = dte[0];
	return true;
}

static bool report_had(const char *bdf, const char *which)
{
	uint64_t w0;

	if (!dte_word0(bdf, &w0)) {
		printf("    %s (%s) unreadable\n", which, bdf);
		return false;
	}
	printf("    %s (%s) DTE[0] %016llx, HAD %s\n", which, bdf,
	       (unsigned long long)w0,
	       (w0 & DTE_FLAG_HAD) == DTE_FLAG_HAD ? "set" : "clear");
	return (w0 & DTE_FLAG_HAD) == DTE_FLAG_HAD;
}

/*
 * Report the fields that distinguish a nested DTE, and say whether the entry is
 * still one. A nested DTE carries GV, the vIOMMU enable and a guest device ID;
 * set_dte_entry() building from the parent domain writes none of them.
 */
static bool report_nested_dte(const char *pci, const char *when)
{
	uint64_t dte[4];
	bool nested;

	if (!dte_words(pci, dte)) {
		printf("    %-14s DTE unreadable\n", when);
		return false;
	}

	nested = (dte[0] & DTE_FLAG_GV) && (dte[3] & DTE_VIOMMU_EN);
	printf("    %-14s DTE[0] %016llx DTE[3] %016llx, mode %llu, GV %d,"
	       " vImuEn %d, gDevID %llu\n", when,
	       (unsigned long long)dte[0], (unsigned long long)dte[3],
	       (unsigned long long)((dte[0] & DTE_MODE_MASK) >> DTE_MODE_SHIFT),
	       !!(dte[0] & DTE_FLAG_GV), !!(dte[3] & DTE_VIOMMU_EN),
	       (unsigned long long)((dte[3] & DTE_VIOMMU_GDEVICEID) >> 16));
	return nested;
}

/* Map the same memory again at a fixed IOVA, to reach for a deeper table */
static bool map_at(struct env *e, uint64_t iova)
{
	struct iommu_ioas_map map = { .size = sizeof(map) };

	map.ioas_id = e->ioas_id;
	map.user_va = (uintptr_t)e->buf;
	map.length = MAP_LEN;
	map.iova = iova;
	map.flags = IOMMU_IOAS_MAP_READABLE | IOMMU_IOAS_MAP_WRITEABLE |
		    IOMMU_IOAS_MAP_FIXED_IOVA;
	return try_ioctl(e->iommufd, IOMMU_IOAS_MAP, &map) == 0;
}

/*
 * The nest parent's v1 table starts shallow and grows a level whenever a
 * mapping lands above what the current top covers. Growing it calls
 * amd_iommu_change_top(), which rewrites the DTE of every device on the
 * parent's dev_list from that device's own domain. A nest-attached device is
 * still on that list, because nested_attach_device() never takes it off, and
 * its domain is the parent, so the question is whether the nested DTE survives.
 */
static void probe_change_top(struct env *e, const char *pci)
{
	static const uint64_t iova[] = {
		1ULL << 40, 1ULL << 43, 1ULL << 46,
		1ULL << 48, 1ULL << 51, 1ULL << 54,
	};

	puts("\nmeasuring whether growing the parent's page table keeps the"
	     " nested DTE:");

	if (!report_nested_dte(pci, "after attach")) {
		fail("start from a nested DTE", "GV or vImuEn missing");
		return;
	}
	ok("the attach left a nested DTE");

	for (unsigned i = 0; i < sizeof(iova) / sizeof(iova[0]); i++) {
		char when[32];

		if (!map_at(e, iova[i])) {
			printf("    mapping at %#llx rejected: %s\n",
			       (unsigned long long)iova[i], strerror(errno));
			continue;
		}
		snprintf(when, sizeof(when), "map %#llx",
			 (unsigned long long)iova[i]);
		if (!report_nested_dte(pci, when)) {
			fail("keep the nested DTE across a table growth",
			     "rebuilt as a plain stage-2 entry");
			return;
		}
	}

	ok("the nested DTE survived every growth");
}

/*
 * Attaching a nest-attached device back to its nest parent has to reprogram
 * the DTE. The device's domain already reads as that parent, so an attach that
 * takes the "same domain, nothing to do" shortcut would leave the guest
 * translation in place on a device the VMM believes it has taken back.
 */
static void probe_reattach(struct env *e, const char *pci)
{
	struct vfio_device_attach_iommufd_pt attach = {
		.argsz = sizeof(attach),
	};

	puts("\nmeasuring whether attaching back to the nest parent takes the"
	     " device back:");

	if (!report_nested_dte(pci, "nested")) {
		fail("start from a nested DTE", "GV or vImuEn missing");
		return;
	}

	attach.pt_id = e->parent_id;
	if (try_ioctl(e->cdev, VFIO_DEVICE_ATTACH_IOMMUFD_PT, &attach)) {
		fail("attach back to the nest parent", strerror(errno));
		return;
	}
	if (report_nested_dte(pci, "back to parent"))
		fail("clear the nested DTE", "still a nested entry");
	else
		ok("the DTE is a plain stage-2 entry again");

	/* And back again, so that the round trip is not one way */
	attach.pt_id = e->nested_id;
	if (try_ioctl(e->cdev, VFIO_DEVICE_ATTACH_IOMMUFD_PT, &attach)) {
		fail("attach to the nested domain again", strerror(errno));
		return;
	}
	if (report_nested_dte(pci, "nested again"))
		ok("the device goes back to nested translation");
	else
		fail("restore the nested DTE", "GV or vImuEn missing");
}

/*
 * The vIOMMU's translate devid, as bus:slot.func, from the driver's debugfs
 * listing. This is the DTE that governs the IOMMU's own accesses to the guest's
 * buffers, so it is the one whose HAD bits decide the question being measured.
 */
static bool trans_devid_bdf(char *out, size_t len)
{
	char line[256];
	FILE *f;

	f = fopen("/sys/kernel/debug/iommu/amd/trans_devid/viommus", "r");
	if (!f)
		return false;

	while (fgets(line, sizeof(line), f)) {
		unsigned devid;
		char *p;

		p = strstr(line, "trans_devid=");
		if (!p || sscanf(p, "trans_devid=%x", &devid) != 1)
			continue;
		snprintf(out, len, "%x:%x.%x", devid >> 8, (devid >> 3) & 0x1f,
			 devid & 7);
		fclose(f);
		return true;
	}
	fclose(f);
	return false;
}

static void measure_dirty(struct env *e, const char *pci, bool arm_late)
{
	volatile uint64_t *sem = sem_ptr(e);
	uint64_t bits[DIRTY_WORDS];
	bool sem_seen, evt_seen;
	struct timespec t0, now;
	uint32_t id;

	bool trans_armed = false;
	char tbdf[16];

	puts("\nmeasuring whether dirty tracking sees the IOMMU's own writes:");

	if (arm_late) {
		puts("  arming after the vIOMMU was allocated, which is the"
		     " order a VMM\n  enabling tracking at migration start"
		     " would naturally use");
		/*
		 * Read the DTE first. Whatever the attach left here is what a
		 * toggle that never reaches this device would leave behind, so
		 * this is the baseline the reading after arming is measured
		 * against.
		 */
		report_had(pci, "before arming ");
		if (!set_dirty_tracking(e, true)) {
			fail("enable dirty tracking", strerror(errno));
			return;
		}
	} else {
		puts("  armed before the vIOMMU was allocated, so that the"
		     " translate DTE\n  inherits it");
	}

	/*
	 * Tracking is on by now in both orders, so the device's DTE has to
	 * carry HAD whichever path put it there: the attach sampling a domain
	 * that was already tracking, or a toggle walking one of the lists the
	 * device sits on.
	 */
	if (report_had(pci, e->nested_id ? "nested device  " : "assigned device"))
		ok("the device DTE is armed");
	else
		fail("arm the device DTE", "HAD clear while tracking is on");

	if (trans_devid_bdf(tbdf, sizeof(tbdf)))
		trans_armed = report_had(tbdf, "translate DTE ");
	else
		fail("locate the translate devid", "debugfs listing unusable");

	id = alloc_ring(e, IOMMU_HW_QUEUE_TYPE_AMD_EVT, EVT_OFF,
			EVT_LEN_ENCODED, IOMMU_HW_QUEUE_FLAG_AMD_EVT_LOG_EN);
	printf("  event log hw_queue=%u at %#llx, semaphore at %#llx\n", id,
	       (unsigned long long)(e->iova + EVT_OFF),
	       (unsigned long long)(e->iova + SEM_OFF));

	if (!read_dirty(e, bits)) {
		fail("read the dirty bitmap", strerror(errno));
		goto out;
	}
	ok("the dirty bitmap reads back");
	report_dirty(bits, "setup");

	/* Control: hardware stores the semaphore on the completion wait */
	*sem = 0;
	plant_completion_wait(slot(e, probe_tail), e->iova + SEM_OFF,
			      SEM_EXPECTED, true);
	probe_tail = (probe_tail + CMD_ENTRY_BYTES) % RING_BYTES;
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	write_reg32(e, VF_CMD_TAIL, probe_tail);

	clock_gettime(CLOCK_MONOTONIC, &t0);
	while (*sem != SEM_EXPECTED) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (elapsed_us(&t0, &now) > 500000)
			break;
	}
	if (*sem != SEM_EXPECTED) {
		fail("the semaphore store lands", "hardware never wrote it");
		goto out;
	}
	ok("the semaphore store landed, so hardware wrote guest memory");

	if (!read_dirty(e, bits)) {
		fail("read the dirty bitmap after the store", strerror(errno));
		goto out;
	}
	sem_seen = page_dirty(bits, SEM_OFF);
	report_dirty(bits, "the semaphore store");

	/* Subject: hardware writes an entry into the guest event log */
	if (!inject_guest_event(e)) {
		fail("inject a guest event", "the log tail never advanced");
		goto out;
	}
	ok("hardware wrote an event log entry");

	if (!read_dirty(e, bits)) {
		fail("read the dirty bitmap after the log write", strerror(errno));
		goto out;
	}
	evt_seen = page_dirty(bits, EVT_OFF);
	report_dirty(bits, "the event log write");

	printf("\n  R-016: translate DTE %s, semaphore page %s, event log page %s\n",
	       trans_armed ? "armed" : "unarmed",
	       sem_seen ? "DIRTY" : "clean", evt_seen ? "DIRTY" : "clean");
	if (evt_seen && sem_seen)
		puts("  tracking observes the IOMMU's own writes when the\n"
		     "  translate DTE is armed for them");
	else if (!trans_armed)
		puts("  the translate DTE was never armed, so this says nothing\n"
		     "  about the hardware, only about the order of arming");
	else
		puts("  armed and still not observed: the payload must carry\n"
		     "  the log contents");

out:
	set_dirty_tracking(e, false);
}

int main(int argc, char **argv)
{
	bool probe = false, abandon = false, drain = false, status = false;
	bool raise_only = false, write_only = false, dirty = false;
	bool arm_late = false, nested = false, cold = false, grow = false;
	bool reattach = false;
	const char *pci = NULL;
	struct env e = {};

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--probe"))
			probe = true;
		else if (!strcmp(argv[i], "--abandon"))
			abandon = true;
		else if (!strcmp(argv[i], "--drain"))
			drain = true;
		else if (!strcmp(argv[i], "--status"))
			status = true;
		else if (!strcmp(argv[i], "--status-raise-only"))
			status = raise_only = true;
		else if (!strcmp(argv[i], "--status-write-only"))
			status = write_only = true;
		else if (!strcmp(argv[i], "--dirty"))
			dirty = true;
		else if (!strcmp(argv[i], "--dirty-late"))
			dirty = arm_late = true;
		else if (!strcmp(argv[i], "--nested"))
			nested = true;
		else if (!strcmp(argv[i], "--nested-cold"))
			nested = cold = true;
		else if (!strcmp(argv[i], "--grow"))
			grow = nested = true;
		else if (!strcmp(argv[i], "--reattach"))
			reattach = nested = true;
		else
			pci = argv[i];
	}
	if (!pci)
		pci = "0000:e1:00.1";

	printf("AMD vIOMMU migration harness, device %s\n", pci);
	setup(&e, pci, dirty, arm_late, nested, cold);

	if (grow) {
		probe_change_top(&e, pci);
		printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
		       failures, failures == 1 ? "" : "s");
	} else if (reattach) {
		probe_reattach(&e, pci);
		printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
		       failures, failures == 1 ? "" : "s");
	} else if (dirty) {
		/* COMWAIT_EN too, since the control probe stores a semaphore */
		alloc_cmd_ring(&e, IOMMU_HW_QUEUE_FLAG_AMD_CMDBUF_EN |
				   IOMMU_HW_QUEUE_FLAG_AMD_COMWAIT_EN);
		measure_dirty(&e, pci, arm_late);
		printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
		       failures, failures == 1 ? "" : "s");
	} else if (status) {
		/* COMWAIT_EN too, since the probe drives a completion wait */
		alloc_cmd_ring(&e, IOMMU_HW_QUEUE_FLAG_AMD_CMDBUF_EN |
				   IOMMU_HW_QUEUE_FLAG_AMD_COMWAIT_EN);
		probe_status(&e, raise_only, write_only);
	} else if (probe) {
		alloc_cmd_ring(&e, IOMMU_HW_QUEUE_FLAG_AMD_CMDBUF_EN |
				   IOMMU_HW_QUEUE_FLAG_AMD_COMWAIT_EN);
		probe_head_vs_store(&e);
	} else if (abandon) {
		alloc_cmd_ring(&e, IOMMU_HW_QUEUE_FLAG_AMD_CMDBUF_EN);
		abandon_prepared(&e);
		printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
		       failures, failures == 1 ? "" : "s");
	} else if (drain) {
		alloc_cmd_ring(&e, IOMMU_HW_QUEUE_FLAG_AMD_CMDBUF_EN |
				   IOMMU_HW_QUEUE_FLAG_AMD_COMWAIT_EN);
		test_drain(&e);
		printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
		       failures, failures == 1 ? "" : "s");
	} else {
		test_capability(&e);
		test_state_machine(&e);
		alloc_cmd_ring(&e, IOMMU_HW_QUEUE_FLAG_AMD_CMDBUF_EN);
		test_fence(&e);
		/* test_fence leaves the ring idle with head and tail at 0 */
		test_save(&e, 0);
		/* Allocates a log ring, so it has to follow test_save */
		test_log_capture(&e);
		/* Both need the log ring the capture test allocated */
		test_restore(&e);
		test_restore_rejects(&e);
		/* These allocate rings of their own, so they go last */
		test_queue_destroy(&e);
		test_commit_restore(&e);
		printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
		       failures, failures == 1 ? "" : "s");
	}

	close(e.cdev);
	close(e.iommufd);
	return failures ? 1 : 0;
}
