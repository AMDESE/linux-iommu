// SPDX-License-Identifier: GPL-2.0-only
/*
 * Exercise VFIO_MIGRATION_STOP_COPY against a real SDXI VF without a VMM.
 *
 * Stands in for the parts of QEMU that a migration needs: open the VFIO cdev,
 * drive the migration state machine, save and restore the MMIO register blob.
 * No guest OS is involved.
 *
 * Usage: sdxi-mig-harness [mode] [pci-address]
 *
 *   default              migration capability, state machine, save/restore
 *   --p2p-flags          migration capability incl. VFIO_MIGRATION_P2P
 *   --p2p-fsm            RUNNING_P2P FSM arcs and P2P stop-copy path
 *   --precopy-fsm        PRE_COPY FSM, precopy ioctl, empty stream, finalize
 *   --stop-gsv           reach GSV_STOP before STOP_COPY save
 *   --cap-mismatch       restore refuses when CAP0/CAP1 do not match
 *   --probe              record fn_gsv, blob size and key MMIO registers
 *
 * Default pci-address: none (required)
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <endian.h>

#include <linux/iommufd.h>
#include <linux/vfio.h>

#define SDXI_MIG_MAGIC		0x49584453	/* "SDXI" */
#define SDXI_MIG_VERSION	2

#define SDXI_MMIO_CTL0		0x00000
#define SDXI_MMIO_CTL2		0x00010
#define SDXI_MMIO_STS0		0x00100
#define SDXI_MMIO_CAP0		0x00200
#define SDXI_MMIO_CAP1		0x00208

#define SDXI_MMIO_STS0_FN_GSV	((uint64_t)0x7)
#define SDXI_MMIO_CAP0_SFUNC	((uint64_t)0xffff)

enum sdxi_fn_gsv {
	SDXI_GSV_STOP = 0,
	SDXI_GSV_INIT,
	SDXI_GSV_ACTIVE,
	SDXI_GSV_STOPG_SF,
	SDXI_GSV_STOPG_HD,
	SDXI_GSV_ERROR,
};

struct sdxi_mig_cxt_sts {
	uint64_t dma;
	uint8_t sts[16];
} __attribute__((packed));

struct sdxi_mig_blob {
	uint32_t magic;
	uint32_t version;
	uint64_t cap0;
	uint64_t cap1;
	uint64_t ctl0;
	uint64_t ctl2;
	uint64_t cxt_l2;
	uint64_t rkey;
	uint64_t err_cfg;
	uint64_t err_ctl;
	uint64_t err_wrt;
	uint64_t err_rd;
	uint32_t nr_cxt;
	uint32_t nr_pad;
	struct sdxi_mig_cxt_sts cxt[];
} __attribute__((packed));

struct mig_image {
	uint8_t *data;
	size_t len;
};

struct dev {
	int iommufd;
	int fd;
	uint32_t ioas_id;
	void *bar0;
	size_t bar0_size;
	enum vfio_device_mig_state state;
};

static int failures;

static void test_migration_flags(struct dev *d, bool want_p2p, bool want_precopy);

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

static int try_ioctl(int fd, unsigned long req, void *arg)
{
	if (ioctl(fd, req, arg))
		return errno ? errno : EIO;
	return 0;
}

static const char *gsv_str(enum sdxi_fn_gsv gsv)
{
	static const char *names[] = {
		[SDXI_GSV_STOP] = "GSV_STOP",
		[SDXI_GSV_INIT] = "GSV_INIT",
		[SDXI_GSV_ACTIVE] = "GSV_ACTIVE",
		[SDXI_GSV_STOPG_SF] = "GSV_STOPG_SF",
		[SDXI_GSV_STOPG_HD] = "GSV_STOPG_HD",
		[SDXI_GSV_ERROR] = "GSV_ERROR",
	};
	if (gsv <= SDXI_GSV_ERROR)
		return names[gsv];
	return "GSV_UNKNOWN";
}

static const char *mig_state_str(enum vfio_device_mig_state st)
{
	switch (st) {
	case VFIO_DEVICE_STATE_ERROR: return "ERROR";
	case VFIO_DEVICE_STATE_STOP: return "STOP";
	case VFIO_DEVICE_STATE_RUNNING: return "RUNNING";
	case VFIO_DEVICE_STATE_STOP_COPY: return "STOP_COPY";
	case VFIO_DEVICE_STATE_RESUMING: return "RESUMING";
	case VFIO_DEVICE_STATE_RUNNING_P2P: return "RUNNING_P2P";
	case VFIO_DEVICE_STATE_PRE_COPY: return "PRE_COPY";
	case VFIO_DEVICE_STATE_PRE_COPY_P2P: return "PRE_COPY_P2P";
	default: return "OTHER";
	}
}

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
			"fatal: %s missing. Bind the VF to sdxi_vfio_pci first:\n"
			"  scripts/setup-sdxi-sriov.sh --setup\n",
			path);
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

static void setup_dev(struct dev *d, const char *pci)
{
	struct iommu_ioas_alloc ioas = { .size = sizeof(ioas) };
	struct vfio_device_bind_iommufd bind = { .argsz = sizeof(bind) };
	struct vfio_device_attach_iommufd_pt attach = {
		.argsz = sizeof(attach),
	};

	d->iommufd = open("/dev/iommu", O_RDWR);
	if (d->iommufd < 0)
		die("/dev/iommu");

	if (try_ioctl(d->iommufd, IOMMU_IOAS_ALLOC, &ioas))
		die("IOMMU_IOAS_ALLOC");
	d->ioas_id = ioas.out_ioas_id;

	d->fd = open_vfio_cdev(pci);

	bind.iommufd = d->iommufd;
	if (try_ioctl(d->fd, VFIO_DEVICE_BIND_IOMMUFD, &bind))
		die("VFIO_DEVICE_BIND_IOMMUFD");

	attach.pt_id = d->ioas_id;
	if (try_ioctl(d->fd, VFIO_DEVICE_ATTACH_IOMMUFD_PT, &attach))
		die("VFIO_DEVICE_ATTACH_IOMMUFD_PT");

	printf("  iommufd=%d ioas=%u cdev=%d\n", d->iommufd, d->ioas_id, d->fd);
}

static void teardown_dev(struct dev *d)
{
	if (d->bar0) {
		munmap(d->bar0, d->bar0_size);
		d->bar0 = NULL;
	}
	if (d->fd >= 0)
		close(d->fd);
	if (d->iommufd >= 0)
		close(d->iommufd);
	d->fd = d->iommufd = -1;
}

static enum sdxi_fn_gsv read_gsv(struct dev *d)
{
	volatile uint64_t sts0;

	if (!d->bar0)
		return SDXI_GSV_ERROR;
	sts0 = *(volatile uint64_t *)((char *)d->bar0 + SDXI_MMIO_STS0);
	if (sts0 == ~0ULL)
		return SDXI_GSV_STOP;
	return (enum sdxi_fn_gsv)(sts0 & SDXI_MMIO_STS0_FN_GSV);
}

static uint64_t read_mmio64(struct dev *d, unsigned off)
{
	return *(volatile uint64_t *)((char *)d->bar0 + off);
}

static void map_bar0(struct dev *d)
{
	struct vfio_region_info reg = { .argsz = sizeof(reg), .index = 0 };

	if (try_ioctl(d->fd, VFIO_DEVICE_GET_REGION_INFO, &reg))
		die("VFIO_DEVICE_GET_REGION_INFO(BAR0)");

	if (!(reg.flags & VFIO_REGION_INFO_FLAG_MMAP))
		die("BAR0 is not mmapable");

	d->bar0 = mmap(NULL, reg.size, PROT_READ | PROT_WRITE, MAP_SHARED,
			 d->fd, reg.offset);
	if (d->bar0 == MAP_FAILED)
		die("mmap BAR0");
	d->bar0_size = reg.size;
}

static int mig_get_state(struct dev *d, enum vfio_device_mig_state *out)
{
	uint64_t buf[4] = {};
	struct vfio_device_feature *feature = (struct vfio_device_feature *)buf;
	struct vfio_device_feature_mig_state *ms =
		(struct vfio_device_feature_mig_state *)feature->data;
	int err;

	feature->argsz = sizeof(*feature) + sizeof(*ms);
	feature->flags = VFIO_DEVICE_FEATURE_GET |
			 VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE;
	ms->data_fd = -1;
	err = try_ioctl(d->fd, VFIO_DEVICE_FEATURE, feature);
	if (err)
		return err;
	*out = ms->device_state;
	d->state = ms->device_state;
	return 0;
}

static int mig_set_state(struct dev *d, enum vfio_device_mig_state new_state,
			 int *data_fd_out)
{
	uint64_t buf[4] = {};
	struct vfio_device_feature *feature = (struct vfio_device_feature *)buf;
	struct vfio_device_feature_mig_state *ms =
		(struct vfio_device_feature_mig_state *)feature->data;
	int err;

	feature->argsz = sizeof(*feature) + sizeof(*ms);
	feature->flags = VFIO_DEVICE_FEATURE_SET |
			 VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE;
	ms->device_state = new_state;
	ms->data_fd = -1;
	err = try_ioctl(d->fd, VFIO_DEVICE_FEATURE, feature);
	if (err)
		return err;
	d->state = ms->device_state;
	if (data_fd_out)
		*data_fd_out = ms->data_fd;
	return 0;
}

static int mig_expect(struct dev *d, enum vfio_device_mig_state new_state,
		      int want, const char *what, int *data_fd_out)
{
	int err = mig_set_state(d, new_state, data_fd_out);

	if (err == want) {
		ok(what);
		return 0;
	}
	fail(what, err ? strerror(err) : "unexpected success");
	return err;
}

static void test_migration_capability(struct dev *d)
{
	test_migration_flags(d, false, false);
}

static void test_migration_flags(struct dev *d, bool want_p2p, bool want_precopy)
{
	uint64_t buf[4] = {};
	struct vfio_device_feature *feature = (struct vfio_device_feature *)buf;
	struct vfio_device_feature_migration *mig =
		(struct vfio_device_feature_migration *)feature->data;

	printf("\nmigration capability:\n");
	feature->argsz = sizeof(*feature) + sizeof(*mig);
	feature->flags = VFIO_DEVICE_FEATURE_GET | VFIO_DEVICE_FEATURE_MIGRATION;
	if (try_ioctl(d->fd, VFIO_DEVICE_FEATURE, feature)) {
		fail("VFIO_DEVICE_FEATURE_MIGRATION", strerror(errno));
		return;
	}
	ok("VFIO_DEVICE_FEATURE_MIGRATION succeeds");
	if (mig->flags & VFIO_MIGRATION_STOP_COPY)
		ok("VFIO_MIGRATION_STOP_COPY is advertised");
	else
		fail("VFIO_MIGRATION_STOP_COPY", "not in flags");
	if (want_p2p) {
		if (mig->flags & VFIO_MIGRATION_P2P)
			ok("VFIO_MIGRATION_P2P is advertised");
		else
			fail("VFIO_MIGRATION_P2P", "not in flags");
	}
	if (want_precopy) {
		if (mig->flags & VFIO_MIGRATION_PRE_COPY)
			ok("VFIO_MIGRATION_PRE_COPY is advertised");
		else
			fail("VFIO_MIGRATION_PRE_COPY", "not in flags");
	}
}

static ssize_t write_full(int fd, const void *buf, size_t len)
{
	size_t done = 0;
	ssize_t n;

	while (done < len) {
		n = write(fd, (const char *)buf + done, len - done);
		if (n < 0)
			return n;
		if (n == 0)
			break;
		done += n;
	}
	return done;
}

static void mig_image_free(struct mig_image *img)
{
	free(img->data);
	img->data = NULL;
	img->len = 0;
}

static int mig_image_read(int fd, struct mig_image *img)
{
	size_t cap = 512, n = 0;
	uint8_t *buf = malloc(cap);

	if (!buf)
		return ENOMEM;

	for (;;) {
		ssize_t r;

		if (n == cap) {
			size_t ncap = cap * 2;
			uint8_t *nbuf = realloc(buf, ncap);

			if (!nbuf) {
				free(buf);
				return ENOMEM;
			}
			buf = nbuf;
			cap = ncap;
		}
		r = read(fd, buf + n, cap - n);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			return errno ? errno : EIO;
		}
		if (r == 0)
			break;
		n += r;
	}

	img->data = buf;
	img->len = n;
	return 0;
}

static int mig_image_check(const struct mig_image *img, const char *what)
{
	const struct sdxi_mig_blob *b;
	char detail[128];
	uint32_t nr;
	size_t expect;

	if (img->len < sizeof(*b)) {
		snprintf(detail, sizeof(detail), "short image %zu", img->len);
		fail(what, detail);
		return -1;
	}

	b = (const struct sdxi_mig_blob *)img->data;
	if (le32toh(b->magic) != SDXI_MIG_MAGIC) {
		snprintf(detail, sizeof(detail), "magic 0x%x",
			 le32toh(b->magic));
		fail(what, detail);
		return -1;
	}
	ok("blob magic is SDXI");
	if (le32toh(b->version) != SDXI_MIG_VERSION) {
		snprintf(detail, sizeof(detail), "version %u",
			 le32toh(b->version));
		fail(what, detail);
		return -1;
	}
	ok("blob version is 2");

	nr = le32toh(b->nr_cxt);
	expect = sizeof(*b) + (size_t)nr * sizeof(struct sdxi_mig_cxt_sts);
	if (img->len != expect) {
		snprintf(detail, sizeof(detail),
			 "len %zu, %u context(s) want %zu",
			 img->len, nr, expect);
		fail(what, detail);
		return -1;
	}
	ok("blob length matches context-status records");
	return 0;
}

static void ensure_running(struct dev *d)
{
	enum vfio_device_mig_state st;
	int err;

	err = mig_get_state(d, &st);
	if (err) {
		fail("read migration state", strerror(err));
		return;
	}
	if (st == VFIO_DEVICE_STATE_RUNNING)
		return;
	if (st == VFIO_DEVICE_STATE_RUNNING_P2P)
		mig_expect(d, VFIO_DEVICE_STATE_RUNNING, 0,
			   "RUNNING_P2P -> RUNNING cleanup", NULL);
	else if (st == VFIO_DEVICE_STATE_STOP)
		mig_expect(d, VFIO_DEVICE_STATE_RUNNING, 0,
			   "STOP -> RUNNING cleanup", NULL);
	else if (st == VFIO_DEVICE_STATE_STOP_COPY)
		mig_expect(d, VFIO_DEVICE_STATE_STOP, 0,
			   "STOP_COPY -> STOP cleanup", NULL);
	else if (st == VFIO_DEVICE_STATE_PRE_COPY)
		mig_expect(d, VFIO_DEVICE_STATE_RUNNING, 0,
			   "PRE_COPY -> RUNNING cleanup", NULL);
	else if (st == VFIO_DEVICE_STATE_PRE_COPY_P2P) {
		mig_expect(d, VFIO_DEVICE_STATE_PRE_COPY, 0,
			   "PRE_COPY_P2P -> PRE_COPY cleanup", NULL);
		mig_expect(d, VFIO_DEVICE_STATE_RUNNING, 0,
			   "PRE_COPY -> RUNNING cleanup", NULL);
	}
}

static void ensure_stop(struct dev *d)
{
	enum vfio_device_mig_state st;
	int err;

	err = mig_get_state(d, &st);
	if (err) {
		fail("read migration state before save", strerror(err));
		return;
	}
	if (st == VFIO_DEVICE_STATE_RUNNING)
		mig_expect(d, VFIO_DEVICE_STATE_STOP, 0,
			   "RUNNING -> STOP before save", NULL);
}

static void test_default_suite(struct dev *d)
{
	struct mig_image img = {};
	enum vfio_device_mig_state st;
	unsigned long data_size = 0;
	int data_fd = -1;
	ssize_t n;
	int err;

	printf("\ndefault migration suite:\n");
	test_migration_capability(d);

	{
		uint64_t sz_buf[4] = {};
		struct vfio_device_feature *feature =
			(struct vfio_device_feature *)sz_buf;
		struct vfio_device_feature_mig_data_size *sz =
			(struct vfio_device_feature_mig_data_size *)feature->data;

		feature->argsz = sizeof(*feature) + sizeof(*sz);
		feature->flags = VFIO_DEVICE_FEATURE_GET |
				 VFIO_DEVICE_FEATURE_MIG_DATA_SIZE;
		if (!try_ioctl(d->fd, VFIO_DEVICE_FEATURE, feature)) {
			data_size = sz->stop_copy_length;
			printf("  stop_copy_length=%lu bytes\n", data_size);
		}
	}
	if (data_size < sizeof(struct sdxi_mig_blob)) {
		char detail[64];

		snprintf(detail, sizeof(detail), "got %lu, header is %zu",
			 data_size, sizeof(struct sdxi_mig_blob));
		fail("stop_copy_length covers the blob header", detail);
	} else {
		ok("stop_copy_length covers the blob header");
	}

	err = mig_get_state(d, &st);
	if (err) {
		fail("read initial migration state", strerror(err));
		return;
	}
	printf("  initial vfio state: %s\n", mig_state_str(st));

	ensure_stop(d);

	err = mig_set_state(d, VFIO_DEVICE_STATE_STOP_COPY, &data_fd);
	if (err) {
		fail("STOP -> STOP_COPY", strerror(err));
		return;
	}
	ok("STOP -> STOP_COPY");
	if (data_fd < 0) {
		fail("STOP_COPY returned a data fd", "data_fd is -1");
		return;
	}
	ok("STOP_COPY returned a data fd");

	err = mig_image_read(data_fd, &img);
	close(data_fd);
	if (err || mig_image_check(&img, "saved blob")) {
		if (err)
			fail("read migration blob from data fd", strerror(err));
		mig_image_free(&img);
		return;
	}
	ok("read migration blob from data fd");

	mig_expect(d, VFIO_DEVICE_STATE_STOP, 0, "STOP_COPY -> STOP", NULL);

	err = mig_set_state(d, VFIO_DEVICE_STATE_RESUMING, &data_fd);
	if (err) {
		mig_image_free(&img);
		fail("STOP -> RESUMING", strerror(err));
		return;
	}
	ok("STOP -> RESUMING");
	if (data_fd < 0) {
		mig_image_free(&img);
		fail("RESUMING returned a data fd", "data_fd is -1");
		return;
	}
	ok("RESUMING returned a data fd");

	n = write_full(data_fd, img.data, img.len);
	close(data_fd);
	if (n != (ssize_t)img.len) {
		char detail[64];

		snprintf(detail, sizeof(detail), "wrote %zd of %zu", n, img.len);
		mig_image_free(&img);
		fail("write migration blob to data fd", detail);
		return;
	}
	mig_image_free(&img);
	ok("write migration blob to data fd");

	mig_expect(d, VFIO_DEVICE_STATE_STOP, 0,
		   "RESUMING -> STOP after restore", NULL);
	mig_expect(d, VFIO_DEVICE_STATE_RUNNING, 0, "STOP -> RUNNING", NULL);

	if (read_gsv(d) == SDXI_GSV_ACTIVE)
		ok("fn_gsv is GSV_ACTIVE after RUNNING transition");
	else
		fail("fn_gsv is GSV_ACTIVE after RUNNING transition",
		     gsv_str(read_gsv(d)));
}

static void test_stop_gsv(struct dev *d)
{
	enum vfio_device_mig_state st;
	enum sdxi_fn_gsv gsv;
	int data_fd = -1;
	int err;
	struct mig_image img = {};

	printf("\nstop-gsv (GSV_STOP before STOP_COPY):\n");

	err = mig_get_state(d, &st);
	if (err) {
		fail("read migration state", strerror(err));
		return;
	}

	gsv = read_gsv(d);
	printf("  fn_gsv before stop: %s\n", gsv_str(gsv));

	if (st == VFIO_DEVICE_STATE_STOP && gsv == SDXI_GSV_STOP) {
		ok("device already stopped at VFIO and GSV levels");
	} else if (st == VFIO_DEVICE_STATE_RUNNING) {
		enum sdxi_fn_gsv mid;

		if (gsv != SDXI_GSV_ACTIVE)
			printf("  note: fn_gsv is %s while VFIO is RUNNING\n",
			       gsv_str(gsv));
		mig_expect(d, VFIO_DEVICE_STATE_STOP, 0,
			   "RUNNING -> STOP (driver soft stop)", NULL);
		mid = read_gsv(d);
		printf("  fn_gsv immediately after STOP: %s\n", gsv_str(mid));
		gsv = read_gsv(d);
		if (gsv == SDXI_GSV_STOP)
			ok("fn_gsv reached GSV_STOP");
		else
			fail("fn_gsv reached GSV_STOP", gsv_str(gsv));
	} else {
		fail("device in a known state for stop-gsv",
		     mig_state_str(st));
		return;
	}

	if (read_gsv(d) != SDXI_GSV_STOP) {
		fail("refusing STOP_COPY while fn_gsv is not GSV_STOP",
		     gsv_str(read_gsv(d)));
		return;
	}
	ok("fn_gsv is GSV_STOP before STOP_COPY");

	if (mig_set_state(d, VFIO_DEVICE_STATE_STOP_COPY, &data_fd)) {
		fail("STOP -> STOP_COPY with fn_gsv stopped", strerror(errno));
		return;
	}
	ok("STOP -> STOP_COPY with fn_gsv stopped");
	if (data_fd >= 0) {
		if (!mig_image_read(data_fd, &img) &&
		    !mig_image_check(&img, "saved blob while fn_gsv is GSV_STOP"))
			ok("saved blob while fn_gsv is GSV_STOP");
		else
			fail("saved blob while fn_gsv is GSV_STOP",
			     "short read");
		mig_image_free(&img);
		close(data_fd);
		mig_expect(d, VFIO_DEVICE_STATE_STOP, 0,
			   "STOP_COPY -> STOP cleanup", NULL);
	}
	mig_expect(d, VFIO_DEVICE_STATE_RUNNING, 0,
		   "STOP -> RUNNING after stop-gsv", NULL);
}

static void test_cap_mismatch(struct dev *d)
{
	struct mig_image img = {}, bad = {};
	int data_fd = -1;
	int err;

	printf("\ncapability mismatch on restore:\n");

	ensure_stop(d);
	if (mig_set_state(d, VFIO_DEVICE_STATE_STOP_COPY, &data_fd)) {
		fail("save blob for cap-mismatch test", strerror(errno));
		return;
	}
	if (data_fd < 0) {
		fail("read saved blob", "no fd");
		return;
	}
	err = mig_image_read(data_fd, &img);
	close(data_fd);
	if (err || mig_image_check(&img, "saved blob")) {
		if (err)
			fail("read saved blob", strerror(err));
		mig_image_free(&img);
		return;
	}
	ok("saved a valid blob");
	mig_expect(d, VFIO_DEVICE_STATE_STOP, 0, "STOP_COPY -> STOP", NULL);

	bad.data = malloc(img.len);
	if (!bad.data) {
		mig_image_free(&img);
		fail("copy blob for cap-mismatch", strerror(ENOMEM));
		return;
	}
	memcpy(bad.data, img.data, img.len);
	bad.len = img.len;
	*(uint64_t *)(bad.data + offsetof(struct sdxi_mig_blob, cap1)) ^=
		htole64(0x1000ULL);

	if (mig_set_state(d, VFIO_DEVICE_STATE_RESUMING, &data_fd)) {
		mig_image_free(&img);
		mig_image_free(&bad);
		fail("STOP -> RESUMING for cap-mismatch test", strerror(errno));
		return;
	}
	if (data_fd < 0) {
		mig_image_free(&img);
		mig_image_free(&bad);
		fail("RESUMING data fd", "missing");
		return;
	}
	write_full(data_fd, bad.data, bad.len);

	err = mig_set_state(d, VFIO_DEVICE_STATE_STOP, NULL);
	if (err == EOPNOTSUPP || err == EINVAL)
		ok("restore refused mismatched CAP1");
	else if (err)
		fail("restore refused mismatched CAP1",
		     strerror(err));
	else
		fail("restore refused mismatched CAP1", "succeeded");

	/*
	 * Restore failed but left us in RESUMING with the bad blob still
	 * buffered. Rewrite the original blob on the same fd and complete
	 * the restore before returning to RUNNING.
	 */
	if (write_full(data_fd, img.data, img.len) != (ssize_t)img.len) {
		fail("rewrite good blob after refused restore", strerror(errno));
		close(data_fd);
		mig_image_free(&img);
		mig_image_free(&bad);
		return;
	}
	close(data_fd);
	mig_image_free(&img);
	mig_image_free(&bad);
	ok("rewrote good blob after refused restore");

	mig_expect(d, VFIO_DEVICE_STATE_STOP, 0,
		   "RESUMING -> STOP after good blob rewrite", NULL);
	mig_expect(d, VFIO_DEVICE_STATE_RUNNING, 0,
		   "recover to RUNNING after refused restore", NULL);
}

static int mig_query_precopy_info(int data_fd, struct vfio_precopy_info *info)
{
	info->argsz = sizeof(*info);
	info->flags = 0;
	info->initial_bytes = 0;
	info->dirty_bytes = 0;
	if (ioctl(data_fd, VFIO_MIG_GET_PRECOPY_INFO, info))
		return errno ? errno : EIO;
	return 0;
}

static int save_restore_roundtrip(struct dev *d)
{
	struct mig_image img = {};
	int data_fd = -1;
	ssize_t n;
	int err;

	ensure_stop(d);
	if (mig_set_state(d, VFIO_DEVICE_STATE_STOP_COPY, &data_fd)) {
		fail("STOP -> STOP_COPY roundtrip", strerror(errno));
		return -1;
	}
	if (data_fd < 0) {
		fail("STOP_COPY data fd roundtrip", "data_fd is -1");
		return -1;
	}
	err = mig_image_read(data_fd, &img);
	close(data_fd);
	if (err || mig_image_check(&img, "roundtrip saved blob")) {
		if (err)
			fail("read blob roundtrip", strerror(err));
		mig_image_free(&img);
		return -1;
	}
	mig_expect(d, VFIO_DEVICE_STATE_STOP, 0, "STOP_COPY -> STOP roundtrip", NULL);

	if (mig_set_state(d, VFIO_DEVICE_STATE_RESUMING, &data_fd)) {
		mig_image_free(&img);
		fail("STOP -> RESUMING roundtrip", strerror(errno));
		return -1;
	}
	if (data_fd < 0) {
		mig_image_free(&img);
		fail("RESUMING data fd roundtrip", "data_fd is -1");
		return -1;
	}
	n = write_full(data_fd, img.data, img.len);
	close(data_fd);
	if (n != (ssize_t)img.len) {
		mig_image_free(&img);
		fail("write blob roundtrip", "short write");
		return -1;
	}
	mig_image_free(&img);
	mig_expect(d, VFIO_DEVICE_STATE_STOP, 0,
		   "RESUMING -> STOP roundtrip", NULL);
	mig_expect(d, VFIO_DEVICE_STATE_RUNNING, 0, "STOP -> RUNNING roundtrip", NULL);
	return 0;
}

static void test_p2p_flags(struct dev *d)
{
	printf("\np2p flags:\n");
	test_migration_flags(d, true, false);
}

static void test_p2p_fsm(struct dev *d)
{
	struct mig_image img = {};
	int data_fd = -1;
	int err;

	printf("\np2p-fsm:\n");
	test_migration_flags(d, true, false);
	ensure_running(d);

	mig_expect(d, VFIO_DEVICE_STATE_RUNNING_P2P, 0,
		   "RUNNING -> RUNNING_P2P", NULL);
	if (read_gsv(d) == SDXI_GSV_STOP)
		ok("fn_gsv is GSV_STOP in RUNNING_P2P");
	else
		fail("fn_gsv is GSV_STOP in RUNNING_P2P", gsv_str(read_gsv(d)));

	mig_expect(d, VFIO_DEVICE_STATE_STOP, 0, "RUNNING_P2P -> STOP", NULL);
	if (read_gsv(d) == SDXI_GSV_STOP)
		ok("fn_gsv still GSV_STOP after RUNNING_P2P -> STOP");
	else
		fail("fn_gsv still GSV_STOP after RUNNING_P2P -> STOP",
		     gsv_str(read_gsv(d)));

	mig_expect(d, VFIO_DEVICE_STATE_RUNNING_P2P, 0,
		   "STOP -> RUNNING_P2P", NULL);
	if (read_gsv(d) == SDXI_GSV_STOP)
		ok("fn_gsv still GSV_STOP after STOP -> RUNNING_P2P");
	else
		fail("fn_gsv still GSV_STOP after STOP -> RUNNING_P2P",
		     gsv_str(read_gsv(d)));

	mig_expect(d, VFIO_DEVICE_STATE_RUNNING, 0,
		   "RUNNING_P2P -> RUNNING", NULL);
	if (read_gsv(d) == SDXI_GSV_ACTIVE)
		ok("fn_gsv is GSV_ACTIVE after RUNNING_P2P -> RUNNING");
	else
		fail("fn_gsv is GSV_ACTIVE after RUNNING_P2P -> RUNNING",
		     gsv_str(read_gsv(d)));

	printf("\np2p-fsm stop-copy path (RUNNING_P2P -> STOP -> STOP_COPY):\n");
	mig_expect(d, VFIO_DEVICE_STATE_RUNNING_P2P, 0,
		   "RUNNING -> RUNNING_P2P (prepare)", NULL);
	mig_expect(d, VFIO_DEVICE_STATE_STOP, 0, "RUNNING_P2P -> STOP", NULL);

	if (mig_set_state(d, VFIO_DEVICE_STATE_STOP_COPY, &data_fd)) {
		fail("STOP -> STOP_COPY after P2P prepare", strerror(errno));
		return;
	}
	ok("STOP -> STOP_COPY after P2P prepare");
	if (data_fd < 0) {
		fail("STOP_COPY data fd after P2P", "data_fd is -1");
		return;
	}
	err = mig_image_read(data_fd, &img);
	close(data_fd);
	if (!err && !mig_image_check(&img, "blob after P2P path"))
		ok("read blob after P2P stop-copy path");
	else
		fail("read blob after P2P stop-copy path",
		     err ? strerror(err) : "bad blob");

	mig_expect(d, VFIO_DEVICE_STATE_STOP, 0, "STOP_COPY -> STOP", NULL);
	if (mig_set_state(d, VFIO_DEVICE_STATE_RESUMING, &data_fd)) {
		mig_image_free(&img);
		fail("STOP -> RESUMING after P2P path", strerror(errno));
		return;
	}
	if (data_fd >= 0) {
		write_full(data_fd, img.data, img.len);
		close(data_fd);
	}
	mig_image_free(&img);
	mig_expect(d, VFIO_DEVICE_STATE_STOP, 0,
		   "RESUMING -> STOP after P2P path", NULL);
	mig_expect(d, VFIO_DEVICE_STATE_RUNNING, 0,
		   "STOP -> RUNNING after P2P path", NULL);

	if (save_restore_roundtrip(d) == 0)
		ok("stop-copy roundtrip after P2P FSM");
}

static void test_precopy_fsm(struct dev *d)
{
	struct mig_image img = {};
	struct vfio_precopy_info pinfo = {};
	enum vfio_device_mig_state st;
	char byte;
	int data_fd = -1;
	ssize_t n;
	int err;

	printf("\nprecopy-fsm:\n");
	test_migration_flags(d, true, true);
	ensure_running(d);

	err = mig_set_state(d, VFIO_DEVICE_STATE_PRE_COPY, &data_fd);
	if (err) {
		fail("RUNNING -> PRE_COPY", strerror(err));
		return;
	}
	ok("RUNNING -> PRE_COPY");
	if (data_fd < 0) {
		fail("PRE_COPY data fd", "data_fd is -1");
		return;
	}
	ok("PRE_COPY returned a data fd");

	err = mig_get_state(d, &st);
	if (!err && st == VFIO_DEVICE_STATE_PRE_COPY)
		ok("VFIO state is PRE_COPY");
	else
		fail("VFIO state is PRE_COPY", mig_state_str(st));

	if (read_gsv(d) == SDXI_GSV_ACTIVE)
		ok("fn_gsv is GSV_ACTIVE during PRE_COPY");
	else
		fail("fn_gsv is GSV_ACTIVE during PRE_COPY", gsv_str(read_gsv(d)));

	err = mig_query_precopy_info(data_fd, &pinfo);
	if (err) {
		fail("VFIO_MIG_GET_PRECOPY_INFO in PRE_COPY", strerror(err));
		close(data_fd);
		return;
	}
	ok("VFIO_MIG_GET_PRECOPY_INFO in PRE_COPY");
	if (pinfo.initial_bytes == 0 && pinfo.dirty_bytes == 0)
		ok("precopy info reports empty stream");
	else
		fail("precopy info reports empty stream",
		     "initial/dirty non-zero");

	errno = 0;
	n = read(data_fd, &byte, 1);
	if (n < 0 && errno == ENOMSG)
		ok("precopy read returns ENOMSG at empty stream");
	else
		fail("precopy read returns ENOMSG at empty stream",
		     n < 0 ? strerror(errno) : "unexpected data");

	mig_expect(d, VFIO_DEVICE_STATE_PRE_COPY_P2P, 0,
		   "PRE_COPY -> PRE_COPY_P2P", NULL);
	if (read_gsv(d) == SDXI_GSV_STOP)
		ok("fn_gsv is GSV_STOP in PRE_COPY_P2P");
	else
		fail("fn_gsv is GSV_STOP in PRE_COPY_P2P", gsv_str(read_gsv(d)));

	err = mig_set_state(d, VFIO_DEVICE_STATE_STOP_COPY, NULL);
	if (err) {
		fail("PRE_COPY_P2P -> STOP_COPY", strerror(err));
		close(data_fd);
		return;
	}
	ok("PRE_COPY_P2P -> STOP_COPY");

	err = mig_query_precopy_info(data_fd, &pinfo);
	if (err == EINVAL)
		ok("VFIO_MIG_GET_PRECOPY_INFO rejected after STOP_COPY (uAPI)");
	else if (err)
		fail("VFIO_MIG_GET_PRECOPY_INFO after STOP_COPY",
		     strerror(err));
	else
		fail("VFIO_MIG_GET_PRECOPY_INFO after STOP_COPY",
		     "unexpected success outside PRE_COPY states");

	err = mig_image_read(data_fd, &img);
	close(data_fd);
	if (!err && !mig_image_check(&img, "blob after precopy path"))
		ok("read blob from precopy session fd after STOP_COPY");
	else
		fail("read blob from precopy session fd after STOP_COPY",
		     err ? strerror(err) : "bad blob");

	mig_expect(d, VFIO_DEVICE_STATE_STOP, 0, "STOP_COPY -> STOP", NULL);

	if (mig_set_state(d, VFIO_DEVICE_STATE_RESUMING, &data_fd)) {
		mig_image_free(&img);
		fail("STOP -> RESUMING after precopy path", strerror(errno));
		return;
	}
	if (data_fd >= 0) {
		write_full(data_fd, img.data, img.len);
		close(data_fd);
	}
	mig_image_free(&img);
	mig_expect(d, VFIO_DEVICE_STATE_STOP, 0,
		   "RESUMING -> STOP after precopy path", NULL);
	mig_expect(d, VFIO_DEVICE_STATE_RUNNING, 0,
		   "STOP -> RUNNING after precopy path", NULL);

	if (read_gsv(d) == SDXI_GSV_ACTIVE)
		ok("fn_gsv is GSV_ACTIVE after precopy restore");
	else
		fail("fn_gsv is GSV_ACTIVE after precopy restore",
		     gsv_str(read_gsv(d)));
}

static void test_probe(struct dev *d)
{
	enum sdxi_fn_gsv gsv = read_gsv(d);
	uint64_t buf[4] = {};
	struct vfio_device_feature *feature = (struct vfio_device_feature *)buf;
	struct vfio_device_feature_mig_data_size *sz =
		(struct vfio_device_feature_mig_data_size *)feature->data;
	unsigned long data_size = sizeof(struct sdxi_mig_blob);

	printf("\nprobe (measurement):\n");
	printf("  fn_gsv=%s\n", gsv_str(gsv));
	printf("  cap0=0x%llx cap1=0x%llx ctl0=0x%llx\n",
	       (unsigned long long)read_mmio64(d, SDXI_MMIO_CAP0),
	       (unsigned long long)read_mmio64(d, SDXI_MMIO_CAP1),
	       (unsigned long long)read_mmio64(d, SDXI_MMIO_CTL0));

	feature->argsz = sizeof(*feature) + sizeof(*sz);
	feature->flags = VFIO_DEVICE_FEATURE_GET |
			 VFIO_DEVICE_FEATURE_MIG_DATA_SIZE;
	if (!try_ioctl(d->fd, VFIO_DEVICE_FEATURE, feature))
		data_size = sz->stop_copy_length;
	printf("  blob_size=%lu bytes\n", data_size);
	ok("probe completed");
}

int main(int argc, char **argv)
{
	bool stop_gsv = false, cap_mismatch = false, probe = false;
	bool p2p_flags = false, p2p_fsm = false, precopy_fsm = false;
	const char *pci = NULL;
	struct dev d = {
		.iommufd = -1,
		.fd = -1,
		.state = VFIO_DEVICE_STATE_ERROR,
	};

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--stop-gsv"))
			stop_gsv = true;
		else if (!strcmp(argv[i], "--cap-mismatch"))
			cap_mismatch = true;
		else if (!strcmp(argv[i], "--probe"))
			probe = true;
		else if (!strcmp(argv[i], "--p2p-flags"))
			p2p_flags = true;
		else if (!strcmp(argv[i], "--p2p-fsm"))
			p2p_fsm = true;
		else if (!strcmp(argv[i], "--precopy-fsm"))
			precopy_fsm = true;
		else
			pci = argv[i];
	}
	if (!pci) {
		fprintf(stderr,
			"usage: %s [mode] <pci-bdf>\n"
			"modes: --p2p-flags --p2p-fsm --precopy-fsm "
			"--stop-gsv --cap-mismatch --probe\n",
			argv[0]);
		return 2;
	}

	printf("SDXI VFIO migration harness, device %s\n", pci);
	setup_dev(&d, pci);
	map_bar0(&d);

	if (probe)
		test_probe(&d);
	else if (p2p_flags)
		test_p2p_flags(&d);
	else if (p2p_fsm)
		test_p2p_fsm(&d);
	else if (precopy_fsm)
		test_precopy_fsm(&d);
	else if (stop_gsv)
		test_stop_gsv(&d);
	else if (cap_mismatch)
		test_cap_mismatch(&d);
	else
		test_default_suite(&d);

	teardown_dev(&d);

	if (!probe)
		printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
		       failures, failures == 1 ? "" : "s");
	return failures ? 1 : 0;
}
