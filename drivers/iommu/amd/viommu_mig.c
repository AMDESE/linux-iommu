// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD vIOMMU migration support.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt)     "AMD-Vi: " fmt

#include <linux/align.h>
#include <linux/bitfield.h>
#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/iommufd.h>
#include <linux/ktime.h>
#include <linux/log2.h>
#include <linux/overflow.h>
#include <linux/string.h>

#include "amd_iommu.h"
#include "amd_iommu_types.h"
#include "viommu_mig.h"

/**
 * amd_viommu_mig_section - Reserve a payload section and locate its data
 * @w: Writer to append to
 * @type: One bit of enum iommu_viommu_mig_section
 * @length: Bytes of section data the caller intends to write
 *
 * Return: where the section data belongs, or NULL when the writer is
 * measuring rather than writing, and on error.
 *
 * The two NULL cases are deliberately not distinguished. A caller fills a
 * section only when it is handed a pointer, which is what keeps a measuring
 * pass out of guest memory, and inspects @w->err once at the end instead of
 * after every section. Registers are fair game while measuring: a section
 * whose size depends on one has to read it in both passes.
 */
void *amd_viommu_mig_section(struct amd_viommu_mig_writer *w, u32 type,
			     size_t length)
{
	struct amd_viommu_mig_tlv tlv = { .type = type, .length = length };
	size_t data_offset, end;

	if (w->err)
		return NULL;

	if (WARN_ON_ONCE(length > U32_MAX)) {
		w->err = -EINVAL;
		return NULL;
	}

	data_offset = size_add(w->offset, sizeof(tlv));
	end = size_add(data_offset, ALIGN(length, AMD_VIOMMU_MIG_SECTION_ALIGN));
	if (end == SIZE_MAX) {
		w->err = -EOVERFLOW;
		return NULL;
	}

	w->section_mask |= type;

	if (!w->buf) {
		w->offset = end;
		return NULL;
	}

	if (end > w->capacity) {
		w->err = -ENOSPC;
		return NULL;
	}

	memcpy(w->buf + w->offset, &tlv, sizeof(tlv));

	/*
	 * Zero the data and its trailing padding rather than relying on the
	 * caller having been handed a zeroed buffer, so that a section which
	 * writes only some of its fields cannot leak stack or heap contents.
	 */
	memset(w->buf + data_offset, 0, end - data_offset);
	w->offset = end;

	return w->buf + data_offset;
}

/**
 * amd_viommu_mig_put - Append a section copied from a caller buffer
 * @w: Writer to append to
 * @type: One bit of enum iommu_viommu_mig_section
 * @data: Section contents
 * @length: Bytes at @data
 *
 * Return: 0, or the writer's sticky error.
 */
int amd_viommu_mig_put(struct amd_viommu_mig_writer *w, u32 type,
		       const void *data, size_t length)
{
	void *dst = amd_viommu_mig_section(w, type, length);

	if (dst)
		memcpy(dst, data, length);

	return w->err;
}

/*
 * Guest command ring quiesce.
 *
 * A payload must not be captured while the vIOMMU still owes the guest a write.
 * The write in question is a COMPLETION_WAIT's semaphore store, the only guest
 * command whose side effect lands in guest memory. Miss one and the destination
 * resumes a guest waiting on a store that will never arrive: invalidations by
 * contrast affect only IOMMU caches, which the destination rebuilds anyway.
 *
 * Waiting for head == tail turns out to be enough. Measured on this hardware
 * over 400,000 completion waits, the head pointer never once reached the tail
 * with a store still outstanding, so it does not advance past a wait until that
 * wait's store is visible. Because a ring is consumed in order through a single
 * head pointer, head getting past a later command means it already got past any
 * earlier wait, and therefore that the earlier wait's store landed.
 *
 * The newest entry is nevertheless checked, and fenced if it is a wait. It costs
 * one 16-byte read of a ring that has already gone quiet, and it does not rely
 * on the ordering property above, which is an observation about one
 * implementation rather than anything the architecture promises. Older entries
 * are not examined: reaching them would mean head had already passed them.
 *
 * Watching the store rather than the status register is deliberate. The
 * register's completion-wait bit is a level flag the guest clears itself, so
 * finding it set or clear says nothing about which command set it, and the
 * command processor has no idle bit to poll: the run bit at bit 4 stays set
 * while the ring sits empty, reporting only that the ring is enabled.
 */

/* Poll interval while waiting for the ring to settle */
#define AMD_VIOMMU_MIG_POLL_MIN_US	20
#define AMD_VIOMMU_MIG_POLL_MAX_US	50

/**
 * struct amd_viommu_cmd_ring - Guest command ring as the hardware sees it
 * @base_gpa: Ring base, in the address space the guest posts addresses in
 * @bytes: Ring size
 * @enabled: Whether the guest has the ring turned on
 */
struct amd_viommu_cmd_ring {
	u64 base_gpa;
	u32 bytes;
	bool enabled;
};

static void amd_viommu_mig_get_ring(struct amd_iommu *iommu, u16 gid,
				    struct amd_viommu_cmd_ring *ring)
{
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);
	u64 val;

	val = readq(vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_COMMAND_CONTROL_OFFSET);

	ring->base_gpa = val & VIOMMU_VFCTRL_CMD_BASE;
	ring->bytes = VIOMMU_VFCTRL_LEN_TO_BYTES(FIELD_GET(VIOMMU_VFCTRL_CMD_LEN, val));
	ring->enabled = val & VIOMMU_VFCTRL_CMD_EN;
}

/*
 * Mask rather than FIELD_GET, because these registers hold a byte offset into
 * the ring in bits 18:4 and the rest of this code wants that offset, not the
 * entry index that shifting down would produce.
 */
static void amd_viommu_mig_get_ptrs(struct amd_iommu *iommu, u16 gid,
				    u32 *head, u32 *tail)
{
	u8 __iomem *vf = VIOMMU_VF_MMIO_BASE(iommu, gid);

	*head = readl(vf + VIOMMU_VF_MMIO_OFF(MMIO_CMD_HEAD_OFFSET)) &
		MMIO_CMD_HEAD_MASK;
	*tail = readl(vf + VIOMMU_VF_MMIO_OFF(MMIO_CMD_TAIL_OFFSET)) &
		MMIO_CMD_TAIL_MASK;
}

/**
 * amd_viommu_mig_wait_sem - Wait for a completion wait's store to land
 * @ctx: Guest memory accessor for this operation
 * @gpa: Address the completion wait stores to
 * @expected: Value it stores
 * @deadline: When to give up
 *
 * Return: 0 once the store is visible, -ETIMEDOUT if it never became visible,
 * or an error from reading guest memory.
 */
static int amd_viommu_mig_wait_sem(const struct iommufd_viommu_mig_ctx *ctx,
				   u64 gpa, u64 expected, ktime_t deadline)
{
	for (;;) {
		u64 observed;
		int ret;

		ret = iommufd_viommu_mig_read(ctx, gpa, &observed,
					      sizeof(observed));
		if (ret)
			return ret;

		/*
		 * Compare as a signed difference rather than for equality,
		 * so that a guest which uses the semaphore as a counter and
		 * has already moved past this value still counts as done.
		 *
		 * No comparison is right for every guest, and the two ways
		 * this one can be wrong are not equally bad. A guest that
		 * cycles a flag back to zero after seeing it set reads as not
		 * yet complete, and migration fails on the timeout below. A
		 * guest that stored a value with the top bit set reads as
		 * complete when it may not be. Only the first is safe, which
		 * is why the monotonic reading is the one taken: it is what
		 * Linux does in wait_on_sem(), and a guest that does
		 * something else is refused rather than mismigrated.
		 */
		if ((s64)(observed - expected) >= 0)
			return 0;

		if (ktime_after(ktime_get(), deadline))
			return -ETIMEDOUT;

		usleep_range(AMD_VIOMMU_MIG_POLL_MIN_US,
			     AMD_VIOMMU_MIG_POLL_MAX_US);
	}
}

/*
 * Fence the newest entry in the ring, if it turns out to be a completion wait
 * that stores. @tail addresses the next free slot rather than the last command,
 * so the newest entry sits one slot behind it, wrapping when the tail is at the
 * start of the ring.
 */
static int amd_viommu_mig_wait_newest(const struct iommufd_viommu_mig_ctx *ctx,
				      const struct amd_viommu_cmd_ring *ring,
				      u32 tail, ktime_t deadline)
{
	struct iommu_cmd cmd;
	u64 gpa, data;
	u32 off;
	int ret;

	off = (tail + ring->bytes - sizeof(cmd)) % ring->bytes;

	/* One aligned entry, so this read can never straddle the ring end */
	ret = iommufd_viommu_mig_read(ctx, ring->base_gpa + off, &cmd,
				      sizeof(cmd));
	if (ret)
		return ret;

	if (FIELD_GET(CMD_TYPE_MASK, cmd.data[1]) != CMD_COMPL_WAIT)
		return 0;

	/*
	 * A completion wait that stores nothing signals through the status
	 * register or an interrupt instead, neither of which can be attributed
	 * to a particular command. There is nothing to observe.
	 */
	if (!(cmd.data[0] & CMD_COMPL_WAIT_STORE_MASK))
		return 0;

	/*
	 * The store address is split across the first two words, with the store
	 * and interrupt flags in the low bits it cannot use. See
	 * build_completion_wait().
	 */
	gpa = ((u64)(cmd.data[1] & GENMASK(19, 0)) << 32) |
	      (cmd.data[0] & ~GENMASK_ULL(2, 0));
	data = ((u64)cmd.data[3] << 32) | cmd.data[2];

	return amd_viommu_mig_wait_sem(ctx, gpa, data, deadline);
}

/**
 * amd_viommu_mig_quiesce_cmdbuf - Settle the guest command ring for capture
 * @aviommu: vIOMMU being migrated
 * @ctx: Guest memory accessor for this operation
 * @timeout_ms: Total budget for draining and for the completion fence
 *
 * Return: 0 once no guest command is outstanding, -ETIMEDOUT if the ring did
 * not settle in time, or an error from reading guest memory.
 *
 * Expects the guest to be stopped already: the caller runs this once the vCPUs
 * are paused and the endpoint has reached VFIO STOP, so nothing can add to the
 * ring while it is being drained. Draining a live guest would be pointless,
 * since it could post another command the moment head met tail.
 *
 * Sleeps, and may do so for the whole budget. Runs under the vIOMMU's
 * mig_lock, which is why that lock is a mutex.
 */
int amd_viommu_mig_quiesce_cmdbuf(struct amd_iommu_viommu *aviommu,
				  const struct iommufd_viommu_mig_ctx *ctx,
				  unsigned int timeout_ms)
{
	struct amd_iommu *iommu =
		container_of(aviommu->core.iommu_dev, struct amd_iommu, iommu);
	ktime_t deadline = ktime_add_ms(ktime_get(), timeout_ms);
	struct amd_viommu_cmd_ring ring;
	u32 head, tail;

	lockdep_assert_held(&aviommu->core.mig_lock);
	might_sleep();

	amd_viommu_mig_get_ring(iommu, aviommu->gid, &ring);

	/*
	 * With the ring off the guest cannot have commands outstanding on it.
	 * It also leaves nowhere to look for a completion wait, so a guest
	 * that turned the ring off without waiting for its last command gets
	 * no fence; it had already given up ordering.
	 */
	if (!ring.enabled)
		return 0;

	for (;;) {
		amd_viommu_mig_get_ptrs(iommu, aviommu->gid, &head, &tail);
		if (head == tail)
			break;

		if (ktime_after(ktime_get(), deadline)) {
			pr_warn("%s: gid=%#x ring did not drain, head=%#x tail=%#x\n",
				__func__, aviommu->gid, head, tail);
			return -ETIMEDOUT;
		}

		usleep_range(AMD_VIOMMU_MIG_POLL_MIN_US,
			     AMD_VIOMMU_MIG_POLL_MAX_US);
	}

	/*
	 * Both come from hardware, so disagreeing with each other means the
	 * ring is not in a state worth capturing. Refuse rather than compute
	 * an address from it.
	 */
	if (tail >= ring.bytes || !IS_ALIGNED(tail, sizeof(struct iommu_cmd))) {
		pr_warn("%s: gid=%#x bad tail %#x for %#x byte ring\n",
			__func__, aviommu->gid, tail, ring.bytes);
		return -EIO;
	}

	return amd_viommu_mig_wait_newest(ctx, &ring, tail, deadline);
}

/*
 * Log generation freeze.
 *
 * Stopping the endpoint does not stop the IOMMU. It writes the EventLog and
 * PPRLog rings itself, and the host can append to a guest's event log with
 * CMD_INSERT_GUEST_EVENT independently of both the guest and the endpoint. An
 * entry landing between the point where the ring pointers are recorded and the
 * point where the ring contents are copied would produce a payload whose
 * pointers and contents disagree, so generation is turned off for the duration.
 *
 * Entries the guest would have received during the frozen window are dropped
 * rather than queued. That is why the overflow status is recorded here: it is
 * the only evidence that anything was lost.
 */
static void amd_viommu_mig_freeze_logs(struct amd_iommu_viommu *aviommu)
{
	struct amd_iommu *iommu =
		container_of(aviommu->core.iommu_dev, struct amd_iommu, iommu);
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, aviommu->gid);
	u64 evt, ppr;

	lockdep_assert_held(&aviommu->core.mig_lock);

	spin_lock(&aviommu->vfctrl_lock);

	evt = readq(vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_EVENT_CONTROL_OFFSET);
	writeq(evt & ~VIOMMU_VFCTRL_EVT_GEN_EN,
	       vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_EVENT_CONTROL_OFFSET);

	ppr = readq(vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_PPR_CONTROL_OFFSET);
	writeq(ppr & ~VIOMMU_VFCTRL_PPR_GEN_EN,
	       vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_PPR_CONTROL_OFFSET);

	spin_unlock(&aviommu->vfctrl_lock);

	aviommu->mig.evt_ctrl = evt;
	aviommu->mig.ppr_ctrl = ppr;
	aviommu->mig.logs_frozen = true;
}

/*
 * Put back only the generation bits the freeze cleared, rather than writing the
 * whole saved register, so that anything else which changed meanwhile survives.
 */
static void amd_viommu_mig_thaw_logs(struct amd_iommu_viommu *aviommu)
{
	struct amd_iommu *iommu =
		container_of(aviommu->core.iommu_dev, struct amd_iommu, iommu);
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, aviommu->gid);
	u64 val;

	lockdep_assert_held(&aviommu->core.mig_lock);

	if (!aviommu->mig.logs_frozen)
		return;

	spin_lock(&aviommu->vfctrl_lock);

	val = readq(vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_EVENT_CONTROL_OFFSET);
	val |= aviommu->mig.evt_ctrl & VIOMMU_VFCTRL_EVT_GEN_EN;
	writeq(val, vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_EVENT_CONTROL_OFFSET);

	val = readq(vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_PPR_CONTROL_OFFSET);
	val |= aviommu->mig.ppr_ctrl & VIOMMU_VFCTRL_PPR_GEN_EN;
	writeq(val, vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_PPR_CONTROL_OFFSET);

	spin_unlock(&aviommu->vfctrl_lock);

	aviommu->mig.logs_frozen = false;
}

/*
 * Record the guest status register once nothing is generating entries any more.
 * An overflow bit here means the guest lost log entries, which is worth
 * reporting but is not a reason to refuse the migration: the entries are
 * already gone, and refusing would not bring them back.
 *
 * What is recorded travels as a report and nothing else. The sticky bits are
 * write-one-to-clear, so no destination can be handed a pending overflow
 * whatever this reads, which is also why it does not matter here whether a bit
 * describes the guest's own history or the freeze that has just started.
 */
static void amd_viommu_mig_read_status(struct amd_iommu_viommu *aviommu)
{
	struct amd_iommu *iommu =
		container_of(aviommu->core.iommu_dev, struct amd_iommu, iommu);
	u8 __iomem *vf = VIOMMU_VF_MMIO_BASE(iommu, aviommu->gid);
	u64 status;

	status = readq(vf + VIOMMU_VF_MMIO_OFF(MMIO_STATUS_OFFSET));
	aviommu->mig.status = status;

	/*
	 * Only the two logs the freeze covers. The GA log has an overflow bit
	 * of its own, but nothing here disables it, so reporting it would say
	 * something about the guest rather than about this migration.
	 */
	if (status & (MMIO_STATUS_EVT_OVERFLOW_MASK |
		      MMIO_STATUS_PPR_OVERFLOW_MASK))
		pr_warn("%s: gid=%#x log overflow before save, status=%#llx\n",
			__func__, aviommu->gid, status);
}

/**
 * amd_viommu_mig_prepare_save - Quiesce a vIOMMU so its state stops changing
 * @viommu: vIOMMU being migrated
 * @ctx: Guest memory accessor for this operation
 * @timeout_ms: How long the guest command ring may take to settle
 * @out_status: Operation detail for userspace
 *
 * Return: 0 with the vIOMMU quiesced, or an error leaving nothing applied.
 *
 * Settle the command ring before freezing the logs, not after, so that a ring
 * which never settles leaves the guest exactly as it was. Command execution can
 * itself generate log entries, and those belong to the guest's history, so they
 * must be allowed to land before generation stops.
 */
int amd_viommu_mig_prepare_save(struct iommufd_viommu *viommu,
				const struct iommufd_viommu_mig_ctx *ctx,
				u32 timeout_ms, u32 *out_status)
{
	struct amd_iommu_viommu *aviommu =
		container_of(viommu, struct amd_iommu_viommu, core);
	int ret;

	ret = amd_viommu_mig_quiesce_cmdbuf(aviommu, ctx, timeout_ms);
	if (ret)
		return ret;

	amd_viommu_mig_freeze_logs(aviommu);
	amd_viommu_mig_read_status(aviommu);

	/*
	 * Left at zero deliberately. The bits of out_status are a userspace
	 * interface and nothing consumes them yet, so assigning meanings here
	 * would fix an ABI ahead of the code that needs it.
	 */
	*out_status = 0;

	return 0;
}

/**
 * amd_viommu_mig_abort - Abandon a migration and undo what it applied
 * @viommu: vIOMMU to release
 *
 * Also runs when an earlier step failed partway, so it undoes only what was
 * actually applied and must work from any point in the sequence.
 */
void amd_viommu_mig_abort(struct iommufd_viommu *viommu)
{
	struct amd_iommu_viommu *aviommu =
		container_of(viommu, struct amd_iommu_viommu, core);

	amd_viommu_mig_thaw_logs(aviommu);
	memset(aviommu->mig.rings, 0, sizeof(aviommu->mig.rings));
	aviommu->mig.status = 0;
}

/*
 * Guest ring capture.
 *
 * The three rings are described entirely by registers: base, size and enables
 * live in the vIOMMU's VFCTRL block, and the pointers live in the page of IOMMU
 * registers the guest sees. Nothing here consults the iommufd hardware queue
 * objects, which are not tracked per vIOMMU and would need a lifetime of their
 * own to reach safely, and which hold no state the registers do not.
 *
 * A consequence worth naming: a ring whose object exists but which the guest
 * has since turned off is indistinguishable from one that was never programmed.
 * Both restore to a disabled ring, which is what the guest asked for either way.
 */

/*
 * Head and tail hold a byte offset into the ring in bits 18:4, in all six of
 * these registers, so one mask serves them all. The low four bits being absent
 * is what makes an entry 16 bytes: a pointer cannot address anything finer.
 */
#define AMD_VIOMMU_MIG_RING_PTR_MASK	GENMASK(18, 4)
#define AMD_VIOMMU_MIG_RING_ENTRY_BYTES	16

/**
 * struct amd_viommu_mig_reg_flag - One enable bit's two spellings
 * @reg: The bit as it appears in the VFCTRL control register
 * @queue: The same bit in enum iommu_hw_queue_flags_amd
 */
struct amd_viommu_mig_reg_flag {
	u64 reg;
	u32 queue;
};

static const struct amd_viommu_mig_reg_flag amd_viommu_mig_cmd_flags[] = {
	{ VIOMMU_VFCTRL_CMD_EN, IOMMU_HW_QUEUE_FLAG_AMD_CMDBUF_EN },
	{ VIOMMU_VFCTRL_CMD_COMWAIT_EN, IOMMU_HW_QUEUE_FLAG_AMD_COMWAIT_EN },
};

static const struct amd_viommu_mig_reg_flag amd_viommu_mig_evt_flags[] = {
	{ VIOMMU_VFCTRL_EVT_LOG_EN, IOMMU_HW_QUEUE_FLAG_AMD_EVT_LOG_EN },
	{ VIOMMU_VFCTRL_EVT_INT_EN, IOMMU_HW_QUEUE_FLAG_AMD_EVT_INT_EN },
};

static const struct amd_viommu_mig_reg_flag amd_viommu_mig_ppr_flags[] = {
	{ VIOMMU_VFCTRL_PPRLOG_EN, IOMMU_HW_QUEUE_FLAG_AMD_PPRLOG_EN },
	{ VIOMMU_VFCTRL_PPRINT_EN, IOMMU_HW_QUEUE_FLAG_AMD_PPRINT_EN },
	{ VIOMMU_VFCTRL_PPR_EN, IOMMU_HW_QUEUE_FLAG_AMD_PPR_EN },
	{ VIOMMU_VFCTRL_PPR_AUTO_RSP_EN, IOMMU_HW_QUEUE_FLAG_AMD_PPR_AUTO_RSP_EN },
	{ VIOMMU_VFCTRL_PPR_BLKSTOPMRK_EN, IOMMU_HW_QUEUE_FLAG_AMD_BLKSTOPMRK_EN },
	{ VIOMMU_VFCTRL_PPR_AUTO_RSP_AON, IOMMU_HW_QUEUE_FLAG_AMD_PPR_AUTO_RSP_AON },
};

/**
 * struct amd_viommu_mig_ring_desc - Where one ring keeps its state
 * @type: enum iommu_hw_queue_type value for this ring
 * @ctrl_off: Control register, within the vIOMMU's VFCTRL block
 * @head_off: Head pointer, within the guest's register page
 * @tail_off: Tail pointer, within the guest's register page
 * @len_mask: Size field of the control register
 * @base_mask: Base address field of the control register
 * @flags: Enable bits this ring has
 * @nr_flags: Entries in @flags
 */
struct amd_viommu_mig_ring_desc {
	u32 type;
	unsigned int ctrl_off;
	unsigned int head_off;
	unsigned int tail_off;
	u64 len_mask;
	u64 base_mask;
	const struct amd_viommu_mig_reg_flag *flags;
	unsigned int nr_flags;
};

/*
 * The payload carries one record per ring and the vIOMMU keeps one arming
 * record per ring, so the two counts have to agree or an index into one would
 * not index the other.
 */
static_assert(AMD_VIOMMU_MIG_HW_QUEUES == AMD_VIOMMU_GUEST_RINGS);

/* Indices into the table below, so that a caller need not count entries */
enum amd_viommu_mig_ring {
	AMD_VIOMMU_MIG_RING_CMD,
	AMD_VIOMMU_MIG_RING_EVT,
	AMD_VIOMMU_MIG_RING_PPR,
};

static const struct amd_viommu_mig_ring_desc
amd_viommu_mig_rings[AMD_VIOMMU_MIG_HW_QUEUES] = {
	[AMD_VIOMMU_MIG_RING_CMD] = {
		.type = IOMMU_HW_QUEUE_TYPE_AMD_CMD,
		.ctrl_off = VIOMMU_VFCTRL_MMIO_GUEST_COMMAND_CONTROL_OFFSET,
		.head_off = VIOMMU_VF_MMIO_OFF(MMIO_CMD_HEAD_OFFSET),
		.tail_off = VIOMMU_VF_MMIO_OFF(MMIO_CMD_TAIL_OFFSET),
		.len_mask = VIOMMU_VFCTRL_CMD_LEN,
		.base_mask = VIOMMU_VFCTRL_CMD_BASE,
		.flags = amd_viommu_mig_cmd_flags,
		.nr_flags = ARRAY_SIZE(amd_viommu_mig_cmd_flags),
	},
	[AMD_VIOMMU_MIG_RING_EVT] = {
		.type = IOMMU_HW_QUEUE_TYPE_AMD_EVT,
		.ctrl_off = VIOMMU_VFCTRL_MMIO_GUEST_EVENT_CONTROL_OFFSET,
		.head_off = VIOMMU_VF_MMIO_OFF(MMIO_EVT_HEAD_OFFSET),
		.tail_off = VIOMMU_VF_MMIO_OFF(MMIO_EVT_TAIL_OFFSET),
		.len_mask = VIOMMU_VFCTRL_EVT_LEN,
		.base_mask = VIOMMU_VFCTRL_EVT_BASE,
		.flags = amd_viommu_mig_evt_flags,
		.nr_flags = ARRAY_SIZE(amd_viommu_mig_evt_flags),
	},
	[AMD_VIOMMU_MIG_RING_PPR] = {
		.type = IOMMU_HW_QUEUE_TYPE_AMD_PPR,
		.ctrl_off = VIOMMU_VFCTRL_MMIO_GUEST_PPR_CONTROL_OFFSET,
		.head_off = VIOMMU_VF_MMIO_OFF(MMIO_PPR_HEAD_OFFSET),
		.tail_off = VIOMMU_VF_MMIO_OFF(MMIO_PPR_TAIL_OFFSET),
		.len_mask = VIOMMU_VFCTRL_PPR_LEN,
		.base_mask = VIOMMU_VFCTRL_PPR_BASE,
		.flags = amd_viommu_mig_ppr_flags,
		.nr_flags = ARRAY_SIZE(amd_viommu_mig_ppr_flags),
	},
};

/*
 * The control register as the guest last programmed it.
 *
 * PREPARE_SAVE clears the event and PPR generation bits, so once the logs are
 * frozen a live read of those two registers describes the freeze rather than the
 * guest. The value captured before the freeze is the one to migrate, or else the
 * destination would come up with the guest's logging silently turned off.
 */
static u64 amd_viommu_mig_ring_ctrl(struct amd_iommu_viommu *aviommu,
				    const struct amd_viommu_mig_ring_desc *desc,
				    u8 __iomem *vfctrl)
{
	if (aviommu->mig.logs_frozen) {
		if (desc->type == IOMMU_HW_QUEUE_TYPE_AMD_EVT)
			return aviommu->mig.evt_ctrl;
		if (desc->type == IOMMU_HW_QUEUE_TYPE_AMD_PPR)
			return aviommu->mig.ppr_ctrl;
	}

	return readq(vfctrl + desc->ctrl_off);
}

static void amd_viommu_mig_read_ring(struct amd_iommu_viommu *aviommu,
				     const struct amd_viommu_mig_ring_desc *desc,
				     struct amd_viommu_mig_hw_queue *rec)
{
	struct amd_iommu *iommu =
		container_of(aviommu->core.iommu_dev, struct amd_iommu, iommu);
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, aviommu->gid);
	u8 __iomem *vf = VIOMMU_VF_MMIO_BASE(iommu, aviommu->gid);
	unsigned int i;
	u64 ctrl;

	ctrl = amd_viommu_mig_ring_ctrl(aviommu, desc, vfctrl);

	rec->type = desc->type;

	/*
	 * An all-zero control register means the ring was never set up: a guest
	 * that programmed one set either a base, a size or an enable. Leave the
	 * rest of the record zeroed rather than reporting the 16-byte ring a
	 * zero size field decodes to, or whatever the pointer registers happen
	 * to have kept from an earlier life.
	 */
	if (!ctrl)
		return;

	rec->record_flags |= AMD_VIOMMU_MIG_HW_QUEUE_PROGRAMMED;
	rec->size_encoded = field_get(desc->len_mask, ctrl);
	rec->length_bytes = VIOMMU_VFCTRL_LEN_TO_BYTES(rec->size_encoded);

	/*
	 * Extract then shift, rather than masking in place, because the base is
	 * not held at the same bit position in all three registers even though
	 * it means the same thing in each. field_get() rather than FIELD_GET()
	 * because the mask comes from the table above, not from a literal.
	 */
	rec->base_gpa = (u64)field_get(desc->base_mask, ctrl) << PAGE_SHIFT;

	for (i = 0; i < desc->nr_flags; i++)
		if (ctrl & desc->flags[i].reg)
			rec->queue_flags |= desc->flags[i].queue;

	rec->head = readl(vf + desc->head_off) & AMD_VIOMMU_MIG_RING_PTR_MASK;
	rec->tail = readl(vf + desc->tail_off) & AMD_VIOMMU_MIG_RING_PTR_MASK;
}

static void amd_viommu_mig_save_hw_queues(struct amd_iommu_viommu *aviommu,
					  struct amd_viommu_mig_writer *w)
{
	struct amd_viommu_mig_hw_queue_section *sec;
	unsigned int i;

	sec = amd_viommu_mig_section(w, IOMMU_VIOMMU_MIG_SECTION_HW_QUEUE,
				     struct_size(sec, recs,
						 AMD_VIOMMU_MIG_HW_QUEUES));
	if (!sec)
		return;

	sec->record_size = sizeof(*sec->recs);
	sec->nr_records = AMD_VIOMMU_MIG_HW_QUEUES;

	for (i = 0; i < AMD_VIOMMU_MIG_HW_QUEUES; i++)
		amd_viommu_mig_read_ring(aviommu, &amd_viommu_mig_rings[i],
					 &sec->recs[i]);
}

static void amd_viommu_mig_save_status(struct amd_iommu_viommu *aviommu,
				       struct amd_viommu_mig_writer *w)
{
	struct amd_viommu_mig_status *st;

	st = amd_viommu_mig_section(w, IOMMU_VIOMMU_MIG_SECTION_STATUS,
				    sizeof(*st));
	if (!st)
		return;

	/* Captured by PREPARE_SAVE, once nothing was generating entries */
	st->raw = aviommu->mig.status;
	st->sticky = aviommu->mig.status & MMIO_STATUS_STICKY_MASK;
}

/*
 * Copy one log ring's contents, or account for them when measuring. @hdr_bytes
 * receives what to report in the header, and is NULL while measuring because
 * there is no header to fill in yet.
 */
static void amd_viommu_mig_save_log(struct amd_iommu_viommu *aviommu,
				    const struct iommufd_viommu_mig_ctx *ctx,
				    struct amd_viommu_mig_writer *w,
				    const struct amd_viommu_mig_ring_desc *desc,
				    u32 section, u32 *hdr_bytes)
{
	struct amd_iommu *iommu =
		container_of(aviommu->core.iommu_dev, struct amd_iommu, iommu);
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, aviommu->gid);
	struct amd_viommu_mig_log_section *sec;
	u32 ring_bytes;
	u64 ctrl, base;
	int ret;

	ctrl = amd_viommu_mig_ring_ctrl(aviommu, desc, vfctrl);

	/* A ring the guest never programmed has no contents to carry */
	if (!ctrl)
		return;

	ring_bytes = VIOMMU_VFCTRL_LEN_TO_BYTES(field_get(desc->len_mask, ctrl));
	base = (u64)field_get(desc->base_mask, ctrl) << PAGE_SHIFT;

	sec = amd_viommu_mig_section(w, section,
				     struct_size(sec, segs, 1) + ring_bytes);
	if (hdr_bytes)
		*hdr_bytes = ring_bytes;
	if (!sec)
		return;

	sec->ring_bytes = ring_bytes;
	sec->nr_segments = 1;
	sec->segs[0].offset = 0;
	sec->segs[0].length = ring_bytes;

	/*
	 * Guest memory, so this can fail on a ring the guest pointed somewhere
	 * unmapped. Report that rather than shipping a section whose descriptors
	 * promise bytes the payload does not contain.
	 */
	ret = iommufd_viommu_mig_read(ctx, base, &sec->segs[sec->nr_segments],
				      ring_bytes);
	if (ret)
		w->err = ret;
}

/*
 * Build a payload, or measure one when @w has no buffer. Both go through here so
 * that a size query and a save cannot disagree about how large a payload is,
 * which would leave a caller sizing its buffer from one and being told by the
 * other that it is too small.
 *
 * @ctx and @hdr are NULL while measuring. Neither is reached in that case: every
 * section that needs them does so only after being handed a buffer to fill.
 */
static void amd_viommu_mig_build(struct amd_iommu_viommu *aviommu,
				 const struct iommufd_viommu_mig_ctx *ctx,
				 struct amd_viommu_mig_writer *w,
				 struct iommu_viommu_mig_header *hdr)
{
	amd_viommu_mig_save_hw_queues(aviommu, w);
	amd_viommu_mig_save_status(aviommu, w);
	amd_viommu_mig_save_log(aviommu, ctx, w,
				&amd_viommu_mig_rings[AMD_VIOMMU_MIG_RING_EVT],
				IOMMU_VIOMMU_MIG_SECTION_EVTLOG,
				hdr ? &hdr->evtlog_bytes : NULL);
	amd_viommu_mig_save_log(aviommu, ctx, w,
				&amd_viommu_mig_rings[AMD_VIOMMU_MIG_RING_PPR],
				IOMMU_VIOMMU_MIG_SECTION_PPRLOG,
				hdr ? &hdr->pprlog_bytes : NULL);
}

/**
 * amd_viommu_mig_get_size - Report the payload size for this vIOMMU
 * @viommu: vIOMMU to size
 * @out_size: Bytes of payload needed
 *
 * Return: 0, or an error if the sections could not be accounted for.
 *
 * Callable in any migration state, so this reads registers but never guest
 * memory, and must not depend on the vIOMMU having been quiesced. The answer is
 * exact for the ring sizes in force when it is asked: a guest that reprograms a
 * log ring afterwards makes the payload a different size, which SAVE reports as
 * -EMSGSIZE with the figure to retry with rather than silently truncating.
 */
int amd_viommu_mig_get_size(struct iommufd_viommu *viommu, size_t *out_size)
{
	struct amd_iommu_viommu *aviommu =
		container_of(viommu, struct amd_iommu_viommu, core);
	struct amd_viommu_mig_writer w;

	amd_viommu_mig_writer_init(&w, NULL, 0);
	amd_viommu_mig_build(aviommu, NULL, &w, NULL);
	if (w.err)
		return w.err;

	*out_size = w.offset;

	return 0;
}

/**
 * amd_viommu_mig_save - Capture a quiesced vIOMMU into @payload
 * @viommu: vIOMMU to capture
 * @ctx: Guest memory accessor for this operation
 * @hdr: Header to describe the payload in
 * @payload: Where to build the payload
 * @payload_len: Bytes available at @payload
 *
 * Return: 0 with @hdr and @payload filled in, or an error having written
 * nothing the caller will use.
 */
int amd_viommu_mig_save(struct iommufd_viommu *viommu,
			const struct iommufd_viommu_mig_ctx *ctx,
			struct iommu_viommu_mig_header *hdr, void *payload,
			size_t payload_len)
{
	struct amd_iommu_viommu *aviommu =
		container_of(viommu, struct amd_iommu_viommu, core);
	struct amd_iommu *iommu =
		container_of(viommu->iommu_dev, struct amd_iommu, iommu);
	struct amd_viommu_cmd_ring cmd_ring;
	struct amd_viommu_mig_writer w;

	lockdep_assert_held(&viommu->mig_lock);

	amd_viommu_mig_writer_init(&w, payload, payload_len);

	/* Fills in the log byte counts as it emits their sections */
	amd_viommu_mig_build(aviommu, ctx, &w, hdr);
	if (w.err)
		return w.err;

	hdr->blob_format_version = AMD_VIOMMU_MIG_FORMAT_VERSION;
	hdr->min_reader_version = AMD_VIOMMU_MIG_MIN_READER_VERSION;
	hdr->section_mask = w.section_mask;
	hdr->payload_size = w.offset;

	/*
	 * Diagnostics only. A destination allocates its own guest ID and must
	 * never program this one.
	 */
	hdr->source_gid = aviommu->gid;

	/*
	 * The command ring's extent, so that a destination can sanity-check the
	 * ring it is asked to allocate before parsing the payload. Its contents
	 * are guest memory and travel as guest RAM.
	 */
	amd_viommu_mig_get_ring(iommu, aviommu->gid, &cmd_ring);
	hdr->cmdbuf_bytes = cmd_ring.enabled ? cmd_ring.bytes : 0;

	return 0;
}

/*
 * Payload consumption.
 *
 * Everything below reads a buffer userspace supplied, so nothing in it may be
 * believed: a length, a record count and an offset are all attacker-controlled
 * until checked against the payload that carries them and the ring they claim
 * to describe.
 */

static const struct amd_viommu_mig_ring_desc *
amd_viommu_mig_desc_for(u32 type)
{
	unsigned int i;

	for (i = 0; i < AMD_VIOMMU_MIG_HW_QUEUES; i++)
		if (amd_viommu_mig_rings[i].type == type)
			return &amd_viommu_mig_rings[i];

	return NULL;
}

/* The ring as the destination's registers have it, whatever the payload says */
static u64 amd_viommu_mig_live_ctrl(struct amd_iommu_viommu *aviommu,
				    const struct amd_viommu_mig_ring_desc *desc)
{
	struct amd_iommu *iommu =
		container_of(aviommu->core.iommu_dev, struct amd_iommu, iommu);
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, aviommu->gid);

	return readq(vfctrl + desc->ctrl_off);
}

/*
 * Put back one ring's pointers, having checked that the ring userspace
 * allocated here is the ring the payload describes.
 *
 * Only head and tail are restored. The enables are deliberately left alone:
 * userspace allocates with them masked off so that a ring is never armed
 * against a stale pointer, and arming is COMMIT_RESTORE's job once every ring
 * has been checked. What it needs to do that is recorded here.
 */
static int amd_viommu_mig_restore_ring(struct amd_iommu_viommu *aviommu,
				       const struct amd_viommu_mig_ring_desc *desc,
				       const struct amd_viommu_mig_hw_queue *rec,
				       struct amd_viommu_ring_arm *arm)
{
	struct amd_iommu *iommu =
		container_of(aviommu->core.iommu_dev, struct amd_iommu, iommu);
	u8 __iomem *vf = VIOMMU_VF_MMIO_BASE(iommu, aviommu->gid);
	u32 bytes;
	u64 ctrl;

	ctrl = amd_viommu_mig_live_ctrl(aviommu, desc);

	/*
	 * A ring that was not programmed on the source must not be programmed
	 * here either, and one that was has to have been allocated before the
	 * restore. Either mismatch means the payload and the objects userspace
	 * built disagree about what this vIOMMU is.
	 */
	if (!(rec->record_flags & AMD_VIOMMU_MIG_HW_QUEUE_PROGRAMMED))
		return ctrl ? -EINVAL : 0;
	if (!ctrl)
		return -EINVAL;

	if (field_get(desc->len_mask, ctrl) != rec->size_encoded)
		return -EINVAL;
	if ((u64)field_get(desc->base_mask, ctrl) << PAGE_SHIFT !=
	    rec->base_gpa)
		return -EINVAL;

	/*
	 * Pointers are byte offsets into the ring and index whole entries, so a
	 * value past the end or inside an entry would leave hardware walking
	 * from somewhere that is not the start of a command.
	 */
	bytes = VIOMMU_VFCTRL_LEN_TO_BYTES(rec->size_encoded);
	if (rec->head >= bytes || rec->tail >= bytes)
		return -EINVAL;
	if (!IS_ALIGNED(rec->head, AMD_VIOMMU_MIG_RING_ENTRY_BYTES) ||
	    !IS_ALIGNED(rec->tail, AMD_VIOMMU_MIG_RING_ENTRY_BYTES))
		return -EINVAL;

	writel(rec->head, vf + desc->head_off);
	writel(rec->tail, vf + desc->tail_off);

	*arm = (struct amd_viommu_ring_arm){
		.base_gpa = rec->base_gpa,
		.size_encoded = rec->size_encoded,
		.queue_flags = rec->queue_flags,
		.programmed = true,
	};

	return 0;
}

static int amd_viommu_mig_restore_hw_queues(struct amd_iommu_viommu *aviommu,
					    const void *data, u32 length)
{
	const struct amd_viommu_mig_hw_queue_section *sec = data;
	u32 seen = 0;
	size_t need;
	u32 i;

	if (length < sizeof(*sec))
		return -EINVAL;

	/*
	 * Accept a record larger than this build's, and stride by what the
	 * source used: a later format may append fields without changing what
	 * the ones here mean, which is the case min_reader_version admits.
	 */
	if (sec->record_size < sizeof(*sec->recs))
		return -EINVAL;
	if (sec->nr_records > AMD_VIOMMU_MIG_HW_QUEUES)
		return -EINVAL;

	need = size_mul(sec->record_size, sec->nr_records);
	if (need > length - sizeof(*sec))
		return -EINVAL;

	for (i = 0; i < sec->nr_records; i++) {
		const struct amd_viommu_mig_hw_queue *rec =
			(const void *)sec->recs + (size_t)i * sec->record_size;
		const struct amd_viommu_mig_ring_desc *desc;
		unsigned int idx;
		int ret;

		desc = amd_viommu_mig_desc_for(rec->type);
		if (!desc)
			return -EINVAL;
		idx = desc - amd_viommu_mig_rings;

		/*
		 * One record per ring. Two describing the same ring would both
		 * be applied, leaving the ring in the state of whichever came
		 * last, so the payload would not say what it restores to.
		 */
		if (seen & BIT(idx))
			return -EINVAL;
		seen |= BIT(idx);

		ret = amd_viommu_mig_restore_ring(aviommu, desc, rec,
						  &aviommu->mig.rings[idx]);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Write one log ring's contents back into guest memory.
 *
 * This is why RESTORE has to run after guest RAM is in place and the nesting
 * parent is mapped: the bytes go to the guest pages the ring points at, not
 * into anything the kernel owns.
 */
static int amd_viommu_mig_restore_log(struct amd_iommu_viommu *aviommu,
				      const struct iommufd_viommu_mig_ctx *ctx,
				      const struct amd_viommu_mig_ring_desc *desc,
				      const void *data, u32 length)
{
	const struct amd_viommu_mig_log_section *sec = data;
	const u8 *bytes;
	size_t hdr_len;
	u32 ring_bytes, avail, i;
	u64 base, ctrl;

	if (length < sizeof(*sec))
		return -EINVAL;

	ctrl = amd_viommu_mig_live_ctrl(aviommu, desc);
	if (!ctrl)
		return -EINVAL;

	ring_bytes = VIOMMU_VFCTRL_LEN_TO_BYTES(field_get(desc->len_mask, ctrl));
	base = (u64)field_get(desc->base_mask, ctrl) << PAGE_SHIFT;

	/*
	 * The contents were laid out for a ring of the source's size. Copying
	 * them into a different one would put entries at offsets that no longer
	 * mean what they meant.
	 */
	if (sec->ring_bytes != ring_bytes)
		return -EINVAL;

	if (sec->nr_segments > ring_bytes / AMD_VIOMMU_MIG_RING_ENTRY_BYTES)
		return -EINVAL;

	hdr_len = struct_size(sec, segs, sec->nr_segments);
	if (hdr_len > length)
		return -EINVAL;

	bytes = (const u8 *)data + hdr_len;
	avail = length - hdr_len;

	for (i = 0; i < sec->nr_segments; i++) {
		const struct amd_viommu_mig_log_segment *seg = &sec->segs[i];
		int ret;

		/* The bytes must be in the payload and belong in the ring */
		if (seg->length > avail)
			return -EINVAL;
		if (seg->offset > ring_bytes ||
		    seg->length > ring_bytes - seg->offset)
			return -EINVAL;

		ret = iommufd_viommu_mig_write(ctx, base + seg->offset,
					       (void *)bytes, seg->length);
		if (ret)
			return ret;

		bytes += seg->length;
		avail -= seg->length;
	}

	return 0;
}

/*
 * The status bits cannot be put back. They are write-one-to-clear, so a write
 * of a set bit clears it and a write of a clear bit does nothing; there is no
 * way to hand the destination a pending overflow. Report one rather than
 * discarding it silently, because it is the only trace that the guest lost log
 * entries and the guest has no other way to find out.
 */
static void amd_viommu_mig_restore_status(struct amd_iommu_viommu *aviommu,
					  const void *data, u32 length)
{
	const struct amd_viommu_mig_status *st = data;

	if (length < sizeof(*st))
		return;

	if (st->sticky & (MMIO_STATUS_EVT_OVERFLOW_MASK |
			  MMIO_STATUS_PPR_OVERFLOW_MASK))
		pr_warn("%s: gid=%#x source had a log overflow pending, sticky=%#llx; it cannot be reinstated here\n",
			__func__, aviommu->gid, st->sticky);
}

/**
 * amd_viommu_mig_restore - Put a saved payload back onto this vIOMMU
 * @viommu: vIOMMU to restore onto
 * @ctx: Guest memory accessor, valid for this call only
 * @hdr: Header saved alongside @payload
 * @payload: Payload bytes as saved
 * @payload_len: Bytes in @payload
 *
 * Return: 0 with the rings pointed where the source had them, or an error
 * having armed nothing.
 *
 * Runs after userspace has allocated the rings with their enables masked off,
 * and after guest RAM is in place, since the log contents are written back into
 * it. Leaves every ring disabled: COMMIT_RESTORE arms them once the whole
 * payload has been accepted.
 */
int amd_viommu_mig_restore(struct iommufd_viommu *viommu,
			   const struct iommufd_viommu_mig_ctx *ctx,
			   const struct iommu_viommu_mig_header *hdr,
			   const void *payload, size_t payload_len)
{
	struct amd_iommu_viommu *aviommu =
		container_of(viommu, struct amd_iommu_viommu, core);
	u64 seen = 0;
	size_t off = 0;

	lockdep_assert_held(&viommu->mig_lock);

	/*
	 * The source states the oldest reader its payload makes sense to. A
	 * newer one means fields this build would skip are load-bearing, so
	 * restoring the parts it does understand would build a half-configured
	 * vIOMMU rather than fail.
	 */
	if (hdr->min_reader_version > AMD_VIOMMU_MIG_FORMAT_VERSION)
		return -EOPNOTSUPP;

	/*
	 * Nothing is armed for a ring this payload turns out not to describe,
	 * so start from a clean slate rather than from whatever an earlier
	 * attempt on this vIOMMU left behind.
	 */
	memset(aviommu->mig.rings, 0, sizeof(aviommu->mig.rings));

	while (off < payload_len) {
		const struct amd_viommu_mig_tlv *tlv;
		const struct amd_viommu_mig_ring_desc *desc;
		const void *data;
		size_t end;
		int ret = 0;

		if (payload_len - off < sizeof(*tlv))
			return -EINVAL;

		tlv = payload + off;
		data = payload + off + sizeof(*tlv);

		if (tlv->length > payload_len - off - sizeof(*tlv))
			return -EINVAL;

		end = off + sizeof(*tlv) +
		      ALIGN(tlv->length, AMD_VIOMMU_MIG_SECTION_ALIGN);
		if (end > payload_len || end <= off)
			return -EINVAL;

		/*
		 * A type is one bit of enum iommu_viommu_mig_section, and a
		 * payload carries each section at most once. Two of a kind
		 * would both be applied, leaving the vIOMMU in the state of
		 * whichever came last, so the payload would not say what it
		 * restores to. Same rule as the ring records within a section.
		 */
		if (!is_power_of_2(tlv->type) || (seen & tlv->type))
			return -EINVAL;
		seen |= tlv->type;

		switch (tlv->type) {
		case IOMMU_VIOMMU_MIG_SECTION_HW_QUEUE:
			ret = amd_viommu_mig_restore_hw_queues(aviommu, data,
							       tlv->length);
			break;
		case IOMMU_VIOMMU_MIG_SECTION_EVTLOG:
			desc = &amd_viommu_mig_rings[AMD_VIOMMU_MIG_RING_EVT];
			ret = amd_viommu_mig_restore_log(aviommu, ctx, desc,
							 data, tlv->length);
			break;
		case IOMMU_VIOMMU_MIG_SECTION_PPRLOG:
			desc = &amd_viommu_mig_rings[AMD_VIOMMU_MIG_RING_PPR];
			ret = amd_viommu_mig_restore_log(aviommu, ctx, desc,
							 data, tlv->length);
			break;
		case IOMMU_VIOMMU_MIG_SECTION_STATUS:
			amd_viommu_mig_restore_status(aviommu, data,
						      tlv->length);
			break;
		default:
			/*
			 * Skipping what this build does not know is the point
			 * of the format; min_reader_version above is what says
			 * whether skipping it is safe.
			 */
			break;
		}

		if (ret)
			return ret;

		off = end;
	}

	/* A payload that describes no rings has nothing to restore */
	if (!(seen & IOMMU_VIOMMU_MIG_SECTION_HW_QUEUE))
		return -EINVAL;

	return 0;
}

/*
 * Confirm a ring is still the one the restore checked.
 *
 * Userspace keeps its hardware queue objects across the restore sequence and
 * may destroy one before committing. Destroying a ring clears its control
 * register, so a ring that has since gone reads back as never programmed, and
 * one replaced by another reads back a different base or size. Arming on that
 * would point hardware at whatever the register holds now rather than at the
 * ring whose pointers and contents were restored.
 */
static int amd_viommu_mig_recheck_ring(struct amd_iommu_viommu *aviommu,
				       const struct amd_viommu_mig_ring_desc *desc,
				       const struct amd_viommu_ring_arm *arm)
{
	u64 ctrl = amd_viommu_mig_live_ctrl(aviommu, desc);

	if (!arm->programmed)
		return ctrl ? -EINVAL : 0;
	if (!ctrl)
		return -EINVAL;

	if (field_get(desc->len_mask, ctrl) != arm->size_encoded)
		return -EINVAL;
	if ((u64)field_get(desc->base_mask, ctrl) << PAGE_SHIFT !=
	    arm->base_gpa)
		return -EINVAL;

	return 0;
}

/*
 * Drop the host translation caches that could still describe this guest, before
 * anything is allowed to translate through them.
 *
 * One flush of the nesting parent covers what matters here: it invalidates the
 * parent's own entries, every host domain ID mapped for this vIOMMU's guest
 * domains, and the device IOTLB of each ATS-capable device attached to the
 * parent, and waits for all of it.
 *
 * Device table and interrupt remapping entries are deliberately left out. Every
 * path that writes one of those already invalidates it: update_dte256() and
 * amd_iommu_update_dte_ir() for the device table, and the modify_irte family for
 * interrupt remapping, which is what the destination's ext-IR replay goes
 * through just before this runs. Flushing them again would repeat work already
 * done, and the only granularity available for it is the whole IOMMU, which
 * would take every other guest's caches with it.
 */
static void amd_viommu_mig_invalidate(struct amd_iommu_viommu *aviommu)
{
	struct protection_domain *parent = aviommu->parent;
	unsigned long flags;

	spin_lock_irqsave(&parent->lock, flags);
	amd_iommu_domain_flush_pages(parent, 0, U64_MAX,
				     CMD_INV_IOMMU_PAGES_PDE_MASK);
	spin_unlock_irqrestore(&parent->lock, flags);
}

/*
 * Set the enable bits the guest had, and only those.
 *
 * Read-modify-write rather than rebuilding the register, because base and
 * length are already in it from the allocation and have just been checked
 * against the payload. Deriving them again here would be a second chance to get
 * them wrong, and this time nothing would catch it.
 *
 * A queue flag with no bit in this ring's register is ignored rather than
 * refused, on the same forward-compatibility grounds as an unknown section: a
 * later format may define flags this build has no register bit for.
 */
static void amd_viommu_mig_arm_ring(struct amd_iommu_viommu *aviommu,
				    const struct amd_viommu_mig_ring_desc *desc,
				    const struct amd_viommu_ring_arm *arm)
{
	struct amd_iommu *iommu =
		container_of(aviommu->core.iommu_dev, struct amd_iommu, iommu);
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, aviommu->gid);
	u64 set = 0;
	unsigned int i;

	if (!arm->programmed)
		return;

	for (i = 0; i < desc->nr_flags; i++)
		if (arm->queue_flags & desc->flags[i].queue)
			set |= desc->flags[i].reg;

	if (!set)
		return;

	spin_lock(&aviommu->vfctrl_lock);
	writeq(readq(vfctrl + desc->ctrl_off) | set, vfctrl + desc->ctrl_off);
	spin_unlock(&aviommu->vfctrl_lock);
}

/**
 * amd_viommu_mig_commit_restore - Bring a restored vIOMMU into service
 * @viommu: vIOMMU whose payload has been restored
 * @ctx: Guest memory accessor for this operation, unused here
 *
 * Return: 0 with the guest's rings live, or an error having armed none of them.
 *
 * The last step of a restore, and the first point at which hardware may act on
 * anything the payload described. Runs after the destination's interrupt
 * remapping routes are in place, so that a log ring cannot take an entry with
 * nowhere to report it.
 */
int amd_viommu_mig_commit_restore(struct iommufd_viommu *viommu,
				  const struct iommufd_viommu_mig_ctx *ctx)
{
	struct amd_iommu_viommu *aviommu =
		container_of(viommu, struct amd_iommu_viommu, core);
	unsigned int i;
	int ret;

	lockdep_assert_held(&viommu->mig_lock);

	/*
	 * Check all three rings before arming any of them. Arming as we went
	 * would leave a guest running against a half-committed vIOMMU when a
	 * later ring turned out not to match.
	 */
	for (i = 0; i < AMD_VIOMMU_MIG_HW_QUEUES; i++) {
		ret = amd_viommu_mig_recheck_ring(aviommu,
						  &amd_viommu_mig_rings[i],
						  &aviommu->mig.rings[i]);
		if (ret)
			return ret;
	}

	amd_viommu_mig_invalidate(aviommu);

	for (i = 0; i < AMD_VIOMMU_MIG_HW_QUEUES; i++)
		amd_viommu_mig_arm_ring(aviommu, &amd_viommu_mig_rings[i],
					&aviommu->mig.rings[i]);

	return 0;
}
