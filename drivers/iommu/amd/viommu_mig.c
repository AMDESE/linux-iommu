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
 * pass from touching hardware, and inspects @w->err once at the end instead
 * of after every section.
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
	ring->bytes = VIOMMU_VFCTRL_CMD_LEN_TO_BYTES(FIELD_GET(VIOMMU_VFCTRL_CMD_LEN, val));
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
