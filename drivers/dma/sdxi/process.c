// SPDX-License-Identifier: GPL-2.0-only
/*
 * User space process management (IOMMU, PASID, etc.)
 *
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#include <linux/device.h>
#include <linux/iommu.h>
#include <linux/slab.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>

#include "context.h"
#include "process.h"
#include "trace.h"

/**********************/
/* PROCESS MANAGEMENT */
/**********************/
static void sdxi_process_cleanup(struct sdxi_process *process)
{
	struct sdxi_cxt *cxt;
	int err = 0;

	if (!process)
		return;

	/*
	 * Cleanup can be triggered either by mm teardown (mmu_notifier->release)
	 * or explicit file close (mmu_notifier_unregister). Keep it idempotent.
	 */
	mutex_lock(&process->mutex);
	cxt = process->cxt;
	if (cxt)
		sdxi_cxt_get(cxt);
	mutex_unlock(&process->mutex);

	if (cxt)
		err = sdxi_cxt_notify_mm_release(cxt);

	if (err && cxt)
		dev_err(sdxi_to_dev(cxt->sdxi),
			"failed to quiesce context %u during mm release: %d\n",
			cxt->id, err);

	if (cxt) {
		sdxi_cxt_put(cxt);
		return;
	}

	/*
	 * Avoid iommu_sva_unbind_device() from the notifier release path.
	 * The IOMMU SVA teardown unregisters its own mmu_notifier and waits
	 * for in-flight release callbacks to finish, which can deadlock if we
	 * try to invoke it from this callback. The last process put handles
	 * any remaining unbind after notifier teardown has completed.
	 */
}

static void sdxi_mmu_notifier_release(struct mmu_notifier *subscription,
				      struct mm_struct *mm)
{
	struct sdxi_process *process;

	process = container_of(subscription, struct sdxi_process, mmu_notifier);
	sdxi_process_cleanup(process);
}

static const struct mmu_notifier_ops sdxi_mmu_notifier_ops = {
	.release = sdxi_mmu_notifier_release,
};

static int sdxi_process_register_mmu_notifier(struct sdxi_process *process)
{
	int err;

	if (!process)
		return -EINVAL;

	if (process->mmu_notifier_registered)
		return 0;

	err = mmu_notifier_register(&process->mmu_notifier, process->mm);
	if (err)
		return err;

	process->mmu_notifier_registered = true;
	return 0;
}

static void sdxi_process_free(struct sdxi_process *process)
{
	struct iommu_sva *sva;
	u32 pasid;

	if (!process)
		return;

	mutex_lock(&process->mutex);
	sva = sdxi_process_detach_sva_locked(process, &pasid);
	mutex_unlock(&process->mutex);

	sdxi_process_unbind_sva(process, sva, pasid);

	put_task_struct(process->lead_thread);
	mmdrop(process->mm);
	mutex_destroy(&process->mutex);
	kfree(process);
}

void sdxi_get_process(struct sdxi_process *process)
{
	refcount_inc(&process->refs);
}

void sdxi_put_process(struct sdxi_process *process)
{
	if (!process)
		return;

	if (refcount_dec_and_test(&process->refs))
		sdxi_process_free(process);
}

int sdxi_bind_process_to_device(struct sdxi_process *process)
{
	struct iommu_sva *sva;
	struct sdxi_dev *sdxi = process->sdxi;
	u32 pasid;
	int err;

	if (!sdxi)
		return -ENODEV;

	sva = iommu_sva_bind_device(sdxi_to_dev(sdxi), process->mm);
	if (IS_ERR(sva))
		return PTR_ERR(sva);

	pasid = iommu_sva_get_pasid(sva);
	if (pasid == IOMMU_PASID_INVALID) {
		err = -EINVAL;
		goto unbind;
	}

	/*
	 * Register after iommu_sva_bind_device(). mmu_notifier_register()
	 * inserts at the head, and mmu_notifier_release() walks from head to
	 * tail. Keeping the SDXI notifier newer than the AMD IOMMU SVA
	 * notifier ensures we stop the context while PASID translations are
	 * still alive during exit_mmap().
	 */
	err = sdxi_process_register_mmu_notifier(process);
	if (err)
		goto unbind;

	process->pasid = pasid;
	process->sva = sva;

	trace_sdxi_bind_process(sdxi, process->pasid);

	return 0;
unbind:
	iommu_sva_unbind_device(sva);
	return err;
}

struct iommu_sva *sdxi_process_detach_sva_locked(struct sdxi_process *process,
						 u32 *pasid)
{
	struct iommu_sva *sva;

	lockdep_assert_held(&process->mutex);

	sva = process->sva;
	if (!sva) {
		if (pasid)
			*pasid = 0;
		return NULL;
	}

	if (pasid)
		*pasid = process->pasid;
	process->sva = NULL;
	process->pasid = 0;

	return sva;
}

void sdxi_process_unbind_sva(struct sdxi_process *process, struct iommu_sva *sva,
			     u32 pasid)
{
	if (!process)
		return;

	/*
	 * Keep the SDXI notifier lifetime tied to the PASID bind so each new
	 * bind re-establishes the release ordering against the IOMMU's own
	 * notifier. mmu_notifier_unregister() may invoke ->release, so the
	 * caller must already have detached any live context from @process.
	 */
	if (process->mmu_notifier_registered) {
		process->mmu_notifier_registered = false;
		mmu_notifier_unregister(&process->mmu_notifier, process->mm);
	}

	if (!sva)
		return;

	iommu_sva_unbind_device(sva);

	trace_sdxi_unbind_process(process->sdxi, pasid);
}

struct sdxi_process *sdxi_create_process(struct file *filep,
					 struct sdxi_dev *sdxi)
{
	struct task_struct *thread = current;
	struct sdxi_process *process;

	if (!thread->mm)
		return ERR_PTR(-EINVAL);

	process = kzalloc_obj(*process, GFP_KERNEL);
	if (!process)
		return ERR_PTR(-ENOMEM);

	refcount_set(&process->refs, 1);
	mutex_init(&process->mutex);
	/*
	 * SVA unbind may run from async context after exit_mmap(). Keep the
	 * mm container and mm->iommu_mm alive without delaying notifier release,
	 * which still quiesces the device before page tables are torn down.
	 */
	process->mm = thread->mm;
	mmgrab(process->mm);
	process->lead_thread = thread->group_leader;
	get_task_struct(process->lead_thread);
	process->sdxi = sdxi;

	process->mmu_notifier.ops = &sdxi_mmu_notifier_ops;
	INIT_HLIST_NODE(&process->mmu_notifier.hlist);

	return process;
}
