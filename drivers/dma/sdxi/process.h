/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * User space process management
 *
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#ifndef __DMA_SDXI_PROCESS_H
#define __DMA_SDXI_PROCESS_H

#include <linux/mmu_notifier.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/types.h>

#include "sdxi.h"

struct iommu_sva;

/* User Space Process Info */
struct sdxi_process {
	refcount_t refs;
	struct mutex mutex;
	struct task_struct *lead_thread;
	struct mm_struct *mm;			/* pinned by mmgrab() */
	struct mmu_notifier mmu_notifier;	/* mm_struct notifier */
	bool mmu_notifier_registered;

	struct sdxi_dev *sdxi;			/* bound SDXI device */
	struct sdxi_cxt *cxt;
	struct iommu_sva *sva;
	u32 pasid;				/* no meaning if !cxt */
};

/* User Process Management */
struct sdxi_process *sdxi_create_process(struct file *filep,
					 struct sdxi_dev *sdxi);
void sdxi_get_process(struct sdxi_process *p);
void sdxi_put_process(struct sdxi_process *p);
int sdxi_bind_process_to_device(struct sdxi_process *p);
struct iommu_sva *sdxi_process_detach_sva_locked(struct sdxi_process *p,
						 u32 *pasid);
void sdxi_process_unbind_sva(struct sdxi_process *p, struct iommu_sva *sva,
			     u32 pasid);

#endif /* __DMA_SDXI_PROCESS_H */
