/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * IOCTL related header
 *
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#ifndef __DMA_SDXI_IOCTL_H
#define __DMA_SDXI_IOCTL_H

#include <linux/bits.h>
#include <linux/mmu_notifier.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>

#include "sdxi.h"
#include "process.h"

struct sdxi_cxt;

enum sdxi_file_type {
	SDXI_FILE_DEVICE = 0,
	SDXI_FILE_CONTEXT,
};

struct sdxi_file {
	enum sdxi_file_type type;
	struct sdxi_process *process;
	struct sdxi_cxt *cxt;
};

typedef int sdxi_ioctl_t(struct file *filep, struct sdxi_file *sf,
			 void *data);

enum sdxi_ioctl_access_class {
	/* Read-only device-scope ioctls and user-visible context creation. */
	SDXI_IOCTL_A_PUBLIC_DEVICE = 0,
	/* Owner-scoped context operations on a returned context fd. */
	SDXI_IOCTL_A_CONTEXT_OWNER,
	/* Function-global and cross-function control paths. */
	SDXI_IOCTL_A_ADMIN_DEVICE,
	/* Vendor paths with handler-declared authorization. */
	SDXI_IOCTL_A_VENDOR_HANDLER,
};

struct sdxi_ioctl_desc {
	unsigned int cmd;
	int file_flags;
	enum sdxi_ioctl_access_class access;
	sdxi_ioctl_t *func;
	unsigned int cmd_drv;
	const char *name;
};

#define SDXI_IOCTL_F_DEVICE	BIT(0)
#define SDXI_IOCTL_F_CONTEXT	BIT(1)

/*
 * Use upper bits of mmap offset to access context specific information.
 * User-created contexts only expose a doorbell mapping; descriptor ring,
 * write-index, and context-status storage are userspace SVA addresses passed
 * to SDXI_CREATE_CXT.
 */
#define SDXI_MMAP_TYPE_SHIFT         40
#define SDXI_MMAP_TYPE_DOORBELL      (0x4ULL << SDXI_MMAP_TYPE_SHIFT)
#define SDXI_MMAP_TYPE_MASK          (0x7ULL << SDXI_MMAP_TYPE_SHIFT)

/*
 * Per-context mmap token encoding:
 *   bits[42:40] : type (SDXI_MMAP_TYPE_DOORBELL)
 *   bits[39:24] : context id
 *   bits[23:12] : context generation
 *   bits[11:0]  : zero (page-aligned)
 */
#define SDXI_MMAP_CXT_ID_SHIFT		24
#define SDXI_MMAP_CXT_ID_MASK		GENMASK_ULL(39, 24)

#define SDXI_MMAP_GEN_SHIFT		12
#define SDXI_MMAP_GEN_MASK		GENMASK_ULL(23, 12)

static inline u64 sdxi_mmap_token(u64 type, u32 cxt_id, u32 gen)
{
	return type |
		(((u64)cxt_id << SDXI_MMAP_CXT_ID_SHIFT) & SDXI_MMAP_CXT_ID_MASK) |
		(((u64)gen << SDXI_MMAP_GEN_SHIFT) & SDXI_MMAP_GEN_MASK);
}

static inline u32 sdxi_mmap_token_cxt_id(u64 token)
{
	return (u32)((token & SDXI_MMAP_CXT_ID_MASK) >> SDXI_MMAP_CXT_ID_SHIFT);
}

static inline u32 sdxi_mmap_token_gen(u64 token)
{
	return (u32)((token & SDXI_MMAP_GEN_MASK) >> SDXI_MMAP_GEN_SHIFT);
}

#endif /* __DMA_SDXI_IOCTL_H */
