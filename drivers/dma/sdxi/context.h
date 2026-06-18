/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Header for sq and descriptor management
 *
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#ifndef __DMA_SDXI_CONTEXT_H
#define __DMA_SDXI_CONTEXT_H

#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/workqueue.h>
#include <asm/barrier.h>

#include "sdxi.h"

struct eventfd_ctx;

struct sdxi_cxt {
	struct sdxi_dev *sdxi;	/* owner */
	refcount_t refs;
	struct mutex cleanup_lock;
	struct delayed_work cleanup_work;
	unsigned int id;
	u32 mmap_gen;
	u32 pasid;
	u32 opb_000_enb;
	u32 quiesce_cst_flags;
	unsigned int vma_refs;
	bool pasid_valid;
	bool handle_closed;
	bool mm_dead;
	bool fatal;
	bool quiesced;
	bool resources_released;

	resource_size_t db_base;	/* doorbell MMIO base addr */
	__le64 __iomem *db;		/* doorbell virt addr */

	struct sdxi_cxt_ctl *cxt_ctl;
	dma_addr_t cxt_ctl_dma;

	struct sdxi_akey_table *akey_table;
	dma_addr_t akey_table_dma;

	struct sdxi_sq *sq;

	struct sdxi_process *process;	/* process representation */

	struct sdxi_ring_state *ring_state;

	/* userspace interrupt routing */
	struct eventfd_ctx *intr_eventfd;
	int intr_irq;
	u32 intr_msg;
	u16 intr_akey;

	/* Whether the context is expected to be running (started by SW). */
	bool started;
};

struct sdxi_desc;

enum sdxi_cxt_id {
	SDXI_ADMIN_CXT_ID = 0,
	SDXI_ANY_CXT_ID,
};

/* Context Control */
struct sdxi_cxt *sdxi_working_cxt_init(struct sdxi_dev *sdxi,
				       enum sdxi_cxt_id);
void sdxi_working_cxt_exit(struct sdxi_cxt *cxt);
struct sdxi_cxt *sdxi_kcxt_new(struct sdxi_dev *sdxi);

void sdxi_cxt_get(struct sdxi_cxt *cxt);
void sdxi_cxt_put(struct sdxi_cxt *cxt);
int sdxi_cxt_quiesce(struct sdxi_cxt *cxt, unsigned int timeout_ms,
		     u32 *cst_flags);
bool sdxi_cxt_is_fatal(const struct sdxi_cxt *cxt);
void sdxi_cxt_kill(struct sdxi_cxt *cxt);
void sdxi_cxt_release_user_handle(struct sdxi_cxt *cxt);
int sdxi_cxt_notify_mm_release(struct sdxi_cxt *cxt);
void sdxi_cxt_vma_open(struct sdxi_cxt *cxt);
void sdxi_cxt_vma_close(struct sdxi_cxt *cxt);

void sdxi_cxt_push_doorbell(struct sdxi_cxt *cxt, u64 index);

#endif /* __DMA_SDXI_CONTEXT_H */
