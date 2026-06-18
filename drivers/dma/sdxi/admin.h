/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI admin command descriptor helpers.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef __DMA_SDXI_ADMIN_H
#define __DMA_SDXI_ADMIN_H

#include "context.h"
#include "sdxi.h"

struct sdxi_desc;

static inline struct sdxi_cxt *to_admin_cxt(const struct sdxi_cxt *cxt)
{
	return cxt->sdxi->admin_cxt;
}

static inline bool sdxi_cxt_is_admin(const struct sdxi_cxt *cxt)
{
	return cxt == to_admin_cxt(cxt);
}

int sdxi_adm_start_cxt_sync(struct sdxi_cxt *cxt, unsigned int timeout_ms,
			    u32 *cst_flags, bool interruptible);
int sdxi_adm_stop_cxt_sync(struct sdxi_cxt *cxt, unsigned int timeout_ms,
			   u32 *cst_flags, bool interruptible);
int sdxi_adm_rkey_update_sync(struct sdxi_dev *sdxi, u16 rkey_start, u16 rkey_end,
			      unsigned int timeout_ms, u32 *cst_flags);
int sdxi_adm_akey_update_sync(struct sdxi_dev *sdxi, u16 cxt_start, u16 cxt_end,
			      u16 akey_start, u16 akey_end,
			      unsigned int timeout_ms, u32 *cst_flags);
int sdxi_adm_disc(struct sdxi_dev *sdxi, u16 index_start, u16 index_end,
		  dma_addr_t addr, unsigned int timeout_ms, u32 *cst_flags);
int sdxi_adm_submit_desc(struct sdxi_cxt *adm, struct sdxi_desc *desc,
			 unsigned int timeout_ms, u32 *cst_flags);
int sdxi_adm_start_cxt(struct sdxi_cxt *cxt);
int sdxi_adm_stop_cxt(struct sdxi_cxt *cxt);

#endif /* __DMA_SDXI_ADMIN_H */
