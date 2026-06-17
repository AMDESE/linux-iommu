/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __DMA_SDXI_ADMIN_H
#define __DMA_SDXI_ADMIN_H

#include "context.h"

struct sdxi_desc;

static inline int sdxi_adm_start_cxt(struct sdxi_cxt *cxt)
{
	return sdxi_start_cxt(cxt);
}

static inline int sdxi_adm_stop_cxt_sync(struct sdxi_cxt *cxt,
					 unsigned int timeout_ms,
					 u32 *cst_flags, bool interruptible)
{
	sdxi_stop_cxt(cxt);
	if (cst_flags)
		*cst_flags = 0;
	return 0;
}

static inline void sdxi_adm_stop_cxt(struct sdxi_cxt *cxt)
{
	sdxi_stop_cxt(cxt);
}

#endif /* __DMA_SDXI_ADMIN_H */
