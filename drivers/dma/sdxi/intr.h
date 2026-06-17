/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __DMA_SDXI_INTR_H
#define __DMA_SDXI_INTR_H

struct sdxi_cxt;

static inline int sdxi_cxt_init_intr(struct sdxi_cxt *cxt)
{
	return 0;
}

static inline void sdxi_cxt_exit_intr(struct sdxi_cxt *cxt)
{
}

#endif /* __DMA_SDXI_INTR_H */
