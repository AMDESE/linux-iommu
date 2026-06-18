/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI userspace interrupt delivery helpers. Route SDXI context
 * MSI/MSI-X interrupts to an eventfd.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef __DMA_SDXI_INTR_H
#define __DMA_SDXI_INTR_H

#include <linux/types.h>

struct sdxi_cxt;

int sdxi_cxt_init_intr(struct sdxi_cxt *cxt);
void sdxi_cxt_exit_intr(struct sdxi_cxt *cxt);
int sdxi_cxt_set_intr_fd(struct sdxi_cxt *cxt, int eventfd_fd,
			 u16 *akey, u32 *intr_num);
bool sdxi_cxt_has_intr_fd(const struct sdxi_cxt *cxt);

#endif /* __DMA_SDXI_INTR_H */
