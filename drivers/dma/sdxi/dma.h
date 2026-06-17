/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI dmaengine provider.
 *
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#ifndef __DMA_SDXI_DMA_H
#define __DMA_SDXI_DMA_H

struct sdxi_dev;

int sdxi_dma_register(struct sdxi_dev *sdxi);
void sdxi_dma_unregister(struct sdxi_dev *sdxi);

#endif /* __DMA_SDXI_DMA_H */
