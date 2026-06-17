/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI error handling entry points.
 *
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#ifndef __DMA_SDXI_ERROR_H
#define __DMA_SDXI_ERROR_H

#include <linux/types.h>

struct sdxi_dev;

int sdxi_error_init(struct sdxi_dev *sdxi);
void sdxi_error_exit(struct sdxi_dev *sdxi);

#endif  /* __DMA_SDXI_ERROR_H */
