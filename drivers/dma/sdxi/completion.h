/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI completion status block helpers.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef __DMA_SDXI_COMPLETION_H
#define __DMA_SDXI_COMPLETION_H

#include "sdxi.h"

/*
 * Polled completion status block that can be attached to a
 * descriptor.
 */
struct sdxi_completion;
struct sdxi_completion *sdxi_completion_alloc(struct sdxi_dev *sdxi);
void sdxi_completion_free(struct sdxi_completion *sc);
void sdxi_completion_poll(const struct sdxi_completion *sc);
int sdxi_completion_wait_timeout(const struct sdxi_completion *sc,
				 unsigned int timeout_ms);
int sdxi_completion_wait_timeout_nosignal(const struct sdxi_completion *sc,
					  unsigned int timeout_ms);
void sdxi_completion_attach(struct sdxi_desc *desc,
			    const struct sdxi_completion *sc);
bool sdxi_completion_signaled(const struct sdxi_completion *sc);
bool sdxi_completion_errored(const struct sdxi_completion *sc);
u32 sdxi_completion_flags(const struct sdxi_completion *sc);

DEFINE_FREE(sdxi_completion, struct sdxi_completion *, if (_T) sdxi_completion_free(_T))

#endif /* __DMA_SDXI_COMPLETION_H */
