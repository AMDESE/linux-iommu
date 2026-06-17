/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * SDXI version constants and comparison APIs.
 *
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#ifndef __DMA_SDXI_VERSION_H
#define __DMA_SDXI_VERSION_H

#include <linux/types.h>

struct sdxi_version {
	u8 major;
	u8 minor;
};

#define SDXI_VERSION_1_0 ((struct sdxi_version){ .major = 1, .minor = 0, })
#define SDXI_VERSION_1_1 ((struct sdxi_version){ .major = 1, .minor = 1, })

static inline u16 sdxi_version_as_u16(struct sdxi_version v)
{
	return (v.major << 8) | v.minor;
}

#define sdxi_version_compare(_name, _op)				\
	static inline bool sdxi_version_ ## _name(struct sdxi_version v1, \
						  struct sdxi_version v2) \
	{								\
		return sdxi_version_as_u16(v1) _op sdxi_version_as_u16(v2); \
	}

sdxi_version_compare(eq, ==)
sdxi_version_compare(gt, >)
sdxi_version_compare(ge, >=)
sdxi_version_compare(lt, <)
sdxi_version_compare(le, <=)

#undef sdxi_version_compare

#endif /* __DMA_SDXI_VERSION_H */
