/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI selftest compatibility helpers.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef SELFTEST_SDXI_COMPAT_H
#define SELFTEST_SDXI_COMPAT_H

// Only defined in compiler-gcc.h for some reason
#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif

#endif/* SELFTEST_SDXI_COMPAT_H */
