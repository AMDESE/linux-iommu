/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#ifndef LINUX_SDXI_H
#define LINUX_SDXI_H

#include <linux/array_size.h>
#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/bug.h>
#include <linux/types.h>

struct device;
struct pci_dev;

/* Refer to "MMIO Control Registers". */
enum sdxi_reg {
	SDXI_MMIO_CTL0       = 0x00000,
	SDXI_MMIO_CTL2       = 0x00010,
	SDXI_MMIO_STS0       = 0x00100,
	SDXI_MMIO_CAP0       = 0x00200,
	SDXI_MMIO_CAP1       = 0x00208,
	SDXI_MMIO_VERSION    = 0x00210,
	SDXI_MMIO_CXT_L2     = 0x10000,
	SDXI_MMIO_RKEY       = 0x10100,
	SDXI_MMIO_ERR_CTL    = 0x20000,
	SDXI_MMIO_ERR_STS    = 0x20008,
	SDXI_MMIO_ERR_CFG    = 0x20010,
	SDXI_MMIO_ERR_WRT    = 0x20020,
	SDXI_MMIO_ERR_RD     = 0x20028,
};

enum {
	/* SDXI_MMIO_CTL0 fields */
	SDXI_MMIO_CTL0_FN_GSR         = GENMASK_ULL(1, 0),
	SDXI_MMIO_CTL0_FN_PASID_VL    = BIT_ULL(2),
	SDXI_MMIO_CTL0_FN_ERR_INTR_EN = BIT_ULL(4),
	SDXI_MMIO_CTL0_FN_PASID       = GENMASK_ULL(27, 8),
	SDXI_MMIO_CTL0_FN_PR          = BIT_ULL(31),          /* SDXI 1.1 */
	SDXI_MMIO_CTL0_FN_GRP_ID      = GENMASK_ULL(63, 32),

	/* SDXI_MMIO_CTL2 fields */
	SDXI_MMIO_CTL2_MAX_BUFFER  = GENMASK_ULL(3, 0),
	SDXI_MMIO_CTL2_MAX_AKEY_SZ = GENMASK_ULL(15, 12),
	SDXI_MMIO_CTL2_MAX_CXT     = GENMASK_ULL(31, 16),
	SDXI_MMIO_CTL2_OPB_000_AVL = GENMASK_ULL(63, 32),

	/* SDXI_MMIO_STS0 bit definitions */
	SDXI_MMIO_STS0_FN_GSV = GENMASK_ULL(2, 0),

	/* SDXI_MMIO_CAP0 bit definitions */
	SDXI_MMIO_CAP0_SFUNC = GENMASK_ULL(15, 0),
	SDXI_MMIO_CAP0_VF = BIT_ULL(16),
	SDXI_MMIO_CAP0_DB_STRIDE = GENMASK_ULL(22, 20),
	SDXI_MMIO_CAP0_MAX_DS_RING_SZ = GENMASK_ULL(28, 24),

	/* SDXI_MMIO_CAP1 fields */
	SDXI_MMIO_CAP1_MAX_BUFFER    = GENMASK_ULL(3, 0),
	SDXI_MMIO_CAP1_RKEY_CAP      = BIT_ULL(4),
	SDXI_MMIO_CAP1_RM            = BIT_ULL(5),
	SDXI_MMIO_CAP1_MMIO64        = BIT_ULL(6),
	SDXI_MMIO_CAP1_MAX_ERRLOG_SZ = GENMASK_ULL(11, 8),
	SDXI_MMIO_CAP1_MAX_AKEY_SZ   = GENMASK_ULL(15, 12),
	SDXI_MMIO_CAP1_MAX_CXT       = GENMASK_ULL(31, 16),
	SDXI_MMIO_CAP1_OPB_000_CAP   = GENMASK_ULL(63, 32),

	/* SDXI_MMIO_VERSION fields */
	SDXI_MMIO_VERSION_MINOR = GENMASK_ULL(7, 0),
	SDXI_MMIO_VERSION_MAJOR = GENMASK_ULL(23, 16),

	/* SDXI_MMIO_CXT_L2 fields */
	SDXI_MMIO_CXT_L2_PTR = GENMASK_ULL(63, 12),

	/* SDXI_MMIO_ERR_CFG bit definitions */
	SDXI_MMIO_ERR_CFG_PTR = GENMASK_ULL(63, 12),
	SDXI_MMIO_ERR_CFG_SZ  = GENMASK_ULL(5, 1),
	SDXI_MMIO_ERR_CFG_EN  = BIT_ULL(0),

	/* SDXI_MMIO_RKEY bit definitions */
	SDXI_MMIO_RKEY_PTR = GENMASK_ULL(63, 12),
	SDXI_MMIO_RKEY_SZ = GENMASK_ULL(4, 1),
	SDXI_MMIO_RKEY_EN = BIT_ULL(0),

	/* SDXI_MMIO_ERR_CTL bit definitions */
	SDXI_MMIO_ERR_CTL_EN = BIT_ULL(0),

	/* SDXI_MMIO_ERR_STS bit definitions. */
	SDXI_MMIO_ERR_STS_STS_BIT = BIT_ULL(0),
	SDXI_MMIO_ERR_STS_OVF_BIT = BIT_ULL(1),
	SDXI_MMIO_ERR_STS_ERR_BIT = BIT_ULL(3),
};

enum sdxi_fn_gsv {
	SDXI_GSV_STOP,
	SDXI_GSV_INIT,
	SDXI_GSV_ACTIVE,
	SDXI_GSV_STOPG_SF,
	SDXI_GSV_STOPG_HD,
	SDXI_GSV_ERROR,
};

enum sdxi_fn_gsr {
	SDXI_GSRV_RESET,
	SDXI_GSRV_STOP_SF,
	SDXI_GSRV_STOP_HD,
	SDXI_GSRV_ACTIVE,
};

static inline const char *sdxi_gsv_str(enum sdxi_fn_gsv gsv)
{
	static const char *const gsv_strings[] = {
		[SDXI_GSV_STOP]     = "stopped",
		[SDXI_GSV_INIT]     = "initializing",
		[SDXI_GSV_ACTIVE]   = "active",
		[SDXI_GSV_STOPG_SF] = "soft stopping",
		[SDXI_GSV_STOPG_HD] = "hard stopping",
		[SDXI_GSV_ERROR]    = "error",
	};

	if ((size_t)gsv < ARRAY_SIZE(gsv_strings))
		return gsv_strings[(size_t)gsv];

	WARN_ONCE(1, "unexpected gsv %u\n", gsv);

	return "unknown";
}

/**
 * sdxi_fn_start() - Drive an SDXI function to the GSV_ACTIVE state.
 * @dev:       Device to log against.
 * @ctrl_regs: Mapping of the function's BAR0 control registers.
 *
 * The function must already be in GSV_STOP; activating from any other state is
 * rejected rather than forced, since the caller is expected to have configured
 * the function's tables while it was stopped.
 *
 * May sleep. Returns 0 once the function is active, -ETIMEDOUT if it did
 * not activate within one second, or -EIO if it was not stopped to begin
 * with, landed in GSV_ERROR, or reported an unrecognized state.
 */
int sdxi_fn_start(struct device *dev, void __iomem *ctrl_regs);

/**
 * sdxi_fn_stop() - Drive an SDXI function to the GSV_STOP state.
 * @dev:       Device to log against.
 * @ctrl_regs: Mapping of the function's BAR0 control registers.
 *
 * Implements SDXI 1.0a §4.1.9: requests a soft stop from GSV_ACTIVE and
 * polls until the function reaches GSV_STOP. A function found in (or
 * landing in) GSV_ERROR is recovered once via GSRV_RESET per §4.1.6.
 *
 * May sleep. Returns 0 once the function is stopped, -ETIMEDOUT if it
 * did not stop within one second, or -EIO on an unrecognized state.
 */
int sdxi_fn_stop(struct device *dev, void __iomem *ctrl_regs);

/**
 * sdxi_fn_stop_timeout() - sdxi_fn_stop() with a caller-chosen wait.
 * @timeout_ms: Poll budget. Zero is rejected.
 *
 * The migration pause drain uses this so a PRI still in flight can be
 * completed by a running guest. The one-second sdxi_fn_stop() wrapper
 * stays the VFIO state-machine path.
 */
int sdxi_fn_stop_timeout(struct device *dev, void __iomem *ctrl_regs,
			 unsigned int timeout_ms);

/**
 * sdxi_pf_restart_vf_contexts() - Restart a VF's contexts after VM resume.
 * @vf:        SDXI VF whose contexts should be restarted.
 * @vf_num:    VF number as understood by the SDXI function (1-based).
 * @cxt_start: First context to target (inclusive).
 * @cxt_end:   Last context to target (inclusive).
 *
 * Returns 0 on success, -ENODEV if @vf is not a VF or its PF is not bound
 * to the SDXI core driver.
 */
int sdxi_pf_restart_vf_contexts(struct pci_dev *vf, u16 vf_num,
				u16 cxt_start, u16 cxt_end);

#endif /* LINUX_SDXI_H */
