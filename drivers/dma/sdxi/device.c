// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI hardware device driver
 *
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-direction.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/interrupt.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <asm/mmu.h>

#include "admin.h"
#include "context.h"
#include "descriptor.h"
#include "dma.h"
#include "hw.h"
#include "error.h"
#include "keys.h"
#include "sdxi.h"
#include "trace.h"

static bool dma_engine;
module_param(dma_engine, bool, 0644);
MODULE_PARM_DESC(dma_engine, "Enable DMA engine interface (default: false)");

enum sdxi_fn_gsv {
	SDXI_GSV_STOP,
	SDXI_GSV_INIT,
	SDXI_GSV_ACTIVE,
	SDXI_GSV_STOPG_SF,
	SDXI_GSV_STOPG_HD,
	SDXI_GSV_ERROR,
};

static const char *const gsv_strings[] = {
	[SDXI_GSV_STOP]     = "stopped",
	[SDXI_GSV_INIT]     = "initializing",
	[SDXI_GSV_ACTIVE]   = "active",
	[SDXI_GSV_STOPG_SF] = "soft stopping",
	[SDXI_GSV_STOPG_HD] = "hard stopping",
	[SDXI_GSV_ERROR]    = "error",
};

static const char *gsv_str(enum sdxi_fn_gsv gsv)
{
	if ((size_t)gsv < ARRAY_SIZE(gsv_strings))
		return gsv_strings[(size_t)gsv];

	WARN_ONCE(1, "unexpected gsv %u\n", gsv);

	return "unknown";
}

enum sdxi_fn_gsr {
	SDXI_GSRV_RESET,
	SDXI_GSRV_STOP_SF,
	SDXI_GSRV_STOP_HD,
	SDXI_GSRV_ACTIVE,
};

static enum sdxi_fn_gsv sdxi_dev_gsv(const struct sdxi_dev *sdxi)
{
	return (enum sdxi_fn_gsv)FIELD_GET(SDXI_MMIO_STS0_FN_GSV,
					sdxi_read64(sdxi, SDXI_MMIO_STS0));
}

static void sdxi_write_fn_gsr(struct sdxi_dev *sdxi, enum sdxi_fn_gsr cmd)
{
	u64 ctl0 = sdxi_read64(sdxi, SDXI_MMIO_CTL0);

	FIELD_MODIFY(SDXI_MMIO_CTL0_FN_GSR, &ctl0, cmd);
	sdxi_write64(sdxi, SDXI_MMIO_CTL0, ctl0);
}

static int sdxi_dev_start(struct sdxi_dev *sdxi)
{
	unsigned long deadline;
	enum sdxi_fn_gsv status;

	status = sdxi_dev_gsv(sdxi);
	if (status != SDXI_GSV_STOP) {
		sdxi_err(sdxi,
			 "can't activate busy device (unexpected gsv: %s)\n",
			 gsv_str(status));
		return -EIO;
	}

	sdxi_write_fn_gsr(sdxi, SDXI_GSRV_ACTIVE);

	deadline = jiffies + msecs_to_jiffies(1000);
	do {
		status = sdxi_dev_gsv(sdxi);
		sdxi_dbg(sdxi, "%s: function state: %s\n", __func__, gsv_str(status));

		switch (status) {
		case SDXI_GSV_ACTIVE:
			sdxi_dbg(sdxi, "activated\n");
			return 0;
		case SDXI_GSV_ERROR:
			sdxi_err(sdxi, "went to error state\n");
			return -EIO;
		case SDXI_GSV_INIT:
		case SDXI_GSV_STOP:
			/* transitional states, wait */
			fsleep(1000);
			break;
		default:
			sdxi_err(sdxi, "unexpected gsv %u, giving up\n", status);
			return -EIO;
		}
	} while (time_before(jiffies, deadline));

	sdxi_err(sdxi, "activation timed out, current status %u\n",
		sdxi_dev_gsv(sdxi));
	return -ETIMEDOUT;
}

/* Get the device to the GSV_STOP state. */
static int sdxi_dev_stop(struct sdxi_dev *sdxi)
{
	unsigned long deadline = jiffies + msecs_to_jiffies(1000);
	bool reset_issued = false;

	do {
		enum sdxi_fn_gsv status = sdxi_dev_gsv(sdxi);

		sdxi_dbg(sdxi, "%s: function state: %s\n", __func__, gsv_str(status));

		switch (status) {
		case SDXI_GSV_ACTIVE:
			sdxi_write_fn_gsr(sdxi, SDXI_GSRV_STOP_SF);
			break;
		case SDXI_GSV_ERROR:
			if (!reset_issued) {
				sdxi_info(sdxi,
					  "function in error state, issuing reset\n");
				sdxi_write_fn_gsr(sdxi, SDXI_GSRV_RESET);
				reset_issued = true;
			} else {
				fsleep(1000);
			}
			break;
		case SDXI_GSV_STOP:
			return 0;
		case SDXI_GSV_INIT:
		case SDXI_GSV_STOPG_SF:
		case SDXI_GSV_STOPG_HD:
			/* transitional states, wait */
			sdxi_dbg(sdxi, "waiting for stop (gsv = %u)\n",
				 status);
			fsleep(1000);
			break;
		default:
			sdxi_err(sdxi, "unknown gsv %u, giving up\n", status);
			return -EIO;
		}
	} while (time_before(jiffies, deadline));

	sdxi_err(sdxi, "stop attempt timed out, current status %u\n",
		sdxi_dev_gsv(sdxi));
	return -ETIMEDOUT;
}

static void sdxi_stop(struct sdxi_dev *sdxi)
{
	sdxi_dev_stop(sdxi);
}

/* Refer to "Activation of the SDXI Function by Software". */
static int sdxi_fn_activate(struct sdxi_dev *sdxi)
{
	const struct sdxi_dev_ops *ops = sdxi->dev_ops;
	u64 version;
	u64 cxt_l2;
	u64 cap0;
	u64 cap1;
	u64 ctl2;
	int err;

	/*
	 * Clear any existing configuration from MMIO_CTL0 and ensure
	 * the function is in GSV_STOP state.
	 */
	sdxi_write64(sdxi, SDXI_MMIO_CTL0, 0);
	err = sdxi_dev_stop(sdxi);
	if (err)
		return err;

	/* Determine which spec version the function implements. */
	version = sdxi_read64(sdxi, SDXI_MMIO_VERSION);
	sdxi->sdxi_version = (struct sdxi_version){
		.major = FIELD_GET(SDXI_MMIO_VERSION_MAJOR, version),
		.minor = FIELD_GET(SDXI_MMIO_VERSION_MINOR, version),
	};

	sdxi_info(sdxi, "SDXI %u.%u device found\n",
		  sdxi->sdxi_version.major, sdxi->sdxi_version.minor);

	/*
	 * 1.a. Discover limits and implemented features via MMIO_CAP0
	 * and MMIO_CAP1.
	 */
	cap0 = sdxi_read64(sdxi, SDXI_MMIO_CAP0);
	sdxi->is_vf = FIELD_GET(SDXI_MMIO_CAP0_VF, cap0);
	sdxi->sfunc = FIELD_GET(SDXI_MMIO_CAP0_SFUNC, cap0);
	sdxi->max_ring_entries = SZ_1K;
	sdxi->max_ring_entries *= 1U << FIELD_GET(SDXI_MMIO_CAP0_MAX_DS_RING_SZ, cap0);
	sdxi->db_stride = SZ_4K;
	sdxi->db_stride *= 1U << FIELD_GET(SDXI_MMIO_CAP0_DB_STRIDE, cap0);

	cap1 = sdxi_read64(sdxi, SDXI_MMIO_CAP1);
	sdxi->max_akeys = SZ_256;
	sdxi->max_akeys *= 1U << FIELD_GET(SDXI_MMIO_CAP1_MAX_AKEY_SZ, cap1);
	sdxi->max_cxts = 1 + FIELD_GET(SDXI_MMIO_CAP1_MAX_CXT, cap1);
	sdxi->op_grp_cap = FIELD_GET(SDXI_MMIO_CAP1_OPB_000_CAP, cap1);

	/*
	 * 1.b. Configure SDXI parameters via MMIO_CTL2. We don't have
	 * any reason to impose more conservative limits than those
	 * reported in the capability registers, so use those for now.
	 */
	ctl2 = 0;
	ctl2 |= FIELD_PREP(SDXI_MMIO_CTL2_MAX_BUFFER,
			   FIELD_GET(SDXI_MMIO_CAP1_MAX_BUFFER, cap1));
	ctl2 |= FIELD_PREP(SDXI_MMIO_CTL2_MAX_AKEY_SZ,
			   FIELD_GET(SDXI_MMIO_CAP1_MAX_AKEY_SZ, cap1));
	ctl2 |= FIELD_PREP(SDXI_MMIO_CTL2_MAX_CXT,
			   FIELD_GET(SDXI_MMIO_CAP1_MAX_CXT, cap1));
	ctl2 |= FIELD_PREP(SDXI_MMIO_CTL2_OPB_000_AVL,
			   FIELD_GET(SDXI_MMIO_CAP1_OPB_000_CAP, cap1));
	sdxi_write64(sdxi, SDXI_MMIO_CTL2, ctl2);

	err = sdxi_keys_init(sdxi, cap1);
	if (err)
		return err;

	sdxi_dbg(sdxi,
		 "sfunc:%#x descmax:%llu dbstride:%#x akeymax:%u cxtmax:%u opgrps:%#x\n",
		 sdxi->sfunc, sdxi->max_ring_entries, sdxi->db_stride,
		 sdxi->max_akeys, sdxi->max_cxts, sdxi->op_grp_cap);

	/* 2.a-2.b. Allocate and zero the 4KB Context Level 2 Table */
	sdxi->l2_table = dmam_alloc_coherent(sdxi_to_dev(sdxi), L2_TABLE_SIZE,
					     &sdxi->l2_dma, GFP_KERNEL);
	if (!sdxi->l2_table) {
		err = -ENOMEM;
		goto keys_exit;
	}

	/* 2.c. Program MMIO_CXT_L2 */
	cxt_l2 = FIELD_PREP(SDXI_MMIO_CXT_L2_PTR, sdxi->l2_dma >> ilog2(SZ_4K));
	sdxi_write64(sdxi, SDXI_MMIO_CXT_L2, cxt_l2);

	/*
	 * 2.c.i. Function-level PASID/PR programming is not required for
	 * the host SVA dataplane supported by this driver.
	 */

	/*
	 * This covers the following steps:
	 *
	 * 3. Context Level 1 Table Setup for contexts 0..127.
	 * 4.a. Create the administrative context and associated control
	 * structures.
	 * 4.b. Set its CXT_STS.state to CXTV_RUN; see 10.b.
	 *
	 * The admin context will not consume descriptors until we
	 * write its doorbell later.
	 */
	sdxi->admin_cxt = sdxi_working_cxt_init(sdxi, SDXI_ADMIN_CXT_ID);
	if (!sdxi->admin_cxt) {
		err = -ENOMEM;
		goto keys_exit;
	}

	/*
	 * 5. Mailbox: we don't use this facility and we assume the
	 * reset values are sane.
	 *
	 * 6. If restoring saved state, adjust as appropriate. (We're not.)
	 */

	/*
	 * MSI allocation is informed by the function's maximum
	 * supported contexts, which was discovered in 1.a. Need to do
	 * this before step 7, which claims an IRQ.
	 */
	err = (ops && ops->irq_init) ? ops->irq_init(sdxi) : 0;
	if (err)
		goto admin_cxt_exit;

	/* 7. Initialize error log according to "Error Log Initialization". */
	err = sdxi_error_init(sdxi);
	if (err)
		goto irq_exit;

	/*
	 * 8. "Software may also need to configure and enable
	 * additional [features]". We've already performed MSI setup,
	 * nothing else for us to do here for now.
	 */

	/*
	 * 9. Set MMIO_CTL0.fn_gsr to GSRV_ACTIVE and wait for
	 * MMIO_STS0.fn_gsv to reach GSV_ACTIVE or GSV_ERROR.
	 */
	err = sdxi_dev_start(sdxi);
	if (err)
		goto error_exit;

	/*
	 * 10. Jump start the admin context. This step refers to
	 * "Starting A context and Context Signaling," where method #3
	 * recommends writing an "appropriate" value to the doorbell
	 * register. We haven't queued any descriptors to the admin
	 * context at this point, so the appropriate value would be 0.
	 */
	iowrite64(0, sdxi->admin_cxt->db);

	return 0;

error_exit:
	sdxi_error_exit(sdxi);
irq_exit:
	if (ops && ops->irq_exit)
		ops->irq_exit(sdxi);
admin_cxt_exit:
	sdxi_working_cxt_exit(sdxi->admin_cxt);
keys_exit:
	sdxi_keys_exit(sdxi);
	return err;
}

int sdxi_device_init(struct sdxi_dev *sdxi, const struct sdxi_dev_ops *ops)
{
	int err;

	sdxi->dev_ops = ops;

	sdxi->write_index_pool = dmam_pool_create("WRITE_INDEX", sdxi_to_dev(sdxi),
						  sizeof(__le64),
						  BIT(WRT_INDEX_PTR_SHIFT), 0);
	sdxi->cxt_sts_pool = dmam_pool_create("CXT_STS", sdxi_to_dev(sdxi),
					      sizeof(struct sdxi_cxt_sts),
					      BIT(CXT_STATUS_PTR_SHIFT), 0);
	sdxi->cxt_ctl_pool = dmam_pool_create("CXT_CTL", sdxi_to_dev(sdxi),
					      sizeof(struct sdxi_cxt_ctl),
					      BIT(L1_CXT_CTRL_PTR_SHIFT), 0);
	if (!sdxi->write_index_pool || !sdxi->cxt_sts_pool || !sdxi->cxt_ctl_pool)
		return -ENOMEM;

	err = sdxi_fn_activate(sdxi);
	if (err)
		return err;

	/* Set up DMA engine provider. */
	if (dma_engine) {
		err = sdxi_dma_register(sdxi);
		if (err) {
			sdxi_device_exit(sdxi);
			return err;
		}
	}

	return 0;
}

void sdxi_device_exit(struct sdxi_dev *sdxi)
{
	sdxi_dma_unregister(sdxi);

	/* Walk sdxi->cxt_array freeing any allocated rows. */
	for (size_t i = 0; i < L2_TABLE_ENTRIES; ++i) {
		if (!sdxi->cxt_array[i])
			continue;
		/* When a context is released its entry in the table should be NULL. */
		for (size_t j = 0; j < L1_TABLE_ENTRIES; ++j) {
			struct sdxi_cxt *cxt = sdxi->cxt_array[i][j];

			if (!cxt)
				continue;
			if (cxt->id != 0)  /* admin context shutdown is last */
				sdxi_working_cxt_exit(cxt);
			sdxi->cxt_array[i][j] = NULL;
		}
		if (i != 0)  /* another special case for admin cxt */
			kfree(sdxi->cxt_array[i]);
	}

	sdxi_working_cxt_exit(sdxi->admin_cxt);
	kfree(sdxi->cxt_array[0]);

	sdxi_keys_exit(sdxi);
	sdxi_stop(sdxi);
	sdxi_error_exit(sdxi);

	if (sdxi->dev_ops && sdxi->dev_ops->irq_exit)
		sdxi->dev_ops->irq_exit(sdxi);
}

static void sdxi_pm_disable_errlog(struct sdxi_dev *sdxi)
{
	u64 reg;

	if (!sdxi || !sdxi->err_log)
		return;

	/* Prevent any new error log interrupts from being generated. */
	disable_irq(sdxi->error_irq);
	sdxi_write64(sdxi, SDXI_MMIO_ERR_CFG, 0);

	reg = sdxi_read64(sdxi, SDXI_MMIO_ERR_CTL);
	FIELD_MODIFY(SDXI_MMIO_ERR_CTL_EN, &reg, 0);
	sdxi_write64(sdxi, SDXI_MMIO_ERR_CTL, reg);

	reg = sdxi_read64(sdxi, SDXI_MMIO_CTL0);
	FIELD_MODIFY(SDXI_MMIO_CTL0_FN_ERR_INTR_EN, &reg, 0);
	sdxi_write64(sdxi, SDXI_MMIO_CTL0, reg);
}

static void sdxi_pm_restore_errlog(struct sdxi_dev *sdxi)
{
	u64 reg;

	if (!sdxi || !sdxi->err_log)
		return;

	/* Inhibit interrupts until the config pointer is restored. */
	sdxi_write64(sdxi, SDXI_MMIO_ERR_CFG, 0);

	/* Clear MMIO_ERR_STS. The flags in this register are RW1C. */
	reg = FIELD_PREP(SDXI_MMIO_ERR_STS_STS_BIT, 1) |
	      FIELD_PREP(SDXI_MMIO_ERR_STS_OVF_BIT, 1) |
	      FIELD_PREP(SDXI_MMIO_ERR_STS_ERR_BIT, 1);
	sdxi_write64(sdxi, SDXI_MMIO_ERR_STS, reg);

	reg = sdxi_read64(sdxi, SDXI_MMIO_ERR_CTL);
	FIELD_MODIFY(SDXI_MMIO_ERR_CTL_EN, &reg, 1);
	sdxi_write64(sdxi, SDXI_MMIO_ERR_CTL, reg);

	reg = sdxi_read64(sdxi, SDXI_MMIO_CTL0);
	FIELD_MODIFY(SDXI_MMIO_CTL0_FN_ERR_INTR_EN, &reg, 1);
	sdxi_write64(sdxi, SDXI_MMIO_CTL0, reg);

	sdxi_write64(sdxi, SDXI_MMIO_ERR_WRT, 0);
	sdxi_write64(sdxi, SDXI_MMIO_ERR_RD, 0);

	/*
	 * Keep the error log size consistent with sdxi_error_init(): fixed to
	 * the spec minimum (64 entries).
	 */
	reg = FIELD_PREP(SDXI_MMIO_ERR_CFG_PTR, sdxi->err_log_dma >> 12) |
	      FIELD_PREP(SDXI_MMIO_ERR_CFG_SZ, 1) |
	      FIELD_PREP(SDXI_MMIO_ERR_CFG_EN, 1);
	sdxi_write64(sdxi, SDXI_MMIO_ERR_CFG, reg);

	enable_irq(sdxi->error_irq);
}

static void sdxi_pm_restore_rkey(struct sdxi_dev *sdxi)
{
	u64 reg;

	if (!sdxi || !sdxi->rkey_cap || !sdxi->rkey_table)
		return;

	reg = FIELD_PREP(SDXI_MMIO_RKEY_PTR,
			 sdxi->rkey_table_dma >> ilog2(SZ_4K)) |
	      FIELD_PREP(SDXI_MMIO_RKEY_SZ, sdxi->rkey_order) |
	      FIELD_PREP(SDXI_MMIO_RKEY_EN, 1);
	sdxi_write64(sdxi, SDXI_MMIO_RKEY, reg);
}

static void sdxi_pm_restore_admin_cxt(struct sdxi_dev *sdxi)
{
	struct sdxi_cxt *adm = sdxi->admin_cxt;
	struct sdxi_sq *sq;
	u64 db_val;

	if (!adm || !adm->sq)
		return;

	sq = adm->sq;
	if (!sq->cxt_sts || !sq->write_index)
		return;

	WRITE_ONCE(sq->cxt_sts->state,
		   FIELD_PREP(SDXI_CXT_STS_STATE, CXTV_RUN));

	/* Ensure CXT_STS updates are visible before ringing the doorbell. */
	dma_wmb();
	db_val = le64_to_cpu(READ_ONCE(*sq->write_index));
	iowrite64(db_val, adm->db);
}

static int sdxi_pm_restart_contexts(struct sdxi_dev *sdxi)
{
	int err = 0;
	int ret;

	mutex_lock(&sdxi->cxt_lock);
	for (size_t l2 = 0; l2 < L2_TABLE_ENTRIES; l2++) {
		struct sdxi_cxt **row = sdxi->cxt_array[l2];

		if (!row)
			continue;

		for (size_t l1 = 0; l1 < L1_TABLE_ENTRIES; l1++) {
			struct sdxi_cxt *cxt = row[l1];

			if (!cxt)
				continue;
			if (sdxi_cxt_is_admin(cxt))
				continue;
			if (sdxi_cxt_is_fatal(cxt))
				continue;
			if (!READ_ONCE(cxt->started))
				continue;

			ret = sdxi_adm_start_cxt(cxt);
			if (ret) {
				sdxi_err(sdxi, "failed to restart cxt %u: %d\n",
					 cxt->id, ret);
				WRITE_ONCE(cxt->started, false);
				sdxi_cxt_kill(cxt);
				err = ret;
			}
		}
	}

	mutex_unlock(&sdxi->cxt_lock);
	return err;
}

int sdxi_device_suspend(struct sdxi_dev *sdxi)
{
	int err;

	if (!sdxi)
		return -ENODEV;

	mutex_lock(&sdxi->pm_lock);

	if (sdxi->pm_suspended) {
		mutex_unlock(&sdxi->pm_lock);
		return 0;
	}

	sdxi->pm_ctl0 = sdxi_read64(sdxi, SDXI_MMIO_CTL0);
	sdxi->pm_ctl2 = sdxi_read64(sdxi, SDXI_MMIO_CTL2);
	sdxi->pm_fn_was_active =
		FIELD_GET(SDXI_MMIO_CTL0_FN_GSR, sdxi->pm_ctl0) ==
		(u64)SDXI_GSRV_ACTIVE;

	sdxi_pm_disable_errlog(sdxi);

	err = sdxi_dev_stop(sdxi);
	if (!err)
		sdxi->pm_suspended = true;
	else
		sdxi_pm_restore_errlog(sdxi);

	mutex_unlock(&sdxi->pm_lock);

	return err;
}

int sdxi_device_resume(struct sdxi_dev *sdxi)
{
	u64 ctl0;
	u64 cxt_l2;
	enum sdxi_fn_gsr gsr;
	int err = 0;

	if (!sdxi)
		return -ENODEV;

	mutex_lock(&sdxi->pm_lock);

	if (!sdxi->pm_suspended) {
		mutex_unlock(&sdxi->pm_lock);
		return 0;
	}

	/*
	 * Restore CTL0 but keep the function stopped while restoring state.
	 * Avoid restoring GSRV_RESET (would reset the function) or GSRV_ACTIVE
	 * (would start too early); bring the function to STOP first.
	 */
	gsr = SDXI_GSRV_STOP_SF;
	if (FIELD_GET(SDXI_MMIO_CTL0_FN_GSR, sdxi->pm_ctl0) ==
	    (u64)SDXI_GSRV_STOP_HD)
		gsr = SDXI_GSRV_STOP_HD;

	ctl0 = sdxi->pm_ctl0;
	FIELD_MODIFY(SDXI_MMIO_CTL0_FN_GSR, &ctl0, gsr);
	sdxi_write64(sdxi, SDXI_MMIO_CTL0, ctl0);

	err = sdxi_dev_stop(sdxi);
	if (err)
		goto out_unlock;

	sdxi_write64(sdxi, SDXI_MMIO_CTL2, sdxi->pm_ctl2);

	cxt_l2 = FIELD_PREP(SDXI_MMIO_CXT_L2_PTR, sdxi->l2_dma >> ilog2(SZ_4K));
	sdxi_write64(sdxi, SDXI_MMIO_CXT_L2, cxt_l2);

	sdxi_pm_restore_rkey(sdxi);

	if (sdxi->pm_fn_was_active) {
		err = sdxi_dev_start(sdxi);
		if (err)
			goto out_unlock;

		sdxi_pm_restore_errlog(sdxi);
		sdxi_pm_restore_admin_cxt(sdxi);
		err = sdxi_pm_restart_contexts(sdxi);
	} else {
		sdxi_pm_restore_errlog(sdxi);
	}
	sdxi->pm_suspended = false;

out_unlock:
	mutex_unlock(&sdxi->pm_lock);
	return err;
}
