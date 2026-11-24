// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO variant driver for AMD SDXI PCI devices supporting
 * VFIO_MIGRATION_STOP_COPY, VFIO_MIGRATION_P2P, and VFIO_MIGRATION_PRE_COPY.
 *
 * Migration FSM and P2P quiesce model: see main.h.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/amd-iommu.h>
#include <linux/anon_inodes.h>
#include <linux/bitfield.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include <linux/vmalloc.h>
#include <linux/vfio.h>
#include <linux/vfio_pci_core.h>

#include "hw.h"
#include "main.h"
#include "migration.h"
#include "mmio.h"

#define sdxi_dev(s)	(&(s)->core_dev.pdev->dev)

static u64 sdxi_read64(struct sdxi_vfio_pci_device *s, enum sdxi_reg reg)
{
	return ioread64(s->bar0 + reg);
}

static void sdxi_write64(struct sdxi_vfio_pci_device *s, enum sdxi_reg reg,
			 u64 val)
{
	iowrite64(val, s->bar0 + reg);
}

/* Leave the function as it is when a pause drain hits an error. */
#define SDXI_FN_STOP_PRESERVE_ERROR BIT(0)

static const char *sdxi_gsv_str(enum sdxi_fn_gsv gsv)
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

	return "unknown";
}

static enum sdxi_fn_gsv sdxi_fn_gsv(void __iomem *ctrl_regs)
{
	return FIELD_GET(SDXI_MMIO_STS0_FN_GSV,
			 ioread64(ctrl_regs + SDXI_MMIO_STS0));
}

static void sdxi_write_fn_gsr(void __iomem *ctrl_regs, enum sdxi_fn_gsr cmd)
{
	u64 ctl0 = ioread64(ctrl_regs + SDXI_MMIO_CTL0);

	FIELD_MODIFY(SDXI_MMIO_CTL0_FN_GSR, &ctl0, cmd);
	iowrite64(ctl0, ctrl_regs + SDXI_MMIO_CTL0);
}

/*
 * BAR0 helpers for the VF this driver owns. The poll is 1 ms and waits
 * out GSV_STOPG_SF. There is no hard stop and no function reset here.
 * The PF's own stop path is untouched.
 */
static int sdxi_fn_start(struct device *dev, void __iomem *ctrl_regs)
{
	unsigned long deadline;
	enum sdxi_fn_gsv status;

	status = sdxi_fn_gsv(ctrl_regs);
	if (status != SDXI_GSV_STOP) {
		dev_err(dev,
			"can't activate busy device (unexpected gsv: %s)\n",
			sdxi_gsv_str(status));
		return -EIO;
	}

	sdxi_write_fn_gsr(ctrl_regs, SDXI_GSRV_ACTIVE);

	deadline = jiffies + msecs_to_jiffies(1000);
	do {
		status = sdxi_fn_gsv(ctrl_regs);
		dev_dbg(dev, "%s: function state: %s\n", __func__,
			sdxi_gsv_str(status));

		switch (status) {
		case SDXI_GSV_ACTIVE:
			dev_dbg(dev, "activated\n");
			return 0;
		case SDXI_GSV_ERROR:
			dev_err(dev, "went to error state\n");
			return -EIO;
		case SDXI_GSV_INIT:
		case SDXI_GSV_STOP:
			fsleep(1000);
			break;
		default:
			dev_err(dev, "unexpected gsv %u, giving up\n", status);
			return -EIO;
		}
	} while (time_before(jiffies, deadline));

	dev_err(dev, "activation timed out, current status %u\n",
		sdxi_fn_gsv(ctrl_regs));
	return -ETIMEDOUT;
}

static void sdxi_fn_log_stop_stall(struct device *dev, void __iomem *regs,
				   const char *why)
{
	u64 sts0 = ioread64(regs + SDXI_MMIO_STS0);
	u64 err_sts = ioread64(regs + SDXI_MMIO_ERR_STS);

	dev_err(dev,
		"stop stall (%s): gsv=%llu sts0=%#llx ctl0=%#llx ctl2=%#llx\n",
		why,
		(unsigned long long)FIELD_GET(SDXI_MMIO_STS0_FN_GSV, sts0),
		sts0,
		ioread64(regs + SDXI_MMIO_CTL0),
		ioread64(regs + SDXI_MMIO_CTL2));
	dev_err(dev,
		"stop stall (%s): err_ctl=%#llx err_sts=%#llx%s%s%s err_cfg=%#llx err_wrt=%llu err_rd=%llu\n",
		why,
		ioread64(regs + SDXI_MMIO_ERR_CTL),
		err_sts,
		(err_sts & SDXI_MMIO_ERR_STS_STS_BIT) ? " log-nonempty" : "",
		(err_sts & SDXI_MMIO_ERR_STS_OVF_BIT) ? " overflow" : "",
		(err_sts & SDXI_MMIO_ERR_STS_ERR_BIT) ? " log-failed" : "",
		ioread64(regs + SDXI_MMIO_ERR_CFG),
		ioread64(regs + SDXI_MMIO_ERR_WRT),
		ioread64(regs + SDXI_MMIO_ERR_RD));
}

static bool sdxi_fn_errlog_pending(void __iomem *regs)
{
	u64 err_sts = ioread64(regs + SDXI_MMIO_ERR_STS);
	u64 wrt = ioread64(regs + SDXI_MMIO_ERR_WRT);
	u64 rd = ioread64(regs + SDXI_MMIO_ERR_RD);

	return (err_sts & SDXI_MMIO_ERR_STS_STS_BIT) || wrt > rd;
}

static int sdxi_fn_preserve_error(struct device *dev, void __iomem *ctrl_regs,
				  enum sdxi_fn_gsv status, bool pending)
{
	/*
	 * Leave MSI-X unmasked. The VFIO caller reads the vector pending
	 * bit and the error-log slot, then masks. Masking here hides both.
	 */
	sdxi_fn_log_stop_stall(dev, ctrl_regs,
			       status == SDXI_GSV_ERROR ?
			       "preserve-error" : "preserve-log");
	dev_err(dev,
		"pause drain: preserving device (gsv=%s errlog=%s), not issuing reset\n",
		sdxi_gsv_str(status), pending ? "pending" : "empty");
	return -EPROTO;
}

static int sdxi_fn_stop_timeout_flags(struct device *dev, void __iomem *ctrl_regs,
				      unsigned int timeout_ms, unsigned int flags)
{
	unsigned long deadline = jiffies + msecs_to_jiffies(timeout_ms);
	bool preserve = flags & SDXI_FN_STOP_PRESERVE_ERROR;
	bool reset_issued = false;
	bool wrote_stop_sf = false;
	bool saw_stopg_sf = false;
	ktime_t t_stop_sf = 0;
	ktime_t t_stopg_sf = 0;
	ktime_t now;

	if (!timeout_ms)
		return -EINVAL;

	do {
		enum sdxi_fn_gsv status = sdxi_fn_gsv(ctrl_regs);
		bool pending = false;

		dev_dbg(dev, "%s: function state: %s\n", __func__,
			sdxi_gsv_str(status));

		if (preserve) {
			pending = sdxi_fn_errlog_pending(ctrl_regs);
			if (status == SDXI_GSV_ERROR || pending)
				return sdxi_fn_preserve_error(dev, ctrl_regs,
							      status, pending);
		}

		switch (status) {
		case SDXI_GSV_ACTIVE:
			sdxi_write_fn_gsr(ctrl_regs, SDXI_GSRV_STOP_SF);
			if (!wrote_stop_sf) {
				t_stop_sf = ktime_get();
				wrote_stop_sf = true;
				dev_info(dev,
					 "soft-stop: wrote MMIO_CTL0.fn_gsr=GSRV_STOP_SF\n");
			}
			/*
			 * GSV_STOPG_SF is entered as soon as the function
			 * accepts the soft stop. Sample before sleeping so
			 * a short dwell is not hidden by the poll interval.
			 */
			status = sdxi_fn_gsv(ctrl_regs);
			if (status != SDXI_GSV_ACTIVE)
				continue;
			fsleep(1000);
			break;
		case SDXI_GSV_ERROR:
			if (!reset_issued) {
				sdxi_fn_log_stop_stall(dev, ctrl_regs, "error");
				dev_info(dev,
					 "function in error state, issuing reset\n");
				sdxi_write_fn_gsr(ctrl_regs, SDXI_GSRV_RESET);
				reset_issued = true;
			} else {
				fsleep(1000);
			}
			break;
		case SDXI_GSV_STOP:
			now = ktime_get();
			if (wrote_stop_sf && saw_stopg_sf)
				dev_info(dev,
					 "soft-stop: MMIO_STS0.fn_gsv=GSV_STOP (+%lld us after GSRV_STOP_SF, %lld us after GSV_STOPG_SF)\n",
					 (long long)ktime_us_delta(now, t_stop_sf),
					 (long long)ktime_us_delta(now, t_stopg_sf));
			else if (saw_stopg_sf)
				dev_info(dev,
					 "soft-stop: MMIO_STS0.fn_gsv=GSV_STOP (+%lld us after GSV_STOPG_SF)\n",
					 (long long)ktime_us_delta(now, t_stopg_sf));
			else if (wrote_stop_sf)
				dev_info(dev,
					 "soft-stop: MMIO_STS0.fn_gsv=GSV_STOP without GSV_STOPG_SF (+%lld us after GSRV_STOP_SF)\n",
					 (long long)ktime_us_delta(now, t_stop_sf));
			return 0;
		case SDXI_GSV_INIT:
		case SDXI_GSV_STOPG_SF:
		case SDXI_GSV_STOPG_HD:
			if (status == SDXI_GSV_STOPG_SF && !saw_stopg_sf) {
				t_stopg_sf = ktime_get();
				saw_stopg_sf = true;
				if (wrote_stop_sf)
					dev_info(dev,
						 "soft-stop: MMIO_STS0.fn_gsv=GSV_STOPG_SF (+%lld us after GSRV_STOP_SF)\n",
						 (long long)ktime_us_delta(t_stopg_sf,
									   t_stop_sf));
				else
					dev_info(dev,
						 "soft-stop: MMIO_STS0.fn_gsv=GSV_STOPG_SF\n");
			}
			dev_dbg(dev, "waiting for stop (gsv = %u)\n", status);
			fsleep(1000);
			break;
		default:
			dev_err(dev, "unknown gsv %u, giving up\n", status);
			return -EIO;
		}
	} while (time_before(jiffies, deadline));

	now = ktime_get();
	dev_err(dev, "stop attempt timed out, current status %u\n",
		sdxi_fn_gsv(ctrl_regs));
	sdxi_fn_log_stop_stall(dev, ctrl_regs, "timeout");
	if (wrote_stop_sf || saw_stopg_sf)
		dev_info(dev,
			 "soft-stop: timed out wrote_stop_sf=%d saw_stopg_sf=%d (+%lld us after GSRV_STOP_SF, +%lld us after GSV_STOPG_SF)\n",
			 wrote_stop_sf, saw_stopg_sf,
			 wrote_stop_sf ?
			 (long long)ktime_us_delta(now, t_stop_sf) : -1LL,
			 saw_stopg_sf ?
			 (long long)ktime_us_delta(now, t_stopg_sf) : -1LL);
	return -ETIMEDOUT;
}

static int sdxi_fn_stop(struct device *dev, void __iomem *ctrl_regs)
{
	return sdxi_fn_stop_timeout_flags(dev, ctrl_regs, 1000, 0);
}

static void sdxi_report_fault_state(struct sdxi_vfio_pci_device *s)
{
	u64 sts0 = sdxi_read64(s, SDXI_MMIO_STS0);
	u64 err_sts = sdxi_read64(s, SDXI_MMIO_ERR_STS);

	dev_warn(sdxi_dev(s),
		 "fault state: fn_gsv=%s err_sts=0x%llx%s%s%s\n",
		 sdxi_gsv_str((enum sdxi_fn_gsv)FIELD_GET(SDXI_MMIO_STS0_FN_GSV,
							  sts0)),
		 err_sts,
		 (err_sts & SDXI_MMIO_ERR_STS_ERR_BIT) ? " [error logged]" : "",
		 (err_sts & SDXI_MMIO_ERR_STS_OVF_BIT) ? " [overflow]" : "",
		 (err_sts & SDXI_MMIO_ERR_STS_STS_BIT) ? " [log non-empty]" : "");
}

/*
 * Context control and status live in the kernel dma pool (L1.KA is set),
 * so the device translates them with the function PASID, or GCR3[0] when
 * that PASID is not valid. A context's own user PASID is for payload DMA.
 */
static u32 sdxi_dma_pasid(struct sdxi_vfio_pci_device *s)
{
	u64 ctl0 = sdxi_read64(s, SDXI_MMIO_CTL0);

	if (!(ctl0 & SDXI_MMIO_CTL0_FN_PASID_VL))
		return 0;

	return FIELD_GET(SDXI_MMIO_CTL0_FN_PASID, ctl0);
}

/* Pointer fields store the address shifted down by the mask's low bit. */
#define sdxi_field_ptr(raw, mask) \
	((dma_addr_t)FIELD_GET((mask), (raw)) << __bf_shf(mask))

static void sdxi_debug_log_stop_stall(struct sdxi_vfio_pci_device *s);

/*
 * Guest never programmed this function. sdxi_fn_start() has already
 * moved it to GSV_ACTIVE, so fn_gsr and fn_gsv are not still at reset.
 * No context table and no function PASID means a soft stop has nothing
 * to quiesce and the device reports GSV_ERROR. GSV_ERROR stays on the
 * preserve path: that is a failed function, not an untouched one.
 */
static bool sdxi_guest_unprogrammed(struct sdxi_vfio_pci_device *s)
{
	u64 ctl0 = sdxi_read64(s, SDXI_MMIO_CTL0);
	u64 sts0 = sdxi_read64(s, SDXI_MMIO_STS0);
	u64 cxt_l2 = sdxi_read64(s, SDXI_MMIO_CXT_L2);
	enum sdxi_fn_gsv gsv;

	if (ctl0 == ~0ULL)
		return false;

	gsv = (enum sdxi_fn_gsv)FIELD_GET(SDXI_MMIO_STS0_FN_GSV, sts0);
	if (gsv != SDXI_GSV_STOP && gsv != SDXI_GSV_ACTIVE)
		return false;
	if (ctl0 & SDXI_MMIO_CTL0_FN_PASID_VL)
		return false;
	return !sdxi_field_ptr(cxt_l2, SDXI_MMIO_CXT_L2_PTR);
}

static int sdxi_stop(struct sdxi_vfio_pci_device *s)
{
	int ret;

	/*
	 * Reads of all-ones from CTL0 indicate the device is not responding
	 * to MMIO -- typically the brief window after a PCI reset, which the
	 * VFIO layer may have performed underneath us. A reset leaves the
	 * function at GSV_STOP once it completes (§4.1.7), and there is no
	 * state to read back until it does, so treat this as stopped rather
	 * than polling a dead mapping for a second.
	 */
	if (sdxi_read64(s, SDXI_MMIO_CTL0) == ~0ULL) {
		dev_info(sdxi_dev(s),
			 "stop: device not responding (post-reset), assumed stopped\n");
		return 0;
	}

	if (sdxi_guest_unprogrammed(s)) {
		dev_info(sdxi_dev(s),
			 "stop: guest SDXI driver not programmed; skip GSRV_STOP_SF\n");
		return 0;
	}

	ret = sdxi_fn_stop(sdxi_dev(s), s->bar0);
	if (ret)
		sdxi_debug_log_stop_stall(s);
	return ret;
}

/*
 * Debug: sample the registers the migration image writes. TC09 reads
 * them only after a failed RUNNING transition, and QEMU's recover path
 * resets the VF in that case.
 */
static void sdxi_debug_log_regs(struct sdxi_vfio_pci_device *s, const char *when)
{
	u64 sts0 = sdxi_read64(s, SDXI_MMIO_STS0);

	dev_info(sdxi_dev(s),
		 "debug regs %s: fn_gsv=%s sts0=0x%llx ctl0=0x%llx ctl2=0x%llx cxt_l2=0x%llx rkey=0x%llx err_ctl=0x%llx err_cfg=0x%llx\n",
		 when,
		 sdxi_gsv_str((enum sdxi_fn_gsv)FIELD_GET(SDXI_MMIO_STS0_FN_GSV,
							  sts0)),
		 sts0,
		 sdxi_read64(s, SDXI_MMIO_CTL0),
		 sdxi_read64(s, SDXI_MMIO_CTL2),
		 sdxi_read64(s, SDXI_MMIO_CXT_L2),
		 sdxi_read64(s, SDXI_MMIO_RKEY),
		 sdxi_read64(s, SDXI_MMIO_ERR_CTL),
		 sdxi_read64(s, SDXI_MMIO_ERR_CFG));
}

static const char *sdxi_mig_state_str(enum vfio_device_mig_state st)
{
	switch (st) {
	case VFIO_DEVICE_STATE_ERROR:
		return "ERROR";
	case VFIO_DEVICE_STATE_STOP:
		return "STOP";
	case VFIO_DEVICE_STATE_RUNNING:
		return "RUNNING";
	case VFIO_DEVICE_STATE_STOP_COPY:
		return "STOP_COPY";
	case VFIO_DEVICE_STATE_RESUMING:
		return "RESUMING";
	case VFIO_DEVICE_STATE_RUNNING_P2P:
		return "RUNNING_P2P";
	case VFIO_DEVICE_STATE_PRE_COPY:
		return "PRE_COPY";
	case VFIO_DEVICE_STATE_PRE_COPY_P2P:
		return "PRE_COPY_P2P";
	default:
		return "OTHER";
	}
}

static void sdxi_debug_log_contexts(struct sdxi_vfio_pci_device *s,
				    const char *when);

/*
 * DSC_CXT_START_RS carries one db_value for the whole range, and that
 * field does not ring the context doorbell. A rewound context is
 * started alone with db_value 0, then write_index is written to its
 * doorbell once the context is RUN. Every other context stays in a
 * db_value 0 range.
 */
static int sdxi_ring_replay_doorbell(struct sdxi_vfio_pci_device *s,
				     u32 cxt_id, u64 write_index)
{
	struct pci_dev *pdev = s->core_dev.pdev;
	u64 cap0 = sdxi_read64(s, SDXI_MMIO_CAP0);
	u32 stride = SZ_4K << FIELD_GET(SDXI_MMIO_CAP0_DB_STRIDE, cap0);
	u64 offset = (u64)cxt_id * stride;
	resource_size_t len = pci_resource_len(pdev, 2);
	void __iomem *dbs;

	if (!len || offset > len - sizeof(u64)) {
		dev_err(sdxi_dev(s),
			"replay: id %u doorbell offset %#llx outside BAR2 len %#llx\n",
			cxt_id, offset, (u64)len);
		return -EINVAL;
	}

	dbs = pci_iomap(pdev, 2, 0);
	if (!dbs) {
		dev_err(sdxi_dev(s), "replay: id %u failed to map doorbell BAR\n",
			cxt_id);
		return -ENOMEM;
	}

	wmb();
	iowrite64(write_index, dbs + offset);
	pci_iounmap(pdev, dbs);
	dev_warn(sdxi_dev(s), "replay: id %u doorbell write %llu\n",
		 cxt_id, write_index);
	return 0;
}

static int sdxi_restart_vf_contexts(struct sdxi_vfio_pci_device *s,
				    struct pci_dev *vf, int vf_id,
				    u32 max_cxt)
{
	u32 start = 0;
	u32 i, n = s->nr_replay;
	int ret = 0;

	for (i = 1; i < n; i++) {
		struct sdxi_replay_db key = s->replay[i];
		u32 j = i;

		while (j > 0 && s->replay[j - 1].id > key.id) {
			s->replay[j] = s->replay[j - 1];
			j--;
		}
		s->replay[j] = key;
	}

	for (i = 0; i < n; i++) {
		u32 id = s->replay[i].id;

		if (id < start)
			continue;
		if (id > max_cxt) {
			dev_warn(sdxi_dev(s),
				 "start: replay id %u is past max_cxt %u\n",
				 id, max_cxt);
			continue;
		}
		if (id > start) {
			dev_info(sdxi_dev(s),
				 "start: P2V restart vf_id=%d cxt %u..%u db_value=0\n",
				 vf_id, start, id - 1);
			ret = sdxi_pf_restart_vf_contexts(vf, vf_id, start,
							  id - 1, 0);
			if (ret)
				return ret;
		}
		dev_info(sdxi_dev(s),
			 "start: P2V restart vf_id=%d cxt %u db_value=0\n",
			 vf_id, id);
		ret = sdxi_pf_restart_vf_contexts(vf, vf_id, id, id, 0);
		if (ret)
			return ret;
		ret = sdxi_ring_replay_doorbell(s, id, s->replay[i].db);
		if (ret)
			return ret;
		start = id + 1;
	}
	if (start <= max_cxt) {
		dev_info(sdxi_dev(s),
			 "start: P2V restart vf_id=%d cxt %u..%u db_value=0\n",
			 vf_id, start, max_cxt);
		ret = sdxi_pf_restart_vf_contexts(vf, vf_id, start, max_cxt, 0);
	}
	if (!ret)
		s->nr_replay = 0;
	return ret;
}

static int sdxi_start(struct sdxi_vfio_pci_device *s)
{
	struct pci_dev *vf = s->core_dev.pdev;
	u64 cap1, cxt_l2;
	u32 max_cxt;
	int vf_id;
	int ret;

	dev_info(sdxi_dev(s), "sdxi_start: enter (mig %s)\n",
		 sdxi_mig_state_str(s->state));
	sdxi_debug_log_regs(s, "start entry");

	/*
	 * PRE_COPY -> RUNNING is also taken when a pause drain stopped the
	 * function without leaving PRE_COPY. Already-active is the normal
	 * cancel path and must not issue another P2V.
	 */
	if ((enum sdxi_fn_gsv)FIELD_GET(SDXI_MMIO_STS0_FN_GSV,
				       sdxi_read64(s, SDXI_MMIO_STS0)) ==
	    SDXI_GSV_ACTIVE) {
		s->nr_replay = 0;
		return 0;
	}

	ret = sdxi_fn_start(sdxi_dev(s), s->bar0);
	if (ret)
		return ret;
	sdxi_debug_log_regs(s, "after fn_start");

	/*
	 * Function went GSV_ACTIVE -> GSV_STOPG -> GSV_STOP at snapshot time,
	 * which moved every running context to CXTV_STOP_FN. To resume, ask
	 * the PF to issue P2V.DSC_CXT_START_RS for all of this VF's contexts
	 * (§6.6.3).
	 *
	 * The range starts at context 0: the guest's admin context is stopped
	 * along with the rest, and while it is at CXTV_STOP_FN the guest can
	 * submit no admin descriptor, so it can never start a context of its
	 * own again. A VF admin context is a legal P2V target because the
	 * descriptor is issued by the PF, not by the context being started.
	 *
	 * QEMU drives RUNNING_P2P then RUNNING at every vm_start, so this is
	 * also reached on a cold boot. Without a context table nothing was
	 * parked at CXTV_STOP_FN, and the descriptor would fail and leave the
	 * PF admin context at CXTV_ERROR, breaking later restarts (MIG-D3).
	 */
	cxt_l2 = sdxi_read64(s, SDXI_MMIO_CXT_L2);
	if (!sdxi_field_ptr(cxt_l2, SDXI_MMIO_CXT_L2_PTR)) {
		dev_dbg(sdxi_dev(s),
			"start: no context table, skipping P2V restart\n");
		s->nr_replay = 0;
		return 0;
	}

	/*
	 * P2V.DSC_CXT_START_RS is only meaningful for a VF: it is issued by
	 * the owning PF on the VF's behalf. vf_num is the 0-based VF index
	 * within that PF.
	 */
	vf_id = pci_iov_vf_id(vf);
	if (vf_id < 0) {
		s->nr_replay = 0;
		return 0;
	}

	cap1 = sdxi_read64(s, SDXI_MMIO_CAP1);
	max_cxt = FIELD_GET(SDXI_MMIO_CAP1_MAX_CXT, cap1);

	/*
	 * A rewound context is started by itself with db_value 0, then
	 * write_index is written to its doorbell. Every other context
	 * stays in a range submitted with db_value 0.
	 */
	if (!s->nr_replay)
		dev_info(sdxi_dev(s),
			 "start: P2V restart vf_id=%d max_cxt=%u db_value=0\n",
			 vf_id, max_cxt);
	else
		dev_info(sdxi_dev(s),
			 "start: P2V restart vf_id=%d max_cxt=%u replay=%u\n",
			 vf_id, max_cxt, s->nr_replay);
	sdxi_debug_log_contexts(s, "before P2V");

	if (!s->nr_replay)
		ret = sdxi_pf_restart_vf_contexts(vf, vf_id, 0, max_cxt, 0);
	else
		ret = sdxi_restart_vf_contexts(s, vf, vf_id, max_cxt);
	sdxi_debug_log_contexts(s, "after P2V");
	if (ret == -ENODEV) {
		dev_dbg(sdxi_dev(s),
			"start: PF SDXI driver not bound, skipping P2V restart\n");
		return 0;
	}
	if (ret) {
		dev_warn(sdxi_dev(s), "start: P2V restart failed: %d\n", ret);
		sdxi_report_fault_state(s);
	}

	return ret;
}

static const char *sdxi_cxt_state_name(u8 state)
{
	switch (state & 0xf) {
	case CXTV_STOP_SW:
		return "STOP_SW";
	case CXTV_RUN:
		return "RUN";
	case CXTV_STOPG_SW:
		return "STOPG_SW";
	case CXTV_STOP_FN:
		return "STOP_FN";
	case CXTV_STOPG_FN:
		return "STOPG_FN";
	case CXTV_ERR_FN:
		return "ERR_FN";
	default:
		return "other";
	}
}

/* Guest driver ids: ID_TO_L2_INDEX(id) = id >> 9, ID_TO_L1_INDEX(id) = id & 0x7f. */
static u32 sdxi_guest_cxt_id(unsigned int l2, unsigned int l1)
{
	return ((u32)l2 << 9) | (l1 & 0x7f);
}

static int sdxi_read_write_index(struct device *dev, u32 pasid,
				 const struct sdxi_cxt_ctl *ctl, u64 *widx)
{
	dma_addr_t widx_dma;
	__le64 raw;
	int ret;

	widx_dma = sdxi_field_ptr(le64_to_cpu(ctl->write_index_ptr),
				  SDXI_CXT_CTL_WRITE_INDEX_PTR);
	if (!widx_dma)
		return -ENOENT;

	ret = amd_iommu_read_guest_dma(dev, pasid, widx_dma, &raw, sizeof(raw));
	if (ret)
		return ret;

	*widx = le64_to_cpu(raw);
	return 0;
}

/*
 * Re-read every valid context after the function is active again.
 * A read failure is logged and skipped so a debug walk cannot fail resume.
 */
static void sdxi_debug_log_contexts(struct sdxi_vfio_pci_device *s,
				    const char *when)
{
	struct device *dev = sdxi_dev(s);
	u32 pasid = sdxi_dma_pasid(s);
	u64 cxt_l2 = sdxi_read64(s, SDXI_MMIO_CXT_L2);
	dma_addr_t l2_dma = sdxi_field_ptr(cxt_l2, SDXI_MMIO_CXT_L2_PTR);
	struct sdxi_cxt_L2_ent *l2;
	u8 *l2_buf, *l1_buf;
	unsigned int logged = 0;
	int i;

	if (!l2_dma) {
		dev_info(dev, "debug cxt %s: no context table\n", when);
		return;
	}

	l2_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	l1_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!l2_buf || !l1_buf) {
		dev_info(dev, "debug cxt %s: allocation failed\n", when);
		goto out;
	}

	if (amd_iommu_read_guest_dma(dev, pasid, l2_dma, l2_buf, PAGE_SIZE)) {
		dev_info(dev, "debug cxt %s: L2 read failed\n", when);
		goto out;
	}

	l2 = (struct sdxi_cxt_L2_ent *)l2_buf;
	for (i = 0; i < SDXI_L2_TABLE_ENTRIES; i++) {
		struct sdxi_cxt_L1_ent *ents;
		u64 raw = le64_to_cpu(l2[i].lv01_ptr);
		dma_addr_t l1_dma;
		int j;

		if (!(raw & SDXI_CXT_L2_ENT_VL))
			continue;

		l1_dma = sdxi_field_ptr(raw, SDXI_CXT_L2_ENT_LV01_PTR);
		if (amd_iommu_read_guest_dma(dev, pasid, l1_dma, l1_buf,
					     PAGE_SIZE)) {
			dev_info(dev, "debug cxt %s: L2 %d L1 read failed\n",
				 when, i);
			continue;
		}

		ents = (struct sdxi_cxt_L1_ent *)l1_buf;
		for (j = 0; j < SDXI_L1_TABLE_ENTRIES; j++) {
			struct sdxi_cxt_ctl ctl;
			struct sdxi_cxt_sts sts;
			dma_addr_t ctl_dma, sts_dma;
			u64 ent = le64_to_cpu(ents[j].cxt_ctl_ptr);
			u64 widx = 0;
			u32 cxt_id;
			int ret, wret;

			if (!(ent & SDXI_CXT_L1_ENT_VL))
				continue;

			cxt_id = sdxi_guest_cxt_id(i, j);
			ctl_dma = sdxi_field_ptr(ent, SDXI_CXT_L1_ENT_CXT_CTL_PTR);
			ret = amd_iommu_read_guest_dma(dev, pasid, ctl_dma, &ctl,
						      sizeof(ctl));
			if (ret) {
				dev_info(dev,
					 "debug cxt %s: id %u ctl read failed: %d\n",
					 when, cxt_id, ret);
				continue;
			}

			sts_dma = sdxi_field_ptr(le64_to_cpu(ctl.cxt_sts_ptr),
						 SDXI_CXT_CTL_CXT_STS_PTR);
			if (!sts_dma) {
				dev_info(dev,
					 "debug cxt %s: id %u no status block\n",
					 when, cxt_id);
				continue;
			}
			ret = amd_iommu_read_guest_dma(dev, pasid, sts_dma, &sts,
						      sizeof(sts));
			if (ret) {
				dev_info(dev,
					 "debug cxt %s: id %u status read failed: %d\n",
					 when, cxt_id, ret);
				continue;
			}

			wret = sdxi_read_write_index(dev, pasid, &ctl, &widx);
			if (wret)
				dev_info(dev,
					 "debug cxt %s: id %u l2=%d l1=%d state=%s (%#x) read_index=%llu write_index unread (%d) p2v_db_value=0\n",
					 when, cxt_id, i, j,
					 sdxi_cxt_state_name(sts.state),
					 sts.state & 0xf,
					 le64_to_cpu(sts.read_index), wret);
			else
				dev_info(dev,
					 "debug cxt %s: id %u l2=%d l1=%d state=%s (%#x) read_index=%llu write_index=%llu p2v_db_value=0\n",
					 when, cxt_id, i, j,
					 sdxi_cxt_state_name(sts.state),
					 sts.state & 0xf,
					 le64_to_cpu(sts.read_index), widx);
			logged++;
		}
	}

	dev_info(dev, "debug cxt %s: %u context(s)\n", when, logged);
out:
	kfree(l2_buf);
	kfree(l1_buf);
}

/* Up to eight new error-log entries. The log lives in guest DMA. */
static void sdxi_debug_log_errlog(struct sdxi_vfio_pci_device *s)
{
	struct device *dev = sdxi_dev(s);
	u64 cfg = sdxi_read64(s, SDXI_MMIO_ERR_CFG);
	u64 wrt = sdxi_read64(s, SDXI_MMIO_ERR_WRT);
	u64 rd = sdxi_read64(s, SDXI_MMIO_ERR_RD);
	u32 pasid = sdxi_dma_pasid(s);
	unsigned int nent, n, i;
	dma_addr_t base;

	dev_info(dev,
		 "stop stall errlog: pasid=%u cfg=%#llx en=%llu sz=%llu wrt=%llu rd=%llu\n",
		 pasid, cfg,
		 (u64)FIELD_GET(SDXI_MMIO_ERR_CFG_EN, cfg),
		 (u64)FIELD_GET(SDXI_MMIO_ERR_CFG_SZ, cfg),
		 wrt, rd);
	if (!(cfg & SDXI_MMIO_ERR_CFG_EN) || wrt <= rd)
		return;

	nent = FIELD_GET(SDXI_MMIO_ERR_CFG_SZ, cfg) << 6;
	if (!nent)
		nent = 64;
	base = sdxi_field_ptr(cfg, SDXI_MMIO_ERR_CFG_PTR);
	n = min_t(u64, wrt - rd, 8);
	for (i = 0; i < n; i++) {
		u8 raw[64];
		u64 idx = rd + i;
		u64 w0, w1;
		int ret;

		ret = amd_iommu_read_guest_dma(dev, pasid,
					       base + (idx % nent) * sizeof(raw),
					       raw, sizeof(raw));
		if (ret) {
			dev_info(dev,
				 "stop stall errlog[%llu]: read failed: %d\n",
				 idx, ret);
			break;
		}
		w0 = get_unaligned_le64(raw);
		w1 = get_unaligned_le64(raw + 8);
		dev_info(dev,
			 "stop stall errlog[%llu]: vl=%u re=%llu step=%llu sub=%llu cv=%u div=%u cxt=%llu dsc=%#llx class=%#x\n",
			 idx,
			 !!(w0 & BIT_ULL(0)),
			 (u64)FIELD_GET(GENMASK_ULL(46, 44), w0),
			 (u64)FIELD_GET(GENMASK_ULL(13, 8), w0),
			 (u64)FIELD_GET(GENMASK_ULL(43, 40), w0),
			 !!(w0 & BIT_ULL(32)),
			 !!(w0 & BIT_ULL(33)),
			 (u64)FIELD_GET(GENMASK_ULL(63, 48), w0),
			 w1,
			 get_unaligned_le16(raw + 44));
	}
}

static void sdxi_debug_log_stop_stall(struct sdxi_vfio_pci_device *s)
{
	sdxi_debug_log_regs(s, "stop stall");
	sdxi_debug_log_contexts(s, "stop stall");
	sdxi_debug_log_errlog(s);
}

static int sdxi_snap_one_context(struct device *dev, u32 pasid,
				 dma_addr_t ctl_dma, struct sdxi_mig_blob *b,
				 u32 max_cxts, u32 cxt_id)
{
	struct sdxi_mig_cxt_sts *rec;
	struct sdxi_cxt_ctl ctl;
	struct sdxi_cxt_sts sts;
	dma_addr_t sts_dma;
	u64 widx = 0;
	u32 nr;
	int ret, wret;

	static_assert(sizeof(sts) == sizeof(rec->sts));

	ret = amd_iommu_read_guest_dma(dev, pasid, ctl_dma, &ctl, sizeof(ctl));
	if (ret)
		return ret;

	sts_dma = sdxi_field_ptr(le64_to_cpu(ctl.cxt_sts_ptr),
				 SDXI_CXT_CTL_CXT_STS_PTR);
	if (!sts_dma)
		return 0;

	ret = amd_iommu_read_guest_dma(dev, pasid, sts_dma, &sts, sizeof(sts));
	if (ret)
		return ret;

	nr = le32_to_cpu(b->nr_cxt);
	if (nr >= max_cxts)
		return -ENOSPC;

	rec = &b->cxt[nr];
	rec->dma = cpu_to_le64(sts_dma);
	memcpy(rec->sts, &sts, sizeof(sts));
	b->nr_cxt = cpu_to_le32(nr + 1);

	wret = sdxi_read_write_index(dev, pasid, &ctl, &widx);
	if (wret)
		dev_info(dev,
			 "context-status save: id %u dma %pad read_index %llu write_index unread (%d) state %s (%#x)\n",
			 cxt_id, &sts_dma, le64_to_cpu(sts.read_index), wret,
			 sdxi_cxt_state_name(sts.state), sts.state & 0xf);
	else
		dev_info(dev,
			 "context-status save: id %u dma %pad read_index %llu write_index %llu state %s (%#x)\n",
			 cxt_id, &sts_dma, le64_to_cpu(sts.read_index), widx,
			 sdxi_cxt_state_name(sts.state), sts.state & 0xf);
	return 0;
}

static int sdxi_snap_l1(struct device *dev, u32 pasid, dma_addr_t l1_dma,
			u8 *l1_buf, struct sdxi_mig_blob *b, u32 max_cxts,
			unsigned int l2)
{
	struct sdxi_cxt_L1_ent *ents = (struct sdxi_cxt_L1_ent *)l1_buf;
	int i, ret;

	ret = amd_iommu_read_guest_dma(dev, pasid, l1_dma, l1_buf, PAGE_SIZE);
	if (ret)
		return ret;

	for (i = 0; i < SDXI_L1_TABLE_ENTRIES; i++) {
		u64 raw = le64_to_cpu(ents[i].cxt_ctl_ptr);
		dma_addr_t ctl;

		if (!(raw & SDXI_CXT_L1_ENT_VL))
			continue;

		ctl = sdxi_field_ptr(raw, SDXI_CXT_L1_ENT_CXT_CTL_PTR);
		ret = sdxi_snap_one_context(dev, pasid, ctl, b, max_cxts,
					    sdxi_guest_cxt_id(l2, i));
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Copy every valid context-status block into the blob. The function is
 * already at GSV_STOP, so read_idx is the post-stop value. A miss fails
 * the save: resuming without that block would keep the precopy page.
 */
static int sdxi_snapshot_context_status(struct sdxi_vfio_pci_device *s,
					struct sdxi_mig_blob *b, u32 max_cxts)
{
	struct device *dev = sdxi_dev(s);
	u32 pasid = sdxi_dma_pasid(s);
	u64 cxt_l2 = sdxi_read64(s, SDXI_MMIO_CXT_L2);
	dma_addr_t l2_dma = sdxi_field_ptr(cxt_l2, SDXI_MMIO_CXT_L2_PTR);
	struct sdxi_cxt_L2_ent *l2;
	u8 *l2_buf, *l1_buf;
	int i, ret = 0;

	b->nr_cxt = 0;
	if (!l2_dma)
		return 0;

	l2_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	l1_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!l2_buf || !l1_buf) {
		ret = -ENOMEM;
		goto out;
	}

	ret = amd_iommu_read_guest_dma(dev, pasid, l2_dma, l2_buf, PAGE_SIZE);
	if (ret)
		goto out;

	l2 = (struct sdxi_cxt_L2_ent *)l2_buf;
	for (i = 0; i < SDXI_L2_TABLE_ENTRIES; i++) {
		u64 raw = le64_to_cpu(l2[i].lv01_ptr);
		dma_addr_t l1_dma;

		if (!(raw & SDXI_CXT_L2_ENT_VL))
			continue;

		l1_dma = sdxi_field_ptr(raw, SDXI_CXT_L2_ENT_LV01_PTR);
		ret = sdxi_snap_l1(dev, pasid, l1_dma, l1_buf, b, max_cxts, i);
		if (ret)
			goto out;
	}

	dev_info(dev, "context-status save: %u block(s) (pasid %u)\n",
		 le32_to_cpu(b->nr_cxt), pasid);
out:
	kfree(l2_buf);
	kfree(l1_buf);
	return ret;
}

static int sdxi_restore_context_status(struct sdxi_vfio_pci_device *s,
				       const struct sdxi_mig_blob *b)
{
	struct device *dev = sdxi_dev(s);
	u32 pasid = sdxi_dma_pasid(s);
	u32 nr = le32_to_cpu(b->nr_cxt);
	u32 i;
	int ret;

	s->nr_replay = 0;
	for (i = 0; i < nr; i++) {
		const struct sdxi_mig_cxt_sts *rec = &b->cxt[i];
		dma_addr_t dma = le64_to_cpu(rec->dma);
		u64 doorbell = le64_to_cpu(rec->replay_db);

		if (!dma)
			return -EINVAL;

		if (doorbell) {
			u32 id = le32_to_cpu(rec->replay_id);

			if (s->nr_replay >= SDXI_REPLAY_DB_MAX) {
				dev_err(dev, "context-status restore: too many replay doorbells\n");
				return -ENOSPC;
			}
			if (id > U16_MAX) {
				dev_err(dev, "context-status restore: replay id %u is not a context id\n",
					id);
				return -EINVAL;
			}
			s->replay[s->nr_replay].id = id;
			s->replay[s->nr_replay].db = doorbell;
			s->nr_replay++;
			dev_info(dev,
				 "context-status restore: id %u replay doorbell %llu\n",
				 id, doorbell);
		}

		ret = amd_iommu_write_guest_dma(dev, pasid, dma, rec->sts,
						sizeof(rec->sts));
		if (ret) {
			dev_err(dev, "context-status restore: dma %pad: %pe\n",
				&dma, ERR_PTR(ret));
			return ret;
		}
	}

	if (nr)
		dev_info(dev, "context-status restore: wrote %u block(s) (pasid %u)\n",
			 nr, pasid);
	return 0;
}

static struct sdxi_mig_csb *sdxi_mig_csbs(struct sdxi_mig_blob *b)
{
	return (struct sdxi_mig_csb *)((u8 *)b + sizeof(*b) +
		le32_to_cpu(b->nr_cxt) * sizeof(b->cxt[0]));
}

static size_t sdxi_mig_blob_len(const struct sdxi_mig_blob *b)
{
	return sizeof(*b) +
	       le32_to_cpu(b->nr_cxt) * sizeof(b->cxt[0]) +
	       le32_to_cpu(b->nr_csb) * sizeof(struct sdxi_mig_csb);
}

static int sdxi_record_retired_csb(struct sdxi_mig_blob *b, u32 max_csb,
				   dma_addr_t csb, u64 signal)
{
	struct sdxi_mig_csb *slot = sdxi_mig_csbs(b);
	u32 nr = le32_to_cpu(b->nr_csb);
	u32 i;

	for (i = 0; i < nr; i++) {
		if (le64_to_cpu(slot[i].dma) == csb)
			return 0;
	}
	if (nr >= max_csb)
		return -ENOSPC;

	slot[nr].dma = cpu_to_le64(csb);
	slot[nr].signal = cpu_to_le64(signal);
	b->nr_csb = cpu_to_le32(nr + 1);
	return 0;
}

/*
 * Move the saved read_index back to desc_index. The live status block
 * stays as the device left it; resume writes this copy on the destination.
 */
static int sdxi_rewind_read_index(struct device *dev, struct sdxi_mig_blob *b,
				  dma_addr_t sts_dma, u32 cxt_id,
				  u64 desc_index, u64 doorbell)
{
	u32 nr = le32_to_cpu(b->nr_cxt);
	u32 i;

	for (i = 0; i < nr; i++) {
		struct sdxi_mig_cxt_sts *rec = &b->cxt[i];
		u8 *rdp;
		u64 cur;

		if (le64_to_cpu(rec->dma) != sts_dma)
			continue;

		rdp = rec->sts + offsetof(struct sdxi_cxt_sts, read_index);
		cur = get_unaligned_le64(rdp);
		if (desc_index >= cur) {
			dev_warn(dev,
				 "completion save: id %u desc %llu is not before read_index %llu\n",
				 cxt_id, desc_index, cur);
			return 0;
		}
		put_unaligned_le64(desc_index, rdp);
		rec->replay_db = cpu_to_le64(doorbell);
		rec->replay_id = cpu_to_le32(cxt_id);
		dev_warn(dev,
			 "completion save: id %u rewinding read_index %llu -> %llu for incomplete desc, signal left in place, doorbell %llu\n",
			 cxt_id, cur, desc_index, doorbell);
		return 0;
	}

	dev_err(dev,
		"completion save: id %u status block %pad is not in the snapshot\n",
		cxt_id, &sts_dma);
	return -EIO;
}

/*
 * A descriptor the device has retired (index < read_index) can still
 * have a non-zero completion signal. When the ring is caught up
 * (read_index == write_index) that store was dropped: rewind the saved
 * read_index to the descriptor and leave the signal, so resume replays
 * it and the guest's decrement wait still holds. Otherwise record the
 * block so resume can write 0. A signal shared with a descriptor the
 * device has not retired is left alone.
 */
static int sdxi_snap_retired_csbs(struct device *dev, u32 pasid,
				  dma_addr_t ctl_dma, u32 cxt_id,
				  struct sdxi_mig_blob *b, u32 max_csb)
{
	struct sdxi_csb_note {
		dma_addr_t dma;
		u64 signal;
		u64 desc_index;
		bool unretired;
	} notes[16];
	struct sdxi_cxt_ctl ctl;
	struct sdxi_cxt_sts sts;
	struct sdxi_desc *descs = NULL;
	dma_addr_t ring, sts_dma;
	size_t bytes;
	u64 widx, read_index, idx, start;
	u32 entries, nnotes = 0;
	int ret;

	ret = amd_iommu_read_guest_dma(dev, pasid, ctl_dma, &ctl, sizeof(ctl));
	if (ret)
		return ret;
	if (!(le64_to_cpu(ctl.ds_ring_ptr) & SDXI_CXT_CTL_VL))
		return 0;

	entries = le32_to_cpu(ctl.ds_ring_sz);
	ring = sdxi_field_ptr(le64_to_cpu(ctl.ds_ring_ptr),
			      SDXI_CXT_CTL_DS_RING_PTR);
	sts_dma = sdxi_field_ptr(le64_to_cpu(ctl.cxt_sts_ptr),
				 SDXI_CXT_CTL_CXT_STS_PTR);
	if (!entries || !ring || !sts_dma)
		return 0;
	if (entries > 65536) {
		dev_err(dev, "completion save: context %u ring size %u is not usable\n",
			cxt_id, entries);
		return -EIO;
	}

	ret = sdxi_read_write_index(dev, pasid, &ctl, &widx);
	if (ret || !widx)
		return ret;
	ret = amd_iommu_read_guest_dma(dev, pasid, sts_dma, &sts, sizeof(sts));
	if (ret)
		return ret;
	read_index = le64_to_cpu(sts.read_index);

	start = widx > entries ? widx - entries : 0;
	bytes = array_size(entries, sizeof(*descs));
	descs = kvmalloc(bytes, GFP_KERNEL);
	if (!descs)
		return -ENOMEM;
	ret = amd_iommu_read_guest_dma(dev, pasid, ring, descs, bytes);
	if (ret)
		goto out;

	for (idx = start; idx < widx; idx++) {
		struct sdxi_desc *desc = &descs[idx % entries];
		u64 raw = le64_to_cpu(desc->generic.csb_ptr);
		dma_addr_t csb;
		__le64 signal;
		u64 value;
		u32 n;
		bool retired = idx < read_index;

		if (raw & SDXI_DSC_NP)
			continue;
		csb = sdxi_field_ptr(raw, SDXI_DSC_CSB_PTR);
		if (!csb)
			continue;

		for (n = 0; n < nnotes; n++) {
			if (notes[n].dma == csb)
				break;
		}
		if (n == nnotes) {
			ret = amd_iommu_read_guest_dma(dev, pasid, csb, &signal,
						      sizeof(signal));
			if (ret)
				goto out;
			value = le64_to_cpu(signal);
			if (!value)
				continue;
			if (nnotes >= ARRAY_SIZE(notes)) {
				dev_err(dev, "completion save: context %u has too many pending completions\n",
					cxt_id);
				ret = -ENOSPC;
				goto out;
			}
			notes[nnotes].dma = csb;
			notes[nnotes].signal = value;
			notes[nnotes].desc_index = idx;
			notes[nnotes].unretired = !retired;
			nnotes++;
			continue;
		}
		if (!retired)
			notes[n].unretired = true;
		else
			notes[n].desc_index = idx;
	}

	/*
	 * Caught-up ring, signal still outstanding: the guest is waiting
	 * for the decrement. Replaying from the earliest such descriptor
	 * leaves every noted signal alone and records write_index so resume
	 * can write it to the context doorbell after CXT_START_RS.
	 */
	if (read_index == widx && nnotes) {
		u64 replay = notes[0].desc_index;

		for (idx = 0; idx < nnotes; idx++) {
			struct sdxi_desc *desc =
				&descs[notes[idx].desc_index % entries];
			u32 opcode = le32_to_cpu(desc->generic.opcode);

			dev_warn(dev,
				 "completion save: id %u incomplete desc %llu csb %pad signal 0x%llx with read_index %llu == write_index %llu vl %u\n",
				 cxt_id, notes[idx].desc_index, &notes[idx].dma,
				 notes[idx].signal, read_index, widx,
				 !!(opcode & SDXI_DSC_VL));
			if (notes[idx].desc_index < replay)
				replay = notes[idx].desc_index;
		}
		ret = sdxi_rewind_read_index(dev, b, sts_dma, cxt_id, replay,
					     widx);
		goto out;
	}

	for (idx = 0; idx < nnotes; idx++) {
		if (notes[idx].unretired) {
			dev_info(dev,
				 "completion save: id %u csb %pad signal 0x%llx still covers an unretired descriptor\n",
				 cxt_id, &notes[idx].dma, notes[idx].signal);
			continue;
		}
		dev_info(dev,
			 "completion save: id %u desc %llu csb %pad signal 0x%llx read_index %llu write_index %llu\n",
			 cxt_id, notes[idx].desc_index, &notes[idx].dma,
			 notes[idx].signal, read_index, widx);
		ret = sdxi_record_retired_csb(b, max_csb, notes[idx].dma,
					      notes[idx].signal);
		if (ret) {
			dev_err(dev, "completion save: no room for context %u csb %pad\n",
				cxt_id, &notes[idx].dma);
			goto out;
		}
	}
	ret = 0;
out:
	kvfree(descs);
	return ret;
}

static int sdxi_snapshot_retired_csbs(struct sdxi_vfio_pci_device *s,
				      struct sdxi_mig_blob *b, u32 max_csb)
{
	struct device *dev = sdxi_dev(s);
	u32 pasid = sdxi_dma_pasid(s);
	u64 cxt_l2 = sdxi_read64(s, SDXI_MMIO_CXT_L2);
	dma_addr_t l2_dma = sdxi_field_ptr(cxt_l2, SDXI_MMIO_CXT_L2_PTR);
	struct sdxi_cxt_L2_ent *l2;
	u8 *l2_buf, *l1_buf;
	int i, ret = 0;

	b->nr_csb = 0;
	if (!l2_dma)
		return 0;

	l2_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	l1_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!l2_buf || !l1_buf) {
		ret = -ENOMEM;
		goto out;
	}

	ret = amd_iommu_read_guest_dma(dev, pasid, l2_dma, l2_buf, PAGE_SIZE);
	if (ret)
		goto out;

	l2 = (struct sdxi_cxt_L2_ent *)l2_buf;
	for (i = 0; i < SDXI_L2_TABLE_ENTRIES && !ret; i++) {
		struct sdxi_cxt_L1_ent *ents;
		u64 raw = le64_to_cpu(l2[i].lv01_ptr);
		dma_addr_t l1_dma;
		int j;

		if (!(raw & SDXI_CXT_L2_ENT_VL))
			continue;

		l1_dma = sdxi_field_ptr(raw, SDXI_CXT_L2_ENT_LV01_PTR);
		ret = amd_iommu_read_guest_dma(dev, pasid, l1_dma, l1_buf,
					      PAGE_SIZE);
		if (ret)
			goto out;

		ents = (struct sdxi_cxt_L1_ent *)l1_buf;
		for (j = 0; j < SDXI_L1_TABLE_ENTRIES && !ret; j++) {
			u64 ent = le64_to_cpu(ents[j].cxt_ctl_ptr);
			dma_addr_t ctl_dma;

			if (!(ent & SDXI_CXT_L1_ENT_VL))
				continue;

			ctl_dma = sdxi_field_ptr(ent, SDXI_CXT_L1_ENT_CXT_CTL_PTR);
			ret = sdxi_snap_retired_csbs(dev, pasid, ctl_dma,
						    sdxi_guest_cxt_id(i, j),
						    b, max_csb);
		}
	}
	if (!ret)
		dev_info(dev, "completion save: %u block(s)\n",
			 le32_to_cpu(b->nr_csb));
out:
	kfree(l2_buf);
	kfree(l1_buf);
	return ret;
}

static int sdxi_restore_retired_csbs(struct sdxi_vfio_pci_device *s,
				     const struct sdxi_mig_blob *b)
{
	struct device *dev = sdxi_dev(s);
	u32 pasid = sdxi_dma_pasid(s);
	u32 nr = le32_to_cpu(b->nr_csb);
	const struct sdxi_mig_csb *slot =
		(const struct sdxi_mig_csb *)((const u8 *)b + sizeof(*b) +
		le32_to_cpu(b->nr_cxt) * sizeof(b->cxt[0]));
	u32 i;

	for (i = 0; i < nr; i++) {
		dma_addr_t dma = le64_to_cpu(slot[i].dma);
		__le64 zero = 0;
		int ret;

		if (!dma)
			return -EINVAL;
		ret = amd_iommu_write_guest_dma(dev, pasid, dma, &zero,
						sizeof(zero));
		if (ret) {
			dev_err(dev, "completion restore: csb %pad: %pe\n",
				&dma, ERR_PTR(ret));
			return ret;
		}
		dev_info(dev, "completion restore: csb %pad signal 0x%llx -> 0\n",
			 &dma, le64_to_cpu(slot[i].signal));
	}
	return 0;
}

static void sdxi_save_regs(struct sdxi_vfio_pci_device *s,
			   struct sdxi_mig_blob *b)
{
	b->magic   = cpu_to_le32(SDXI_MIG_MAGIC);
	b->version = cpu_to_le32(SDXI_MIG_VERSION);
	b->cap0    = cpu_to_le64(sdxi_read64(s, SDXI_MMIO_CAP0));
	b->cap1    = cpu_to_le64(sdxi_read64(s, SDXI_MMIO_CAP1));
	/* FN_GSR is a write-only command field; never replay it. */
	b->ctl0    = cpu_to_le64(sdxi_read64(s, SDXI_MMIO_CTL0) & ~SDXI_MMIO_CTL0_FN_GSR);
	b->ctl2    = cpu_to_le64(sdxi_read64(s, SDXI_MMIO_CTL2));
	b->cxt_l2  = cpu_to_le64(sdxi_read64(s, SDXI_MMIO_CXT_L2));
	b->rkey    = cpu_to_le64(sdxi_read64(s, SDXI_MMIO_RKEY));
	b->err_cfg = cpu_to_le64(sdxi_read64(s, SDXI_MMIO_ERR_CFG));
	b->err_ctl = cpu_to_le64(sdxi_read64(s, SDXI_MMIO_ERR_CTL));
	b->err_wrt = cpu_to_le64(sdxi_read64(s, SDXI_MMIO_ERR_WRT));
	b->err_rd  = cpu_to_le64(sdxi_read64(s, SDXI_MMIO_ERR_RD));
	b->nr_cxt  = 0;
	b->nr_csb  = 0;
}

/*
 * Fields with an explicit rule in sdxi_caps_compatible(). Any other CAP
 * bit, including reserved and implementation-defined bits, must still match.
 * SFUNC is the VF requester ID and is not a capability.
 */
#define SDXI_CAP0_RULED (SDXI_MMIO_CAP0_SFUNC | SDXI_MMIO_CAP0_VF | \
			 SDXI_MMIO_CAP0_CS_CAP | SDXI_MMIO_CAP0_DB_STRIDE | \
			 SDXI_MMIO_CAP0_MAX_DS_RING_SZ | \
			 SDXI_MMIO_CAP0_MAX_RKEY_SZ)
#define SDXI_CAP1_RULED (SDXI_MMIO_CAP1_MAX_BUFFER | SDXI_MMIO_CAP1_RKEY_CAP | \
			 SDXI_MMIO_CAP1_RM | SDXI_MMIO_CAP1_MMIO64 | \
			 SDXI_MMIO_CAP1_MAX_ERRLOG_SZ | \
			 SDXI_MMIO_CAP1_MAX_AKEY_SZ | SDXI_MMIO_CAP1_MAX_CXT | \
			 SDXI_MMIO_CAP1_OPB_000_CAP)

/* 10b supports both completion modes. 01b is reserved. */
static bool sdxi_cs_cap_hosts(u8 src, u8 dst)
{
	if (src > 3 || dst > 3 || src == 1 || dst == 1)
		return false;
	if (src == 2)
		return dst == 2;
	return dst == src || dst == 2;
}

/*
 * §4.1.8 step 1.a: the destination must host the saved content. Ceilings
 * are checked against the programmed CTL2, RKEY, and error-log size.
 * max_ds_ring_sz is a source ceiling; per-ring sizes are not in the blob.
 * Error-log size is 2**(sz+12); the CAP1 ceiling is 2**(max_errlog_sz+23).
 */
static bool sdxi_caps_compatible(u64 src_cap0, u64 dst_cap0,
				 u64 src_cap1, u64 dst_cap1,
				 u64 ctl2, u64 rkey, u64 err_cfg)
{
	u8 err_sz, err_max;

	if ((src_cap0 ^ dst_cap0) & ~SDXI_CAP0_RULED)
		return false;
	if ((src_cap1 ^ dst_cap1) & ~SDXI_CAP1_RULED)
		return false;

	if (FIELD_GET(SDXI_MMIO_CAP0_VF, src_cap0) !=
	    FIELD_GET(SDXI_MMIO_CAP0_VF, dst_cap0))
		return false;
	if (FIELD_GET(SDXI_MMIO_CAP0_DB_STRIDE, src_cap0) !=
	    FIELD_GET(SDXI_MMIO_CAP0_DB_STRIDE, dst_cap0))
		return false;
	if (!sdxi_cs_cap_hosts(FIELD_GET(SDXI_MMIO_CAP0_CS_CAP, src_cap0),
			       FIELD_GET(SDXI_MMIO_CAP0_CS_CAP, dst_cap0)))
		return false;
	if (FIELD_GET(SDXI_MMIO_CAP0_MAX_DS_RING_SZ, dst_cap0) <
	    FIELD_GET(SDXI_MMIO_CAP0_MAX_DS_RING_SZ, src_cap0))
		return false;

	if ((src_cap1 & SDXI_MMIO_CAP1_RM) != (dst_cap1 & SDXI_MMIO_CAP1_RM))
		return false;
	if ((src_cap1 & SDXI_MMIO_CAP1_MMIO64) &&
	    !(dst_cap1 & SDXI_MMIO_CAP1_MMIO64))
		return false;

	if (FIELD_GET(SDXI_MMIO_CTL2_MAX_BUFFER, ctl2) >
	    FIELD_GET(SDXI_MMIO_CAP1_MAX_BUFFER, dst_cap1))
		return false;
	if (FIELD_GET(SDXI_MMIO_CTL2_MAX_AKEY_SZ, ctl2) >
	    FIELD_GET(SDXI_MMIO_CAP1_MAX_AKEY_SZ, dst_cap1))
		return false;
	if (FIELD_GET(SDXI_MMIO_CTL2_MAX_CXT, ctl2) >
	    FIELD_GET(SDXI_MMIO_CAP1_MAX_CXT, dst_cap1))
		return false;
	if (ctl2 & SDXI_MMIO_CTL2_OPB_000_AVL & ~dst_cap1)
		return false;

	if ((rkey & SDXI_MMIO_RKEY_EN) &&
	    (!(dst_cap1 & SDXI_MMIO_CAP1_RKEY_CAP) ||
	     FIELD_GET(SDXI_MMIO_RKEY_SZ, rkey) >
	     FIELD_GET(SDXI_MMIO_CAP0_MAX_RKEY_SZ, dst_cap0)))
		return false;

	err_sz = FIELD_GET(SDXI_MMIO_ERR_CFG_SZ, err_cfg);
	err_max = FIELD_GET(SDXI_MMIO_CAP1_MAX_ERRLOG_SZ, dst_cap1);
	if (err_sz > err_max + 11)
		return false;

	return true;
}

/*
 * The device clears VL when it retires a descriptor. A rewound index
 * points at that slot, so set VL again before P2V or the device will
 * not fetch it. The final guest RAM copy is already done by the time
 * this runs.
 */
static int sdxi_set_replay_desc_vl(struct device *dev, u32 pasid,
				   dma_addr_t ring, u32 entries, u64 idx)
{
	dma_addr_t slot = ring + (idx % entries) * sizeof(struct sdxi_desc);
	__le32 opcode;
	u32 raw;
	int ret;

	ret = amd_iommu_read_guest_dma(dev, pasid, slot, &opcode, sizeof(opcode));
	if (ret)
		return ret;

	raw = le32_to_cpu(opcode);
	if (raw & SDXI_DSC_VL) {
		dev_info(dev, "replay desc %llu vl already set opcode %#x\n",
			 idx, raw);
		return 0;
	}

	raw |= SDXI_DSC_VL;
	opcode = cpu_to_le32(raw);
	ret = amd_iommu_write_guest_dma(dev, pasid, slot, &opcode, sizeof(opcode));
	if (ret)
		return ret;

	dev_warn(dev, "replay desc %llu set vl opcode %#x\n", idx, raw);
	return 0;
}

static int sdxi_restore_replay_vl(struct sdxi_vfio_pci_device *s,
				  const struct sdxi_mig_blob *b)
{
	struct device *dev = sdxi_dev(s);
	u32 pasid = sdxi_dma_pasid(s);
	u32 nr = le32_to_cpu(b->nr_cxt);
	u64 cxt_l2 = sdxi_read64(s, SDXI_MMIO_CXT_L2);
	dma_addr_t l2_dma = sdxi_field_ptr(cxt_l2, SDXI_MMIO_CXT_L2_PTR);
	u32 i;

	if (!s->nr_replay)
		return 0;
	if (!l2_dma) {
		dev_err(dev, "replay: no context table\n");
		return -EINVAL;
	}

	for (i = 0; i < nr; i++) {
		const struct sdxi_mig_cxt_sts *rec = &b->cxt[i];
		struct sdxi_cxt_L2_ent l2ent;
		struct sdxi_cxt_L1_ent l1ent;
		struct sdxi_cxt_ctl ctl;
		dma_addr_t l1_dma, ctl_dma, ring;
		u64 end = le64_to_cpu(rec->replay_db);
		u64 start, idx, raw;
		u32 id, entries, l2, l1;
		int ret;

		if (!end)
			continue;

		id = le32_to_cpu(rec->replay_id);
		start = get_unaligned_le64(rec->sts +
					   offsetof(struct sdxi_cxt_sts, read_index));
		if (start >= end) {
			dev_err(dev, "replay: id %u read_index %llu is not before write_index %llu\n",
				id, start, end);
			return -EINVAL;
		}

		l2 = id >> 9;
		l1 = id & 0x7f;
		if (l2 >= SDXI_L2_TABLE_ENTRIES) {
			dev_err(dev, "replay: id %u is not a context id\n", id);
			return -EINVAL;
		}

		ret = amd_iommu_read_guest_dma(dev, pasid,
					       l2_dma + l2 * sizeof(l2ent),
					       &l2ent, sizeof(l2ent));
		if (ret)
			return ret;
		raw = le64_to_cpu(l2ent.lv01_ptr);
		if (!(raw & SDXI_CXT_L2_ENT_VL)) {
			dev_err(dev, "replay: id %u l2 entry is not valid\n", id);
			return -EINVAL;
		}
		l1_dma = sdxi_field_ptr(raw, SDXI_CXT_L2_ENT_LV01_PTR);

		ret = amd_iommu_read_guest_dma(dev, pasid,
					       l1_dma + l1 * sizeof(l1ent),
					       &l1ent, sizeof(l1ent));
		if (ret)
			return ret;
		raw = le64_to_cpu(l1ent.cxt_ctl_ptr);
		if (!(raw & SDXI_CXT_L1_ENT_VL)) {
			dev_err(dev, "replay: id %u l1 entry is not valid\n", id);
			return -EINVAL;
		}
		ctl_dma = sdxi_field_ptr(raw, SDXI_CXT_L1_ENT_CXT_CTL_PTR);

		ret = amd_iommu_read_guest_dma(dev, pasid, ctl_dma, &ctl,
					       sizeof(ctl));
		if (ret)
			return ret;
		if (!(le64_to_cpu(ctl.ds_ring_ptr) & SDXI_CXT_CTL_VL)) {
			dev_err(dev, "replay: id %u descriptor ring is not valid\n",
				id);
			return -EINVAL;
		}
		ring = sdxi_field_ptr(le64_to_cpu(ctl.ds_ring_ptr),
				      SDXI_CXT_CTL_DS_RING_PTR);
		entries = le32_to_cpu(ctl.ds_ring_sz);
		if (!ring || !entries || entries > 65536) {
			dev_err(dev, "replay: id %u ring is not usable\n", id);
			return -EINVAL;
		}
		if (end - start > entries) {
			dev_err(dev, "replay: id %u range %llu..%llu exceeds ring %u\n",
				id, start, end, entries);
			return -EINVAL;
		}

		for (idx = start; idx < end; idx++) {
			ret = sdxi_set_replay_desc_vl(dev, pasid, ring, entries,
						      idx);
			if (ret) {
				dev_err(dev, "replay: id %u desc %llu: %pe\n",
					id, idx, ERR_PTR(ret));
				return ret;
			}
		}
	}
	return 0;
}

static int sdxi_restore_regs(struct sdxi_vfio_pci_device *s,
			     const struct sdxi_mig_blob *b)
{
	u64 dst_cap0 = sdxi_read64(s, SDXI_MMIO_CAP0);
	u64 dst_cap1 = sdxi_read64(s, SDXI_MMIO_CAP1);
	u64 src_cap0 = le64_to_cpu(b->cap0);
	u64 src_cap1 = le64_to_cpu(b->cap1);
	u64 ctl2 = le64_to_cpu(b->ctl2);
	u64 rkey = le64_to_cpu(b->rkey);
	u64 err_cfg;
	int ret;

	if (le32_to_cpu(b->magic) != SDXI_MIG_MAGIC) {
		dev_err(sdxi_dev(s), "restore: bad magic 0x%x\n",
			le32_to_cpu(b->magic));
		return -EINVAL;
	}
	if (le32_to_cpu(b->version) != SDXI_MIG_VERSION) {
		dev_err(sdxi_dev(s), "restore: unsupported version %u\n",
			le32_to_cpu(b->version));
		return -EOPNOTSUPP;
	}

	/*
	 * §4.1.8 step 1.a. SFUNC is the destination VF's requester ID.
	 * sdxi_start() reads that live value for the P2V restart.
	 */
	err_cfg = le64_to_cpu(b->err_cfg);
	if (!sdxi_caps_compatible(src_cap0, dst_cap0, src_cap1, dst_cap1,
				  ctl2, rkey, err_cfg)) {
		dev_err(sdxi_dev(s),
			"restore: capability mismatch (src cap0=0x%llx cap1=0x%llx, dst cap0=0x%llx cap1=0x%llx)\n",
			src_cap0, src_cap1, dst_cap0, dst_cap1);
		return -EOPNOTSUPP;
	}

	/*
	 * Restore ordering: CTL2 (limits) before CTL0; table pointers
	 * before the rest. Per §9, MMIO_CXT_L2 is only writable while
	 * fn_gsv == GSV_STOP, which is precisely the state VFIO has us
	 * in here. CTL0 is written last with FN_GSR cleared so the
	 * function stays stopped; sdxi_start() issues GSRV_ACTIVE.
	 *
	 * §9.3: ERR_WRT is only writable when error logging is disabled
	 * (ERR_CFG.en=0 or ERR_STS.err=1). Write ERR_CFG with en=0
	 * first, replay the head/tail indexes, then commit the saved
	 * ERR_CFG value (which may have en=1).
	 */
	sdxi_debug_log_regs(s, "before write");
	dev_info(sdxi_dev(s),
		 "debug regs blob: ctl0=0x%llx ctl2=0x%llx cxt_l2=0x%llx rkey=0x%llx err_ctl=0x%llx err_cfg=0x%llx\n",
		 le64_to_cpu(b->ctl0), ctl2,
		 le64_to_cpu(b->cxt_l2), rkey,
		 le64_to_cpu(b->err_ctl), err_cfg);

	sdxi_write64(s, SDXI_MMIO_CTL2,    ctl2);
	sdxi_write64(s, SDXI_MMIO_CXT_L2,  le64_to_cpu(b->cxt_l2));
	sdxi_write64(s, SDXI_MMIO_RKEY,    rkey);
	sdxi_write64(s, SDXI_MMIO_ERR_CFG, err_cfg & ~SDXI_MMIO_ERR_CFG_EN);
	sdxi_write64(s, SDXI_MMIO_ERR_WRT, le64_to_cpu(b->err_wrt));
	sdxi_write64(s, SDXI_MMIO_ERR_RD,  le64_to_cpu(b->err_rd));
	sdxi_write64(s, SDXI_MMIO_ERR_CFG, err_cfg);
	sdxi_write64(s, SDXI_MMIO_ERR_CTL, le64_to_cpu(b->err_ctl));
	sdxi_write64(s, SDXI_MMIO_CTL0,    le64_to_cpu(b->ctl0));
	sdxi_debug_log_regs(s, "after write");

	ret = sdxi_restore_context_status(s, b);
	if (ret)
		return ret;
	ret = sdxi_restore_replay_vl(s, b);
	if (ret)
		return ret;
	return sdxi_restore_retired_csbs(s, b);
}

static int sdxi_mig_release(struct inode *inode, struct file *filp)
{
	struct sdxi_mig_file *m = filp->private_data;

	mutex_destroy(&m->lock);
	kvfree(m->blob);
	kfree(m);
	return 0;
}

/*
 * copy_{to,from}_user() may fault and take mmap_lock. A BAR fault takes
 * memory_lock under mmap_lock, and VFIO_DEVICE_RESET takes state_mutex from
 * reset_done() while holding memory_lock. Holding m->lock or state_mutex
 * across the user copy closes an mmap_lock cycle, so snapshot under the
 * mutex and copy only after it is released.
 */
static ssize_t sdxi_save_read(struct file *filp, char __user *buf,
			      size_t len, loff_t *pos)
{
	struct sdxi_mig_file *m = filp->private_data;
	unsigned long missed;
	void *bounce;
	loff_t off;
	size_t n;

	mutex_lock(&m->lock);
	if (m->precopy && !m->finalized) {
		int early = m->pos == 0 ? -ENOMSG : 0;

		mutex_unlock(&m->lock);
		return early;
	}
	if (!m->finalized) {
		mutex_unlock(&m->lock);
		return -EINVAL;
	}
	if (m->pos < 0) {
		mutex_unlock(&m->lock);
		return -EINVAL;
	}
	if (!len || (size_t)m->pos >= m->blob_len) {
		mutex_unlock(&m->lock);
		return 0;
	}
	n = min_t(size_t, len, m->blob_len - (size_t)m->pos);
	off = m->pos;
	mutex_unlock(&m->lock);

	bounce = kvmalloc(n, GFP_KERNEL);
	if (!bounce)
		return -ENOMEM;

	mutex_lock(&m->lock);
	if (m->pos != off || !m->finalized || m->pos < 0 ||
	    (size_t)m->pos >= m->blob_len ||
	    m->blob_len - (size_t)m->pos < n) {
		mutex_unlock(&m->lock);
		kvfree(bounce);
		return sdxi_save_read(filp, buf, len, pos);
	}
	memcpy(bounce, (u8 *)m->blob + off, n);
	/* Reserve the range so a second reader does not return it again. */
	m->pos = off + n;
	mutex_unlock(&m->lock);

	missed = copy_to_user(buf, bounce, n);
	kvfree(bounce);
	if (!missed)
		return n;

	mutex_lock(&m->lock);
	if (m->pos == off + n)
		m->pos = off + (n - missed);
	mutex_unlock(&m->lock);
	return missed == n ? -EFAULT : n - missed;
}

static long sdxi_save_precopy_ioctl(struct file *filp, unsigned int cmd,
				    unsigned long arg)
{
	struct sdxi_mig_file *m = filp->private_data;
	struct sdxi_vfio_pci_device *s = m->sdev;
	struct vfio_precopy_info info;
	int ret;

	ret = vfio_check_precopy_ioctl(&s->core_dev.vdev, cmd, arg, &info);
	if (ret)
		return ret;

	scoped_guard(mutex, &s->state_mutex) {
		if (s->state != VFIO_DEVICE_STATE_PRE_COPY &&
		    s->state != VFIO_DEVICE_STATE_PRE_COPY_P2P)
			return -EINVAL;

		scoped_guard(mutex, &m->lock) {
			info.dirty_bytes = 0;
			if (m->finalized)
				info.initial_bytes = m->blob_len - m->pos;
			else
				info.initial_bytes = 0;
		}
	}

	return copy_to_user((void __user *)arg, &info,
			    offsetofend(struct vfio_precopy_info, dirty_bytes)) ?
		-EFAULT : 0;
}

static const struct file_operations sdxi_save_fops = {
	.owner          = THIS_MODULE,
	.read           = sdxi_save_read,
	.unlocked_ioctl = sdxi_save_precopy_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
	.release        = sdxi_mig_release,
};

static ssize_t sdxi_restore_write(struct file *filp, const char __user *buf,
				  size_t len, loff_t *pos)
{
	struct sdxi_mig_file *m = filp->private_data;
	void *kbuf;
	ssize_t ret;
	size_t n;
	loff_t off;

	if (!len)
		return 0;

retry:
	mutex_lock(&m->lock);
	if (m->pos < 0) {
		mutex_unlock(&m->lock);
		return -EINVAL;
	}
	if ((size_t)m->pos >= m->blob_cap) {
		mutex_unlock(&m->lock);
		return 0;
	}
	n = min_t(size_t, len, m->blob_cap - (size_t)m->pos);
	off = m->pos;
	mutex_unlock(&m->lock);

	kbuf = memdup_user(buf, n);
	if (IS_ERR(kbuf))
		return PTR_ERR(kbuf);

	mutex_lock(&m->lock);
	if (m->pos != off) {
		mutex_unlock(&m->lock);
		kfree(kbuf);
		goto retry;
	}
	memcpy((u8 *)m->blob + off, kbuf, n);
	m->pos = off + n;
	kfree(kbuf);
	ret = n;

	if (m->pos >= sizeof(*m->blob)) {
		u32 nr = le32_to_cpu(m->blob->nr_cxt);
		u32 nr_csb = le32_to_cpu(m->blob->nr_csb);
		size_t expect;

		if (nr > m->max_cxts || nr_csb > m->max_cxts) {
			ret = -EINVAL;
			goto out_unlock;
		}
		expect = sdxi_mig_blob_len(m->blob);
		if (m->pos > expect) {
			ret = -EINVAL;
			goto out_unlock;
		}
		if (m->pos == expect)
			m->valid = true;
	}

out_unlock:
	mutex_unlock(&m->lock);
	return ret;
}

static const struct file_operations sdxi_restore_fops = {
	.owner   = THIS_MODULE,
	.write   = sdxi_restore_write,
	.release = sdxi_mig_release,
};

static u32 sdxi_max_cxts(struct sdxi_vfio_pci_device *s)
{
	u64 cap1 = sdxi_read64(s, SDXI_MMIO_CAP1);

	return FIELD_GET(SDXI_MMIO_CAP1_MAX_CXT, cap1) + 1;
}

static size_t sdxi_mig_image_cap(u32 max_cxts)
{
	size_t cxt_bytes, csb_bytes, bytes;

	if (check_mul_overflow((size_t)max_cxts, sizeof(struct sdxi_mig_cxt_sts),
			       &cxt_bytes) ||
	    check_mul_overflow((size_t)max_cxts, sizeof(struct sdxi_mig_csb),
			       &csb_bytes) ||
	    check_add_overflow(cxt_bytes, sizeof(struct sdxi_mig_blob), &bytes) ||
	    check_add_overflow(bytes, csb_bytes, &bytes))
		return 0;
	return bytes;
}

static struct sdxi_mig_file *
sdxi_mig_file_alloc(struct sdxi_vfio_pci_device *s,
		    const struct file_operations *fops, int flags,
		    bool precopy)
{
	struct sdxi_mig_file *m;
	size_t cap;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return ERR_PTR(-ENOMEM);

	m->sdev = s;
	m->precopy = precopy;
	m->max_cxts = sdxi_max_cxts(s);
	cap = sdxi_mig_image_cap(m->max_cxts);
	m->blob = cap ? kvzalloc(cap, GFP_KERNEL) : NULL;
	m->blob_cap = cap;
	if (!m->blob) {
		kfree(m);
		return ERR_PTR(-ENOMEM);
	}

	mutex_init(&m->lock);
	m->filp = anon_inode_getfile("sdxi_vfio_mig", fops, m, flags);
	if (IS_ERR(m->filp)) {
		int err = PTR_ERR(m->filp);

		mutex_destroy(&m->lock);
		kvfree(m->blob);
		kfree(m);
		return ERR_PTR(err);
	}
	stream_open(file_inode(m->filp), m->filp);
	return m;
}

static void sdxi_mig_file_put(struct sdxi_mig_file *m)
{
	if (m)
		fput(m->filp);
}

static struct sdxi_mig_file *
sdxi_save_open(struct sdxi_vfio_pci_device *s, bool precopy)
{
	struct sdxi_mig_file *m;

	m = sdxi_mig_file_alloc(s, &sdxi_save_fops, O_RDONLY, precopy);
	if (IS_ERR(m))
		return m;

	get_file(m->filp);
	s->save_file = m;
	return m;
}

static int sdxi_save_finalize(struct sdxi_vfio_pci_device *s)
{
	struct sdxi_mig_file *m = s->save_file;
	int err;

	if (!m)
		return -EINVAL;

	sdxi_save_regs(s, m->blob);
	err = sdxi_snapshot_context_status(s, m->blob, m->max_cxts);
	if (err)
		return err;
	err = sdxi_snapshot_retired_csbs(s, m->blob, m->max_cxts);
	if (err)
		return err;
	m->blob_len = sdxi_mig_blob_len(m->blob);
	m->finalized = true;
	m->precopy = false;
	m->pos = 0;
	return 0;
}

static void sdxi_save_close(struct sdxi_vfio_pci_device *s)
{
	sdxi_mig_file_put(s->save_file);
	s->save_file = NULL;
}

static struct file *
sdxi_step_state(struct sdxi_vfio_pci_device *s, enum vfio_device_mig_state next)
{
	enum vfio_device_mig_state cur = s->state;
	struct sdxi_mig_file *m;
	int err;

	if (cur == VFIO_DEVICE_STATE_RUNNING && next == VFIO_DEVICE_STATE_STOP)
		return sdxi_stop(s) ? ERR_PTR(-EIO) : NULL;

	if (cur == VFIO_DEVICE_STATE_STOP && next == VFIO_DEVICE_STATE_RUNNING) {
		dev_info(sdxi_dev(s), "sdxi_start: arc STOP -> RUNNING\n");
		err = sdxi_start(s);
		return err ? ERR_PTR(err) : NULL;
	}

	/*
	 * P2P quiesce (QAT-style): SDXI cannot stop peer DMA alone, so
	 * RUNNING_P2P uses the same function stop as STOP (GSV_STOP). MMIO
	 * remains usable; all DMA including cross-function RKey is off.
	 */
	if (cur == VFIO_DEVICE_STATE_RUNNING &&
	    next == VFIO_DEVICE_STATE_RUNNING_P2P)
		return sdxi_stop(s) ? ERR_PTR(-EIO) : NULL;

	if (cur == VFIO_DEVICE_STATE_RUNNING_P2P &&
	    next == VFIO_DEVICE_STATE_RUNNING) {
		dev_info(sdxi_dev(s),
			 "sdxi_start: arc RUNNING_P2P -> RUNNING\n");
		err = sdxi_start(s);
		return err ? ERR_PTR(err) : NULL;
	}

	if ((cur == VFIO_DEVICE_STATE_RUNNING_P2P &&
	     next == VFIO_DEVICE_STATE_STOP) ||
	    (cur == VFIO_DEVICE_STATE_STOP &&
	     next == VFIO_DEVICE_STATE_RUNNING_P2P))
		return NULL;

	if ((cur == VFIO_DEVICE_STATE_RUNNING &&
	     next == VFIO_DEVICE_STATE_PRE_COPY) ||
	    (cur == VFIO_DEVICE_STATE_RUNNING_P2P &&
	     next == VFIO_DEVICE_STATE_PRE_COPY_P2P)) {
		m = sdxi_save_open(s, true);
		return IS_ERR(m) ? ERR_CAST(m) : m->filp;
	}

	if (cur == VFIO_DEVICE_STATE_PRE_COPY &&
	    next == VFIO_DEVICE_STATE_PRE_COPY_P2P)
		return sdxi_stop(s) ? ERR_PTR(-EIO) : NULL;

	if (cur == VFIO_DEVICE_STATE_PRE_COPY_P2P &&
	    next == VFIO_DEVICE_STATE_PRE_COPY) {
		dev_info(sdxi_dev(s),
			 "sdxi_start: arc PRE_COPY_P2P -> PRE_COPY\n");
		err = sdxi_start(s);
		return err ? ERR_PTR(err) : NULL;
	}

	if (cur == VFIO_DEVICE_STATE_PRE_COPY &&
	    next == VFIO_DEVICE_STATE_RUNNING) {
		dev_info(sdxi_dev(s),
			 "sdxi_start: arc PRE_COPY -> RUNNING\n");
		err = sdxi_start(s);
		if (err)
			return ERR_PTR(err);
		sdxi_save_close(s);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_PRE_COPY_P2P &&
	    next == VFIO_DEVICE_STATE_RUNNING_P2P) {
		sdxi_save_close(s);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_PRE_COPY_P2P &&
	    next == VFIO_DEVICE_STATE_STOP_COPY) {
		err = sdxi_save_finalize(s);
		return err ? ERR_PTR(err) : NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP &&
	    next == VFIO_DEVICE_STATE_STOP_COPY) {
		m = sdxi_save_open(s, false);
		if (IS_ERR(m))
			return ERR_CAST(m);
		err = sdxi_save_finalize(s);
		if (err) {
			sdxi_save_close(s);
			return ERR_PTR(err);
		}
		return m->filp;
	}

	if (cur == VFIO_DEVICE_STATE_STOP_COPY &&
	    next == VFIO_DEVICE_STATE_STOP) {
		sdxi_save_close(s);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP &&
	    next == VFIO_DEVICE_STATE_RESUMING) {
		m = sdxi_mig_file_alloc(s, &sdxi_restore_fops, O_WRONLY, false);
		if (IS_ERR(m))
			return ERR_CAST(m);
		get_file(m->filp);
		s->restore_file = m;
		return m->filp;
	}

	if (cur == VFIO_DEVICE_STATE_RESUMING &&
	    next == VFIO_DEVICE_STATE_STOP) {
		m = s->restore_file;
		if (!m) {
			dev_err(sdxi_dev(s), "restore: no migration data\n");
			return ERR_PTR(-EINVAL);
		}
		if (!m->valid) {
			dev_err(sdxi_dev(s), "restore: incomplete blob\n");
			sdxi_mig_file_put(m);
			s->restore_file = NULL;
			return ERR_PTR(-EINVAL);
		}
		err = sdxi_restore_regs(s, m->blob);
		if (err) {
			m->pos = 0;
			m->valid = false;
			return ERR_PTR(err);
		}
		s->restore_file = NULL;
		sdxi_mig_file_put(m);
		return NULL;
	}

	WARN_ON_ONCE(true);
	return ERR_PTR(-EINVAL);
}

static struct file *
sdxi_vfio_set_state(struct vfio_device *vdev,
		    enum vfio_device_mig_state new_state)
{
	struct sdxi_vfio_pci_device *s =
		container_of(vdev, struct sdxi_vfio_pci_device, core_dev.vdev);
	enum vfio_device_mig_state next;
	struct file *res = NULL;
	int err;

	guard(mutex)(&s->state_mutex);
	dev_info(sdxi_dev(s), "set_state %s -> %s\n",
		 sdxi_mig_state_str(s->state),
		 sdxi_mig_state_str(new_state));
	while (new_state != s->state) {
		err = vfio_mig_get_next_state(vdev, s->state, new_state, &next);
		if (err)
			return ERR_PTR(err);

		res = sdxi_step_state(s, next);
		if (IS_ERR(res))
			return res;

		s->state = next;
		if (WARN_ON(res && new_state != s->state)) {
			fput(res);
			return ERR_PTR(-EINVAL);
		}
	}
	return res;
}

static int sdxi_vfio_get_state(struct vfio_device *vdev,
			       enum vfio_device_mig_state *state)
{
	struct sdxi_vfio_pci_device *s =
		container_of(vdev, struct sdxi_vfio_pci_device, core_dev.vdev);

	guard(mutex)(&s->state_mutex);
	*state = s->state;
	return 0;
}

static int sdxi_vfio_get_data_size(struct vfio_device *vdev,
				   unsigned long *stop_copy_length)
{
	struct sdxi_vfio_pci_device *s =
		container_of(vdev, struct sdxi_vfio_pci_device, core_dev.vdev);

	*stop_copy_length = sdxi_mig_image_cap(sdxi_max_cxts(s));
	if (!*stop_copy_length)
		return -EOVERFLOW;
	return 0;
}

static const struct vfio_migration_ops sdxi_vfio_mig_ops = {
	.migration_set_state     = sdxi_vfio_set_state,
	.migration_get_state     = sdxi_vfio_get_state,
	.migration_get_data_size = sdxi_vfio_get_data_size,
};

static int sdxi_vfio_init_device(struct vfio_device *vdev)
{
	struct sdxi_vfio_pci_device *s =
		container_of(vdev, struct sdxi_vfio_pci_device, core_dev.vdev);
	int err;

	err = vfio_pci_core_init_dev(vdev);
	if (err)
		return err;

	mutex_init(&s->state_mutex);
	vdev->migration_flags = VFIO_MIGRATION_STOP_COPY |
				VFIO_MIGRATION_P2P |
				VFIO_MIGRATION_PRE_COPY;
	vdev->mig_ops = &sdxi_vfio_mig_ops;
	return 0;
}

static void sdxi_vfio_release_device(struct vfio_device *vdev)
{
	struct sdxi_vfio_pci_device *s =
		container_of(vdev, struct sdxi_vfio_pci_device, core_dev.vdev);

	mutex_destroy(&s->state_mutex);
	vfio_pci_core_release_dev(vdev);
}

static bool sdxi_gsv_reset_hangs(u64 sts0)
{
	enum sdxi_fn_gsv gsv;

	if (sts0 == ~0ULL)
		return true;

	gsv = (enum sdxi_fn_gsv)FIELD_GET(SDXI_MMIO_STS0_FN_GSV, sts0);
	return gsv == SDXI_GSV_STOPG_SF || gsv == SDXI_GSV_STOPG_HD;
}

/*
 * FLR does not finish while the function is soft-stopping, and a
 * function that no longer answers MMIO will not finish it either.
 * Peek before VFIO's open/close reset. A healthy function still resets.
 */
static bool sdxi_peek_reset_hangs(struct pci_dev *pdev)
{
	void __iomem *bar0;
	u16 vendor;
	bool hangs = false;

	if (pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor) ||
	    vendor == (u16)~0)
		return true;

	if (pci_enable_device(pdev))
		return false;

	bar0 = pci_iomap(pdev, 0, 0);
	if (bar0) {
		hangs = sdxi_gsv_reset_hangs(ioread64(bar0 + SDXI_MMIO_STS0));
		pci_iounmap(pdev, bar0);
	}
	pci_disable_device(pdev);
	return hangs;
}

static int sdxi_vfio_open_device(struct vfio_device *vdev)
{
	struct sdxi_vfio_pci_device *s =
		container_of(vdev, struct sdxi_vfio_pci_device, core_dev.vdev);
	struct pci_dev *pdev = s->core_dev.pdev;
	u64 sts0;
	enum sdxi_fn_gsv gsv;
	int err;

	s->core_dev.skip_reset = sdxi_peek_reset_hangs(pdev);
	err = vfio_pci_core_enable(&s->core_dev);
	if (err)
		return err;

	s->bar0 = pci_iomap(pdev, 0, 0);
	if (!s->bar0) {
		vfio_pci_core_disable(&s->core_dev);
		return -ENOMEM;
	}

	sts0 = sdxi_read64(s, SDXI_MMIO_STS0);
	gsv = (sts0 == ~0ULL) ? SDXI_GSV_STOP :
		(enum sdxi_fn_gsv)FIELD_GET(SDXI_MMIO_STS0_FN_GSV, sts0);
	s->state = (gsv == SDXI_GSV_ACTIVE) ?
		VFIO_DEVICE_STATE_RUNNING : VFIO_DEVICE_STATE_STOP;

	vfio_pci_core_finish_enable(&s->core_dev);
	return 0;
}

static void sdxi_drop_mig_files(struct sdxi_vfio_pci_device *s)
{
	sdxi_save_close(s);
	sdxi_mig_file_put(s->restore_file);
	s->restore_file = NULL;
}

static void sdxi_vfio_close_device(struct vfio_device *vdev)
{
	struct sdxi_vfio_pci_device *s =
		container_of(vdev, struct sdxi_vfio_pci_device, core_dev.vdev);

	scoped_guard(mutex, &s->state_mutex)
		sdxi_drop_mig_files(s);

	if (s->preserve_error)
		s->core_dev.skip_reset = true;
	else if (s->bar0)
		s->core_dev.skip_reset =
			sdxi_gsv_reset_hangs(sdxi_read64(s, SDXI_MMIO_STS0));
	else
		s->core_dev.skip_reset = false;

	pci_iounmap(s->core_dev.pdev, s->bar0);
	s->bar0 = NULL;
	vfio_pci_core_close_device(vdev);
}

static bool sdxi_vfio_is_config(loff_t ppos)
{
	return VFIO_PCI_OFFSET_TO_INDEX(ppos) == VFIO_PCI_CONFIG_REGION_INDEX;
}

static ssize_t sdxi_vfio_write(struct vfio_device *core_vdev,
			       const char __user *buf, size_t count,
			       loff_t *ppos)
{
	ssize_t ret = vfio_pci_core_write(core_vdev, buf, count, ppos);

	if (ret != -EOPNOTSUPP || !sdxi_vfio_is_config(*ppos))
		return ret;

	*ppos += count;
	return count;
}

static ssize_t sdxi_vfio_read(struct vfio_device *core_vdev, char __user *buf,
			      size_t count, loff_t *ppos)
{
	ssize_t ret = vfio_pci_core_read(core_vdev, buf, count, ppos);
	size_t i;

	if (ret != -EOPNOTSUPP || !sdxi_vfio_is_config(*ppos))
		return ret;

	for (i = 0; i < count; i++) {
		loff_t pos = *ppos + i;
		char zero = 0;

		ret = vfio_pci_core_read(core_vdev, buf + i, 1, &pos);
		if (ret == -EOPNOTSUPP) {
			if (copy_to_user(buf + i, &zero, 1))
				return -EFAULT;
			continue;
		}
		if (ret < 0)
			return ret;
	}
	*ppos += count;
	return count;
}

/*
 * GSV_STOP with read_index == write_index means every posted descriptor
 * was retired. The completion store is ordered before that, so the
 * signal should already be back to zero. A non-zero signal here is the
 * dropped store. pause_drain_action selects what happens after the warning.
 * Returns 0, or -EPROTO when the action is "pause".
 */
static int sdxi_warn_stopped_signal(struct device *dev, u32 pasid,
				    dma_addr_t ctl_dma, u32 cxt_id)
{
	struct {
		dma_addr_t dma;
		u64 signal;
		u64 desc_index;
	} notes[16];
	struct sdxi_cxt_ctl ctl;
	struct sdxi_cxt_sts sts;
	struct sdxi_desc *descs = NULL;
	dma_addr_t ring, sts_dma;
	size_t bytes;
	u64 widx, read_index, idx, start;
	u32 entries, nnotes = 0;
	int ret;

	ret = amd_iommu_read_guest_dma(dev, pasid, ctl_dma, &ctl, sizeof(ctl));
	if (ret) {
		dev_warn(dev, "pause drain: id %u ctl read failed: %d\n",
			 cxt_id, ret);
		return 0;
	}
	if (!(le64_to_cpu(ctl.ds_ring_ptr) & SDXI_CXT_CTL_VL))
		return 0;

	entries = le32_to_cpu(ctl.ds_ring_sz);
	ring = sdxi_field_ptr(le64_to_cpu(ctl.ds_ring_ptr),
			      SDXI_CXT_CTL_DS_RING_PTR);
	sts_dma = sdxi_field_ptr(le64_to_cpu(ctl.cxt_sts_ptr),
				 SDXI_CXT_CTL_CXT_STS_PTR);
	if (!entries || !ring || !sts_dma)
		return 0;
	if (entries > 65536) {
		dev_warn(dev, "pause drain: id %u ring size %u is not usable\n",
			 cxt_id, entries);
		return 0;
	}

	ret = sdxi_read_write_index(dev, pasid, &ctl, &widx);
	if (ret == -ENOENT || !widx)
		return 0;
	if (ret) {
		dev_warn(dev, "pause drain: id %u write_index read failed: %d\n",
			 cxt_id, ret);
		return 0;
	}
	ret = amd_iommu_read_guest_dma(dev, pasid, sts_dma, &sts, sizeof(sts));
	if (ret) {
		dev_warn(dev, "pause drain: id %u status read failed: %d\n",
			 cxt_id, ret);
		return 0;
	}
	read_index = le64_to_cpu(sts.read_index);
	if (read_index != widx)
		return 0;

	start = widx > entries ? widx - entries : 0;
	bytes = array_size(entries, sizeof(*descs));
	descs = kvmalloc(bytes, GFP_KERNEL);
	if (!descs) {
		dev_warn(dev, "pause drain: id %u ring allocation failed\n",
			 cxt_id);
		return 0;
	}
	ret = amd_iommu_read_guest_dma(dev, pasid, ring, descs, bytes);
	if (ret) {
		dev_warn(dev, "pause drain: id %u ring read failed: %d\n",
			 cxt_id, ret);
		goto out;
	}

	for (idx = start; idx < widx; idx++) {
		struct sdxi_desc *desc = &descs[idx % entries];
		u64 raw = le64_to_cpu(desc->generic.csb_ptr);
		dma_addr_t csb;
		__le64 signal;
		u64 value;
		u32 n;

		if (raw & SDXI_DSC_NP)
			continue;
		csb = sdxi_field_ptr(raw, SDXI_DSC_CSB_PTR);
		if (!csb)
			continue;

		for (n = 0; n < nnotes; n++) {
			if (notes[n].dma == csb)
				break;
		}
		if (n < nnotes) {
			notes[n].desc_index = idx;
			continue;
		}
		ret = amd_iommu_read_guest_dma(dev, pasid, csb, &signal,
					      sizeof(signal));
		if (ret) {
			dev_warn(dev, "pause drain: id %u csb %pad read failed: %d\n",
				 cxt_id, &csb, ret);
			goto out;
		}
		value = le64_to_cpu(signal);
		if (!value)
			continue;
		if (nnotes >= ARRAY_SIZE(notes)) {
			dev_warn(dev, "pause drain: id %u has too many non-zero completion signals\n",
				 cxt_id);
			break;
		}
		notes[nnotes].dma = csb;
		notes[nnotes].signal = value;
		notes[nnotes].desc_index = idx;
		nnotes++;
	}

	for (idx = 0; idx < nnotes; idx++)
		dev_warn(dev,
			 "pause drain: id %u desc %llu csb %pad signal 0x%llx with read_index %llu == write_index %llu\n",
			 cxt_id, notes[idx].desc_index, &notes[idx].dma,
			 notes[idx].signal, read_index, widx);
out:
	kvfree(descs);
	return 0;
}

static int sdxi_warn_stopped_nonzero_signals(struct sdxi_vfio_pci_device *s)
{
	struct device *dev = sdxi_dev(s);
	u32 pasid = sdxi_dma_pasid(s);
	u64 cxt_l2 = sdxi_read64(s, SDXI_MMIO_CXT_L2);
	dma_addr_t l2_dma = sdxi_field_ptr(cxt_l2, SDXI_MMIO_CXT_L2_PTR);
	struct sdxi_cxt_L2_ent *l2;
	u8 *l2_buf, *l1_buf;
	int i, ret = 0;

	if (!l2_dma)
		return 0;

	l2_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	l1_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!l2_buf || !l1_buf) {
		dev_warn(dev, "pause drain: completion check allocation failed\n");
		goto out;
	}
	if (amd_iommu_read_guest_dma(dev, pasid, l2_dma, l2_buf, PAGE_SIZE)) {
		dev_warn(dev, "pause drain: completion check L2 read failed\n");
		goto out;
	}

	l2 = (struct sdxi_cxt_L2_ent *)l2_buf;
	for (i = 0; i < SDXI_L2_TABLE_ENTRIES; i++) {
		struct sdxi_cxt_L1_ent *ents;
		u64 raw = le64_to_cpu(l2[i].lv01_ptr);
		dma_addr_t l1_dma;
		int j;

		if (!(raw & SDXI_CXT_L2_ENT_VL))
			continue;
		l1_dma = sdxi_field_ptr(raw, SDXI_CXT_L2_ENT_LV01_PTR);
		if (amd_iommu_read_guest_dma(dev, pasid, l1_dma, l1_buf,
					    PAGE_SIZE)) {
			dev_warn(dev, "pause drain: completion check L1 %d read failed\n",
				 i);
			continue;
		}

		ents = (struct sdxi_cxt_L1_ent *)l1_buf;
		for (j = 0; j < SDXI_L1_TABLE_ENTRIES; j++) {
			u64 ent = le64_to_cpu(ents[j].cxt_ctl_ptr);
			dma_addr_t ctl_dma;

			if (!(ent & SDXI_CXT_L1_ENT_VL))
				continue;
			ctl_dma = sdxi_field_ptr(ent, SDXI_CXT_L1_ENT_CXT_CTL_PTR);
			ret = sdxi_warn_stopped_signal(dev, pasid, ctl_dma,
						      sdxi_guest_cxt_id(i, j));
			if (ret)
				goto out;
		}
	}
out:
	kfree(l2_buf);
	kfree(l1_buf);
	return ret;
}

/* Per-vector mask. MASKALL in the stop path is optional on some devices. */
static void sdxi_mask_msix_vectors(struct sdxi_vfio_pci_device *s)
{
	struct pci_dev *pdev = s->core_dev.pdev;
	struct msi_desc *desc;

	/* No descriptor storage until the user has enabled MSI-X. */
	if (!pdev->msix_enabled)
		return;

	guard(msi_descs_lock)(&pdev->dev);
	msi_for_each_desc(desc, &pdev->dev, MSI_DESC_ASSOCIATED) {
		struct irq_data *data = irq_get_irq_data(desc->irq);

		if (data)
			pci_msi_mask_irq(data);
	}
}

static void sdxi_mask_msix_all(struct sdxi_vfio_pci_device *s)
{
	struct pci_dev *pdev = s->core_dev.pdev;
	u16 ctrl;

	if (!pdev->msix_cap)
		return;

	pci_read_config_word(pdev, pdev->msix_cap + PCI_MSIX_FLAGS, &ctrl);
	ctrl |= PCI_MSIX_FLAGS_MASKALL;
	pci_write_config_word(pdev, pdev->msix_cap + PCI_MSIX_FLAGS, ctrl);
}

static void sdxi_log_err_indexes(struct sdxi_vfio_pci_device *s, const char *tag)
{
	dev_info(sdxi_dev(s), "%s: err_sts=%#llx err_wrt=%llu err_rd=%llu\n",
		 tag,
		 sdxi_read64(s, SDXI_MMIO_ERR_STS),
		 sdxi_read64(s, SDXI_MMIO_ERR_WRT),
		 sdxi_read64(s, SDXI_MMIO_ERR_RD));
}

/* Vector 0 mask and pending bit, before either mask is set. */
static void sdxi_log_msix_vec0(struct sdxi_vfio_pci_device *s)
{
	struct pci_dev *pdev = s->core_dev.pdev;
	struct device *dev = sdxi_dev(s);
	int cap = pdev->msix_cap;
	u16 flags = 0;
	u32 table = 0, pba_reg = 0;
	unsigned int tbir, pbir;
	u32 toff, poff;
	void __iomem *tbl = NULL;
	void __iomem *pba = NULL;
	u32 vec_ctrl = ~0U;
	u32 pba0 = ~0U;

	if (!cap) {
		dev_info(dev, "preserve pre-mask: no MSI-X capability\n");
		return;
	}

	pci_read_config_word(pdev, cap + PCI_MSIX_FLAGS, &flags);
	pci_read_config_dword(pdev, cap + PCI_MSIX_TABLE, &table);
	pci_read_config_dword(pdev, cap + PCI_MSIX_PBA, &pba_reg);
	tbir = table & PCI_MSIX_TABLE_BIR;
	toff = table & PCI_MSIX_TABLE_OFFSET;
	pbir = pba_reg & PCI_MSIX_PBA_BIR;
	poff = pba_reg & PCI_MSIX_PBA_OFFSET;

	if (tbir < PCI_STD_NUM_BARS &&
	    toff + PCI_MSIX_ENTRY_SIZE <= pci_resource_len(pdev, tbir)) {
		tbl = pci_iomap(pdev, tbir, 0);
		if (tbl)
			vec_ctrl = ioread32(tbl + toff + PCI_MSIX_ENTRY_VECTOR_CTRL);
	}
	if (pbir < PCI_STD_NUM_BARS &&
	    poff + sizeof(pba0) <= pci_resource_len(pdev, pbir)) {
		if (pbir == tbir)
			pba = tbl;
		else
			pba = pci_iomap(pdev, pbir, 0);
		if (pba)
			pba0 = ioread32(pba + poff);
	}

	dev_info(dev,
		 "preserve pre-mask: msix flags=%#x maskall=%u enable=%u vec0_ctrl=%#x vec0_mask=%u pba0=%#x pending=%u\n",
		 flags,
		 !!(flags & PCI_MSIX_FLAGS_MASKALL),
		 !!(flags & PCI_MSIX_FLAGS_ENABLE),
		 vec_ctrl,
		 vec_ctrl != ~0U && (vec_ctrl & PCI_MSIX_ENTRY_CTRL_MASKBIT),
		 pba0,
		 pba0 != ~0U && (pba0 & BIT(0)));

	if (pba && pba != tbl)
		pci_iounmap(pdev, pba);
	if (tbl)
		pci_iounmap(pdev, tbl);
}

static void sdxi_log_err_slot_raw(struct sdxi_vfio_pci_device *s, const char *tag)
{
	struct device *dev = sdxi_dev(s);
	u64 cfg = sdxi_read64(s, SDXI_MMIO_ERR_CFG);
	u64 wrt = sdxi_read64(s, SDXI_MMIO_ERR_WRT);
	u64 rd = sdxi_read64(s, SDXI_MMIO_ERR_RD);
	u32 nent = FIELD_GET(SDXI_MMIO_ERR_CFG_SZ, cfg) << 6;
	u8 raw[64];
	dma_addr_t base;
	int ret;

	if (!nent)
		nent = 64;
	if (!(cfg & SDXI_MMIO_ERR_CFG_EN) || wrt <= rd) {
		dev_info(dev,
			 "preserve pre-mask %s: no slot en=%llu wrt=%llu rd=%llu\n",
			 tag, (u64)!!(cfg & SDXI_MMIO_ERR_CFG_EN), wrt, rd);
		return;
	}

	base = sdxi_field_ptr(cfg, SDXI_MMIO_ERR_CFG_PTR);
	ret = amd_iommu_read_guest_dma(dev, sdxi_dma_pasid(s),
				       base + (rd % nent) * sizeof(raw),
				       raw, sizeof(raw));
	if (ret) {
		dev_info(dev, "preserve pre-mask %s: slot %llu read failed: %d\n",
			 tag, rd, ret);
		return;
	}
	dev_info(dev, "preserve pre-mask %s: slot %llu %*ph\n",
		 tag, rd, (int)sizeof(raw), raw);
}

/* MSI-X and the log slot, then the indexes again. Caller masks after this. */
static void sdxi_log_preserve_before_mask(struct sdxi_vfio_pci_device *s)
{
	sdxi_log_msix_vec0(s);
	sdxi_log_err_indexes(s, "preserve pre-mask");
	sdxi_log_err_slot_raw(s, "read1");
	sdxi_log_err_slot_raw(s, "read2");
	sdxi_log_err_indexes(s, "preserve pre-mask after slot");
}

static int sdxi_feature_pause(struct sdxi_vfio_pci_device *s, u32 flags,
			      void __user *arg, size_t argsz)
{
	struct vfio_device_feature_sdxi_pause pause;
	unsigned int timeout_ms;
	int ret;

	ret = vfio_check_feature(flags, argsz, VFIO_DEVICE_FEATURE_SET,
				 sizeof(pause));
	if (ret != 1)
		return ret;
	if (copy_from_user(&pause, arg, sizeof(pause)))
		return -EFAULT;

	guard(mutex)(&s->state_mutex);

	if (pause.flags == VFIO_DEVICE_FEATURE_SDXI_PAUSE_RESUME) {
		dev_info(sdxi_dev(s), "sdxi_start: SDXI_PAUSE_RESUME\n");
		return sdxi_start(s);
	}

	if (pause.flags != VFIO_DEVICE_FEATURE_SDXI_PAUSE_DRAIN)
		return -EINVAL;

	/*
	 * A reset leaves CTL0 as all-ones until the function answers again.
	 * sdxi_stop() treats that as already stopped; do the same here so
	 * the drain does not poll a dead mapping.
	 */
	if (sdxi_read64(s, SDXI_MMIO_CTL0) == ~0ULL)
		return 0;

	if (sdxi_guest_unprogrammed(s)) {
		dev_info(sdxi_dev(s),
			 "pause drain: guest SDXI driver not programmed; skip GSRV_STOP_SF\n");
		return 0;
	}

	timeout_ms = pause.timeout_ms ?: 30000;
	if (timeout_ms > 120000)
		timeout_ms = 120000;

	dev_info(sdxi_dev(s), "pause drain: waiting up to %u ms for GSV_STOP\n",
		 timeout_ms);
	ret = sdxi_fn_stop_timeout_flags(sdxi_dev(s), s->bar0, timeout_ms,
					 SDXI_FN_STOP_PRESERVE_ERROR);
	if (ret == -EPROTO) {
		s->preserve_error = true;
		s->core_dev.skip_reset = true;
		sdxi_log_preserve_before_mask(s);
		sdxi_mask_msix_all(s);
		sdxi_mask_msix_vectors(s);
		sdxi_debug_log_stop_stall(s);
		dev_err(sdxi_dev(s),
			"sdxi preserve: pause drain holding device, migration aborted\n");
		return ret;
	}
	if (ret) {
		dev_err(sdxi_dev(s), "pause drain failed: %d\n", ret);
		sdxi_debug_log_stop_stall(s);
		return ret;
	}
	ret = sdxi_warn_stopped_nonzero_signals(s);
	if (ret)
		return ret;
	/*
	 * Return as soon as the function stops. A retired descriptor can
	 * still have a non-zero completion signal; STOP_COPY records it
	 * and resume writes 0 before the guest runs. Waiting here lets
	 * the guest's completion timeout fire while the context is stopped.
	 */
	sdxi_log_err_indexes(s, "pause drain stopped");
	dev_info(sdxi_dev(s),
		 "pause drain: function stopped; completion stores are sampled at STOP_COPY\n");
	return 0;
}

static int sdxi_vfio_device_feature(struct vfio_device *device, u32 flags,
				    void __user *arg, size_t argsz)
{
	struct sdxi_vfio_pci_device *s =
		container_of(device, struct sdxi_vfio_pci_device, core_dev.vdev);

	switch (flags & VFIO_DEVICE_FEATURE_MASK) {
	case VFIO_DEVICE_FEATURE_SDXI_PAUSE:
		return sdxi_feature_pause(s, flags, arg, argsz);
	default:
		return vfio_pci_core_ioctl_feature(device, flags, arg, argsz);
	}
}

static const struct vfio_device_ops sdxi_vfio_ops = {
	.name			= KBUILD_MODNAME,
	.init			= sdxi_vfio_init_device,
	.release		= sdxi_vfio_release_device,
	.open_device		= sdxi_vfio_open_device,
	.close_device		= sdxi_vfio_close_device,
	.ioctl			= vfio_pci_core_ioctl,
	.get_region_info_caps	= vfio_pci_ioctl_get_region_info,
	.device_feature		= sdxi_vfio_device_feature,
	.read			= sdxi_vfio_read,
	.write			= sdxi_vfio_write,
	.mmap			= vfio_pci_core_mmap,
	.request		= vfio_pci_core_request,
	.bind_iommufd		= vfio_iommufd_physical_bind,
	.unbind_iommufd		= vfio_iommufd_physical_unbind,
	.attach_ioas		= vfio_iommufd_physical_attach_ioas,
	.detach_ioas		= vfio_iommufd_physical_detach_ioas,
};

static int sdxi_vfio_pci_probe(struct pci_dev *pdev,
			       const struct pci_device_id *id)
{
	struct sdxi_vfio_pci_device *s;
	int err;

	s = vfio_alloc_device(sdxi_vfio_pci_device, core_dev.vdev,
			      &pdev->dev, &sdxi_vfio_ops);
	if (IS_ERR(s))
		return PTR_ERR(s);

	dev_set_drvdata(&pdev->dev, &s->core_dev);

	err = vfio_pci_core_register_device(&s->core_dev);
	if (err) {
		vfio_put_device(&s->core_dev.vdev);
		return err;
	}
	return 0;
}

static void sdxi_vfio_pci_remove(struct pci_dev *pdev)
{
	struct vfio_pci_core_device *core =
		dev_get_drvdata(&pdev->dev);
	struct sdxi_vfio_pci_device *s =
		container_of(core, struct sdxi_vfio_pci_device, core_dev);

	vfio_pci_core_unregister_device(&s->core_dev);
	vfio_put_device(&s->core_dev.vdev);
}

static int sdxi_vfio_pci_sriov_configure(struct pci_dev *pdev, int nr_virtfn)
{
	struct vfio_pci_core_device *vdev = dev_get_drvdata(&pdev->dev);

	return vfio_pci_core_sriov_configure(vdev, nr_virtfn);
}

static const struct pci_device_id sdxi_vfio_pci_table[] = {
	{ PCI_DEVICE_CLASS(PCI_CLASS_ACCELERATOR_SDXI, 0xffffff) },
	{}
};
MODULE_DEVICE_TABLE(pci, sdxi_vfio_pci_table);

static void sdxi_vfio_reset_done(struct pci_dev *pdev)
{
	struct vfio_pci_core_device *core = dev_get_drvdata(&pdev->dev);
	struct sdxi_vfio_pci_device *s =
		container_of(core, struct sdxi_vfio_pci_device, core_dev);

	guard(mutex)(&s->state_mutex);
	/*
	 * Open's FLR also lands here, before bar0 is mapped, and
	 * open_device() then overwrites s->state from the function's GSV.
	 * A reset QEMU issues while the device is open must match the
	 * uAPI: device_state returns to RUNNING. The function itself
	 * stays at GSV_STOP until the next sdxi_start().
	 */
	if (s->bar0)
		dev_info(&pdev->dev, "reset_done: %s -> RUNNING\n",
			 sdxi_mig_state_str(s->state));
	sdxi_drop_mig_files(s);
	s->state = VFIO_DEVICE_STATE_RUNNING;
}

static pci_ers_result_t sdxi_vfio_aer_err_detected(struct pci_dev *pdev,
						   pci_channel_state_t state)
{
	struct vfio_pci_core_device *vdev = pci_get_drvdata(pdev);

	return vfio_pci_core_aer_err_detected(vdev);
}

static const struct pci_error_handlers sdxi_vfio_err_handlers = {
	.error_detected = sdxi_vfio_aer_err_detected,
	.reset_done = sdxi_vfio_reset_done,
};

static struct pci_driver sdxi_vfio_pci_driver = {
	.name			= KBUILD_MODNAME,
	.id_table		= sdxi_vfio_pci_table,
	.probe			= sdxi_vfio_pci_probe,
	.remove			= sdxi_vfio_pci_remove,
	.sriov_configure	= sdxi_vfio_pci_sriov_configure,
	.err_handler		= &sdxi_vfio_err_handlers,
	.driver_managed_dma	= true,
};
module_pci_driver(sdxi_vfio_pci_driver);

MODULE_DESCRIPTION("VFIO variant driver for AMD SDXI PCI devices");
MODULE_AUTHOR("Tycho Andersen (AMD) <tycho@kernel.org>");
MODULE_IMPORT_NS("SDXI");
MODULE_LICENSE("GPL");
