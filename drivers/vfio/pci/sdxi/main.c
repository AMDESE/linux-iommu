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
#include <linux/io.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/pci.h>
#include <linux/sdxi.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/vfio.h>
#include <linux/vfio_pci_core.h>

#include "hw.h"
#include "main.h"

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

static int sdxi_stop(struct sdxi_vfio_pci_device *s)
{
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

	return sdxi_fn_stop(sdxi_dev(s), s->bar0);
}

static int sdxi_start(struct sdxi_vfio_pci_device *s)
{
	struct pci_dev *vf = s->core_dev.pdev;
	u64 cap0, cap1;
	u32 max_cxt;
	u16 sfunc;
	int vf_id;
	int ret;

	/*
	 * PRE_COPY -> RUNNING is also taken when a pause drain stopped the
	 * function without leaving PRE_COPY. Already-active is the normal
	 * cancel path and must not issue another P2V.
	 */
	if ((enum sdxi_fn_gsv)FIELD_GET(SDXI_MMIO_STS0_FN_GSV,
				       sdxi_read64(s, SDXI_MMIO_STS0)) ==
	    SDXI_GSV_ACTIVE)
		return 0;

	ret = sdxi_fn_start(sdxi_dev(s), s->bar0);
	if (ret)
		return ret;

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
	 */
	cap0 = sdxi_read64(s, SDXI_MMIO_CAP0);
	cap1 = sdxi_read64(s, SDXI_MMIO_CAP1);
	max_cxt = FIELD_GET(SDXI_MMIO_CAP1_MAX_CXT, cap1);
	sfunc = FIELD_GET(SDXI_MMIO_CAP0_SFUNC, cap0);

	/*
	 * P2V.DSC_CXT_START_RS is only meaningful for a VF: it is issued by
	 * the owning PF on the VF's behalf.
	 */
	vf_id = pci_iov_vf_id(vf);
	if (vf_id < 0)
		return 0;

	/*
	 * The P2V descriptor's vf_num identifies the target VF by its
	 * SDXI function identifier, MMIO_CAP0.sfunc (§8.2) -- an
	 * implementation-specific value that maps to the VF's PCIe
	 * Requester ID, not necessarily the Linux 0-based VF index.
	 * Sending the wrong identifier makes the PF reject the P2V and
	 * HaltErr:Fn into GSV_ERROR with nothing logged, so use the
	 * VF's own sfunc and log it next to the PCI VF id.
	 */
	dev_info(sdxi_dev(s),
		 "start: P2V restart vf_id=%d sfunc=0x%x max_cxt=%u\n",
		 vf_id, sfunc, max_cxt);

	ret = sdxi_pf_restart_vf_contexts(vf, sfunc, 0, max_cxt);
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

static int sdxi_snap_one_context(struct device *dev, u32 pasid,
				 dma_addr_t ctl_dma, struct sdxi_mig_blob *b,
				 u32 max_cxts)
{
	struct sdxi_mig_cxt_sts *rec;
	struct sdxi_cxt_ctl ctl;
	struct sdxi_cxt_sts sts;
	dma_addr_t sts_dma;
	u32 nr;
	int ret;

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

	dev_info(dev,
		 "context-status save: dma %pad read_index %llu state %#x\n",
		 &sts_dma, le64_to_cpu(sts.read_index), sts.state);
	return 0;
}

static int sdxi_snap_l1(struct device *dev, u32 pasid, dma_addr_t l1_dma,
			u8 *l1_buf, struct sdxi_mig_blob *b, u32 max_cxts)
{
	struct sdxi_cxt_l1_ent *ents = (struct sdxi_cxt_l1_ent *)l1_buf;
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
		ret = sdxi_snap_one_context(dev, pasid, ctl, b, max_cxts);
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
	struct sdxi_cxt_l2_ent *l2;
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

	l2 = (struct sdxi_cxt_l2_ent *)l2_buf;
	for (i = 0; i < SDXI_L2_TABLE_ENTRIES; i++) {
		u64 raw = le64_to_cpu(l2[i].lv01_ptr);
		dma_addr_t l1_dma;

		if (!(raw & SDXI_CXT_L2_ENT_VL))
			continue;

		l1_dma = sdxi_field_ptr(raw, SDXI_CXT_L2_ENT_LV01_PTR);
		ret = sdxi_snap_l1(dev, pasid, l1_dma, l1_buf, b, max_cxts);
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

	for (i = 0; i < nr; i++) {
		const struct sdxi_mig_cxt_sts *rec = &b->cxt[i];
		dma_addr_t dma = le64_to_cpu(rec->dma);

		if (!dma)
			return -EINVAL;

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
	b->nr_pad  = 0;
}

static int sdxi_restore_regs(struct sdxi_vfio_pci_device *s,
			     const struct sdxi_mig_blob *b)
{
	u64 dst_cap0 = sdxi_read64(s, SDXI_MMIO_CAP0);
	u64 dst_cap1 = sdxi_read64(s, SDXI_MMIO_CAP1);
	u64 err_cfg;

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
	 * §4.1.8 step 1.a: capability sets must match the saved content.
	 * CAP0/CAP1 are read-only; identical values guarantee the
	 * destination can host the source's table layouts. CAP0.SFUNC is
	 * the VF's own function identifier (its Requester ID), not a
	 * capability -- it legitimately differs when resuming on a
	 * different VF, so exclude it from the compatibility check.
	 * (sdxi_start() uses the destination's live SFUNC for P2V restart.)
	 */
	if ((le64_to_cpu(b->cap0) & ~SDXI_MMIO_CAP0_SFUNC) !=
		(dst_cap0 & ~SDXI_MMIO_CAP0_SFUNC) ||
	    le64_to_cpu(b->cap1) != dst_cap1) {
		dev_err(sdxi_dev(s),
			"restore: capability mismatch (src cap0=0x%llx cap1=0x%llx, dst cap0=0x%llx cap1=0x%llx)\n",
			le64_to_cpu(b->cap0), le64_to_cpu(b->cap1),
			dst_cap0, dst_cap1);
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
	err_cfg = le64_to_cpu(b->err_cfg);

	sdxi_write64(s, SDXI_MMIO_CTL2,    le64_to_cpu(b->ctl2));
	sdxi_write64(s, SDXI_MMIO_CXT_L2,  le64_to_cpu(b->cxt_l2));
	sdxi_write64(s, SDXI_MMIO_RKEY,    le64_to_cpu(b->rkey));
	sdxi_write64(s, SDXI_MMIO_ERR_CFG, err_cfg & ~SDXI_MMIO_ERR_CFG_EN);
	sdxi_write64(s, SDXI_MMIO_ERR_WRT, le64_to_cpu(b->err_wrt));
	sdxi_write64(s, SDXI_MMIO_ERR_RD,  le64_to_cpu(b->err_rd));
	sdxi_write64(s, SDXI_MMIO_ERR_CFG, err_cfg);
	sdxi_write64(s, SDXI_MMIO_ERR_CTL, le64_to_cpu(b->err_ctl));
	sdxi_write64(s, SDXI_MMIO_CTL0,    le64_to_cpu(b->ctl0));

	return sdxi_restore_context_status(s, b);
}

static int sdxi_mig_release(struct inode *inode, struct file *filp)
{
	struct sdxi_mig_file *m = filp->private_data;

	mutex_destroy(&m->lock);
	kvfree(m->blob);
	kfree(m);
	return 0;
}

static ssize_t sdxi_save_read(struct file *filp, char __user *buf,
			      size_t len, loff_t *pos)
{
	struct sdxi_mig_file *m = filp->private_data;
	ssize_t ret;

	guard(mutex)(&m->lock);

	if (m->precopy && !m->finalized) {
		if (m->pos == 0)
			return -ENOMSG;
		return 0;
	}

	if (!m->finalized)
		return -EINVAL;

	ret = simple_read_from_buffer(buf, len, &m->pos, m->blob, m->blob_len);
	return ret;
}

static long sdxi_save_precopy_ioctl(struct file *filp, unsigned int cmd,
				    unsigned long arg)
{
	struct sdxi_mig_file *m = filp->private_data;
	struct sdxi_vfio_pci_device *s = m->sdev;
	struct vfio_precopy_info info;
	enum vfio_device_mig_state state;
	int ret;

	ret = vfio_check_precopy_ioctl(&s->core_dev.vdev, cmd, arg, &info);
	if (ret)
		return ret;

	guard(mutex)(&s->state_mutex);
	state = s->state;
	if (state != VFIO_DEVICE_STATE_PRE_COPY &&
	    state != VFIO_DEVICE_STATE_PRE_COPY_P2P)
		return -EINVAL;

	guard(mutex)(&m->lock);

	info.dirty_bytes = 0;
	if (m->finalized)
		info.initial_bytes = m->blob_len - m->pos;
	else
		info.initial_bytes = 0;

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
	ssize_t ret;

	guard(mutex)(&m->lock);
	ret = simple_write_to_buffer(m->blob, m->blob_cap, &m->pos, buf, len);
	if (ret > 0 && m->pos >= sizeof(*m->blob)) {
		u32 nr = le32_to_cpu(m->blob->nr_cxt);
		size_t expect;

		if (nr > m->max_cxts)
			return -EINVAL;
		expect = sizeof(*m->blob) + nr * sizeof(m->blob->cxt[0]);
		if (m->pos > expect)
			return -EINVAL;
		if (m->pos == expect)
			m->valid = true;
	}
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
	size_t bytes;

	if (check_mul_overflow((size_t)max_cxts, sizeof(struct sdxi_mig_cxt_sts),
			       &bytes) ||
	    check_add_overflow(bytes, sizeof(struct sdxi_mig_blob), &bytes))
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
	m->blob_len = sizeof(*m->blob) +
		      le32_to_cpu(m->blob->nr_cxt) * sizeof(m->blob->cxt[0]);
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
		err = sdxi_start(s);
		return err ? ERR_PTR(err) : NULL;
	}

	if (cur == VFIO_DEVICE_STATE_PRE_COPY &&
	    next == VFIO_DEVICE_STATE_RUNNING) {
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

static void sdxi_vfio_close_device(struct vfio_device *vdev)
{
	struct sdxi_vfio_pci_device *s =
		container_of(vdev, struct sdxi_vfio_pci_device, core_dev.vdev);

	scoped_guard(mutex, &s->state_mutex) {
		sdxi_save_close(s);
		sdxi_mig_file_put(s->restore_file);
		s->restore_file = NULL;
	}

	if (s->bar0) {
		s->core_dev.skip_reset =
			sdxi_gsv_reset_hangs(sdxi_read64(s, SDXI_MMIO_STS0));
	} else {
		s->core_dev.skip_reset = false;
	}

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

	if (pause.flags == VFIO_DEVICE_FEATURE_SDXI_PAUSE_RESUME)
		return sdxi_start(s);

	if (pause.flags != VFIO_DEVICE_FEATURE_SDXI_PAUSE_DRAIN)
		return -EINVAL;

	/*
	 * A reset leaves CTL0 as all-ones until the function answers again.
	 * sdxi_stop() treats that as already stopped; do the same here so
	 * the drain does not poll a dead mapping.
	 */
	if (sdxi_read64(s, SDXI_MMIO_CTL0) == ~0ULL)
		return 0;

	timeout_ms = pause.timeout_ms ?: 30000;
	if (timeout_ms > 120000)
		timeout_ms = 120000;

	dev_info(sdxi_dev(s), "pause drain: waiting up to %u ms for GSV_STOP\n",
		 timeout_ms);
	ret = sdxi_fn_stop_timeout(sdxi_dev(s), s->bar0, timeout_ms);
	if (ret)
		dev_err(sdxi_dev(s), "pause drain failed: %d\n", ret);
	else
		dev_info(sdxi_dev(s), "pause drain: function stopped\n");
	return ret;
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

static struct pci_driver sdxi_vfio_pci_driver = {
	.name			= KBUILD_MODNAME,
	.id_table		= sdxi_vfio_pci_table,
	.probe			= sdxi_vfio_pci_probe,
	.remove			= sdxi_vfio_pci_remove,
	.sriov_configure	= sdxi_vfio_pci_sriov_configure,
	.err_handler		= &vfio_pci_core_err_handlers,
	.driver_managed_dma	= true,
};
module_pci_driver(sdxi_vfio_pci_driver);

MODULE_DESCRIPTION("VFIO variant driver for AMD SDXI PCI devices");
MODULE_AUTHOR("Tycho Andersen (AMD) <tycho@kernel.org>");
MODULE_LICENSE("GPL");
