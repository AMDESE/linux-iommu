// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO variant driver for AMD SDXI PCI devices supporting
 * VFIO_MIGRATION_STOP_COPY.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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
#include <linux/uaccess.h>
#include <linux/vfio.h>
#include <linux/vfio_pci_core.h>

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

	return 0;
}

static int sdxi_mig_release(struct inode *inode, struct file *filp)
{
	struct sdxi_mig_file *m = filp->private_data;

	mutex_destroy(&m->lock);
	kfree(m);
	return 0;
}

static ssize_t sdxi_save_read(struct file *filp, char __user *buf,
			      size_t len, loff_t *pos)
{
	struct sdxi_mig_file *m = filp->private_data;
	ssize_t ret;

	guard(mutex)(&m->lock);
	ret = simple_read_from_buffer(buf, len, &m->pos, &m->blob, sizeof(m->blob));
	return ret;
}

static const struct file_operations sdxi_save_fops = {
	.owner   = THIS_MODULE,
	.read    = sdxi_save_read,
	.release = sdxi_mig_release,
};

static ssize_t sdxi_restore_write(struct file *filp, const char __user *buf,
				  size_t len, loff_t *pos)
{
	struct sdxi_mig_file *m = filp->private_data;
	ssize_t ret;

	guard(mutex)(&m->lock);
	ret = simple_write_to_buffer(&m->blob, sizeof(m->blob), &m->pos, buf, len);
	if (ret > 0 && m->pos == sizeof(m->blob))
		m->valid = true;
	return ret;
}

static const struct file_operations sdxi_restore_fops = {
	.owner   = THIS_MODULE,
	.write   = sdxi_restore_write,
	.release = sdxi_mig_release,
};

static struct sdxi_mig_file *
sdxi_mig_file_alloc(const struct file_operations *fops, int flags)
{
	struct sdxi_mig_file *m;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return ERR_PTR(-ENOMEM);

	mutex_init(&m->lock);
	m->filp = anon_inode_getfile("sdxi_vfio_mig", fops, m, flags);
	if (IS_ERR(m->filp)) {
		int err = PTR_ERR(m->filp);

		mutex_destroy(&m->lock);
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

	if (cur == VFIO_DEVICE_STATE_STOP &&
	    next == VFIO_DEVICE_STATE_STOP_COPY) {
		m = sdxi_mig_file_alloc(&sdxi_save_fops, O_RDONLY);
		if (IS_ERR(m))
			return ERR_CAST(m);
		sdxi_save_regs(s, &m->blob);
		get_file(m->filp);
		s->save_file = m;
		return m->filp;
	}

	if (cur == VFIO_DEVICE_STATE_STOP_COPY &&
	    next == VFIO_DEVICE_STATE_STOP) {
		sdxi_mig_file_put(s->save_file);
		s->save_file = NULL;
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP &&
	    next == VFIO_DEVICE_STATE_RESUMING) {
		m = sdxi_mig_file_alloc(&sdxi_restore_fops, O_WRONLY);
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
		err = sdxi_restore_regs(s, &m->blob);
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
	*stop_copy_length = sizeof(struct sdxi_mig_blob);
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
	vdev->migration_flags = VFIO_MIGRATION_STOP_COPY;
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

static int sdxi_vfio_open_device(struct vfio_device *vdev)
{
	struct sdxi_vfio_pci_device *s =
		container_of(vdev, struct sdxi_vfio_pci_device, core_dev.vdev);
	struct pci_dev *pdev = s->core_dev.pdev;
	u64 sts0;
	enum sdxi_fn_gsv gsv;
	int err;

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
		sdxi_mig_file_put(s->save_file);
		s->save_file = NULL;
		sdxi_mig_file_put(s->restore_file);
		s->restore_file = NULL;
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

static const struct vfio_device_ops sdxi_vfio_ops = {
	.name			= KBUILD_MODNAME,
	.init			= sdxi_vfio_init_device,
	.release		= sdxi_vfio_release_device,
	.open_device		= sdxi_vfio_open_device,
	.close_device		= sdxi_vfio_close_device,
	.ioctl			= vfio_pci_core_ioctl,
	.get_region_info_caps	= vfio_pci_ioctl_get_region_info,
	.device_feature		= vfio_pci_core_ioctl_feature,
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
