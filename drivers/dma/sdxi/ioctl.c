// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI IOCTL Interface
 *
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#include <linux/anon_inodes.h>
#include <linux/cdev.h>
#include <linux/capability.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/minmax.h>
#include <linux/string.h>
#include <linux/sizes.h>
#include <linux/unaligned.h>
#include <linux/uaccess.h>
#include <uapi/linux/sdxi.h>

#include "admin.h"
#include "context.h"
#include "error.h"
#include "intr.h"
#include "ioctl.h"
#include "keys.h"
#include "process.h"
#include "sdxi.h"
#include "sysfs.h"
#include "vendor.h"

/*
 * Limit for total SDXI character devices (PFs + VFs) per system.
 */
#define SDXI_MAX_MINORS		1024

static const char sdxi_dev_name[] = "sdxi";
static const char sdxi_cxt_file_name[] = "sdxi-cxt";
static int sdxi_char_dev_major = -1;
static dev_t sdxi_devt;
static struct class *sdxi_class;
static DEFINE_IDA(sdxi_minor_ida);

static const struct file_operations sdxi_cxt_fops;

static void sdxi_cxt_vma_open_cb(struct vm_area_struct *vma)
{
	sdxi_cxt_vma_open(vma->vm_private_data);
}

static void sdxi_cxt_vma_close_cb(struct vm_area_struct *vma)
{
	sdxi_cxt_vma_close(vma->vm_private_data);
}

static const struct vm_operations_struct sdxi_cxt_vma_ops = {
	.open = sdxi_cxt_vma_open_cb,
	.close = sdxi_cxt_vma_close_cb,
};

static bool
sdxi_admin_vendor_reserved_zero(const struct sdxi_admin_vendor_args *args);

static void sdxi_cxt_vma_attach(struct vm_area_struct *vma,
				struct sdxi_cxt *cxt)
{
	vma->vm_ops = &sdxi_cxt_vma_ops;
	vma->vm_private_data = cxt;
	sdxi_cxt_vma_open(cxt);
}

/*********************/
/* SUPPORT FUNCTIONS */
/*********************/
/*
 * Context-fd ownership check.
 *
 * Every path that dereferences context-specific resources hanging off
 * filp->private_data must call this helper first. The current owner
 * is defined as the thread that issued "SDXI_CREATE_CXT" or in the
 * device-fd case, the thread that issued "open(/dev/sdxi*)".
 *
 * Returning "-EBADF" here is what stops a hostile or accidental fd
 * transfer via "fork()", "dup2()" + "execve()", etc. from being able
 * to drive the context.
 */
static int sdxi_file_check_owner(struct sdxi_process *process)
{
	if (!process)
		return -EINVAL;

	if ((process->lead_thread != current->group_leader) ||
	    (process->mm != current->mm))
		return -EBADF;

	return 0;
}

static int sdxi_cxt_doorbell_mmap(struct sdxi_process *process,
				  struct sdxi_cxt *cxt,
				  struct vm_area_struct *vma)
{
	struct sdxi_dev *sdxi = cxt->sdxi;
	phys_addr_t address;
	int ret;

	if (vma->vm_end - vma->vm_start != sdxi->db_stride)
		return -EINVAL;

	if (!(vma->vm_flags & VM_WRITE) || (vma->vm_flags & VM_EXEC))
		return -EPERM;

	address = cxt->db_base;

	vm_flags_set(vma, VM_IO | VM_DONTCOPY | VM_DONTEXPAND | VM_NORESERVE |
		     VM_DONTDUMP | VM_PFNMAP);

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_pgoff = 0;

	pr_debug("pasid 0x%x mapping mmio page (dev=%s)\n"
		 "     target user address == 0x%08llX\n"
		 "     physical address    == %pa\n"
		 "     vm_flags            == 0x%04lX\n"
		 "     size                == 0x%04lX\n",
		 process->pasid, dev_name(sdxi_to_dev(sdxi)),
		 (unsigned long long) vma->vm_start, &address,
		 vma->vm_flags, PAGE_SIZE);

	ret = io_remap_pfn_range(vma,
				 vma->vm_start,
				 address >> PAGE_SHIFT,
				 sdxi->db_stride,
				 vma->vm_page_prot);
	if (!ret)
		sdxi_cxt_vma_attach(vma, cxt);

	return ret;
}

static int sdxi_ioctl_get_uapi_info(struct file *filep,
				    struct sdxi_file *sf, void *data)
{
	struct sdxi_uapi_info_args *args = data;
	u64 caps0;

	if (args->flags)
		return -EINVAL;

	if (args->argsz < sizeof(*args))
		return -EINVAL;

	caps0 = SDXI_UAPI_CAP_DEV_INFO |
		SDXI_UAPI_CAP_DEV_ATTR_MGMT |
		SDXI_UAPI_CAP_RKEY_MGMT |
		SDXI_UAPI_CAP_CXT_CREATE |
		SDXI_UAPI_CAP_CXT_EVENTFD |
		SDXI_UAPI_CAP_AKEY_MGMT |
		SDXI_UAPI_CAP_ADMIN_DISC |
		SDXI_UAPI_CAP_ADMIN_VENDOR;

	args->argsz = sizeof(*args);
	args->uapi_major = SDXI_UAPI_MAJOR;
	args->uapi_minor = SDXI_UAPI_MINOR;
	args->cap_words = SDXI_UAPI_CAP_WORDS;
	args->rsvd0 = 0;

	memset(args->caps, 0, sizeof(args->caps));
	args->caps[0] = caps0;

	return 0;
}

static int sdxi_ioctl_get_dev_info(struct file *filep,
				   struct sdxi_file *sf, void *data)
{
	struct sdxi_dev_info_args *args = data;
	struct sdxi_process *p = sf->process;
	struct sdxi_dev *sdxi = p->sdxi;
	u64 version;

	if (!sdxi)
		return -ENODEV;

	if (args->flags)
		return -EINVAL;

	if (args->argsz < sizeof(*args))
		return -EINVAL;

	version = sdxi_read64(sdxi, SDXI_MMIO_VERSION);
	args->hw_major = FIELD_GET(SDXI_MMIO_VERSION_MAJOR, version);
	args->hw_minor = FIELD_GET(SDXI_MMIO_VERSION_MINOR, version);

	args->cap0 = sdxi_read64(sdxi, SDXI_MMIO_CAP0);
	args->cap1 = sdxi_read64(sdxi, SDXI_MMIO_CAP1);
	args->sts0 = sdxi_read64(sdxi, SDXI_MMIO_STS0);

	args->argsz = sizeof(*args);

	return 0;
}

/*
 * Device attribute table backing SDXI_{GET,SET}_DEV_ATTR.
 *
 * Each row describes one attribute as a control-register field plus an
 * optional capability-register cap. Attributes that don't fit this design
 * provide a custom @get override (e.g. RKEY table size, which is fixed at
 * driver init).
 */
enum {
	SDXI_DEV_ATTR_F_RO = BIT(0),	/* attribute is read-only */
};

struct sdxi_dev_attr_desc {
	u32 reg;			/* CTL register; 0 if @get is set */
	u64 mask;			/* field mask within @reg */
	u32 cap_reg;			/* CAP register; 0 if no cap check */
	u64 cap_mask;			/* field mask within @cap_reg */
	unsigned int flags;
	int (*get)(struct sdxi_dev *sdxi, u64 *val);
};

static int sdxi_dev_attr_get_max_rkey_sz(struct sdxi_dev *sdxi, u64 *val)
{
	*val = sdxi->rkey_cap ? sdxi->rkey_entries : 0;
	return 0;
}

static const struct sdxi_dev_attr_desc sdxi_dev_attr_table[] = {
	[SDXI_DEV_ATTR_GSR] = {
		.reg  = SDXI_MMIO_CTL0,
		.mask = SDXI_MMIO_CTL0_FN_GSR,
	},
	[SDXI_DEV_ATTR_GRP_ID] = {
		.reg  = SDXI_MMIO_CTL0,
		.mask = SDXI_MMIO_CTL0_FN_GRP_ID,
	},
	[SDXI_DEV_ATTR_MAX_BUFFER] = {
		.reg      = SDXI_MMIO_CTL2,
		.mask     = SDXI_MMIO_CTL2_MAX_BUFFER,
		.cap_reg  = SDXI_MMIO_CAP1,
		.cap_mask = SDXI_MMIO_CAP1_MAX_BUFFER,
	},
	[SDXI_DEV_ATTR_MAX_AKEY_SZ] = {
		.reg      = SDXI_MMIO_CTL2,
		.mask     = SDXI_MMIO_CTL2_MAX_AKEY_SZ,
		.cap_reg  = SDXI_MMIO_CAP1,
		.cap_mask = SDXI_MMIO_CAP1_MAX_AKEY_SZ,
	},
	[SDXI_DEV_ATTR_MAX_RKEY_SZ] = {
		.flags = SDXI_DEV_ATTR_F_RO,
		.get   = sdxi_dev_attr_get_max_rkey_sz,
	},
	[SDXI_DEV_ATTR_MAX_CXT] = {
		.reg      = SDXI_MMIO_CTL2,
		.mask     = SDXI_MMIO_CTL2_MAX_CXT,
		.cap_reg  = SDXI_MMIO_CAP1,
		.cap_mask = SDXI_MMIO_CAP1_MAX_CXT,
	},
};

static const struct sdxi_dev_attr_desc *sdxi_dev_attr_lookup(u64 attr)
{
	const struct sdxi_dev_attr_desc *d;

	if (!attr || attr >= ARRAY_SIZE(sdxi_dev_attr_table))
		return NULL;

	d = &sdxi_dev_attr_table[attr];

	if (!d->mask && !d->get)
		return NULL;

	return d;
}

static int sdxi_dev_attr_read(struct sdxi_dev *sdxi,
			      const struct sdxi_dev_attr_desc *d, u64 *val)
{
	if (d->get)
		return d->get(sdxi, val);

	*val = (sdxi_read64(sdxi, d->reg) & d->mask) >> __ffs64(d->mask);

	return 0;
}

static int sdxi_dev_attr_write(struct sdxi_dev *sdxi,
			       const struct sdxi_dev_attr_desc *d, u64 val)
{
	u64 reg, shift, max_val;

	if (d->flags & SDXI_DEV_ATTR_F_RO)
		return -EOPNOTSUPP;

	shift = __ffs64(d->mask);
	max_val = d->mask >> shift;
	if (val > max_val)
		return -EINVAL;

	if (d->cap_reg) {
		u64 cap = (sdxi_read64(sdxi, d->cap_reg) & d->cap_mask) >>
			  __ffs64(d->cap_mask);

		if (val > cap)
			return -EINVAL;
	}

	reg = sdxi_read64(sdxi, d->reg);
	reg = (reg & ~d->mask) | ((val << shift) & d->mask);
	sdxi_write64(sdxi, d->reg, reg);

	return 0;
}

static bool sdxi_dev_attr_args_valid(const struct sdxi_dev_attr_args *args)
{
	size_t i;

	if (args->flags)
		return false;

	if (args->argsz < sizeof(*args))
		return false;

	for (i = 0; i < ARRAY_SIZE(args->rsvd0); i++)
		if (args->rsvd0[i])
			return false;

	return true;
}

static int sdxi_ioctl_get_dev_attr(struct file *filep,
				   struct sdxi_file *sf, void *data)
{
	struct sdxi_dev_attr_args *args = data;
	struct sdxi_process *p = sf->process;
	struct sdxi_dev *sdxi = p->sdxi;
	const struct sdxi_dev_attr_desc *d;

	if (!sdxi)
		return -ENODEV;

	if (!sdxi_dev_attr_args_valid(args))
		return -EINVAL;

	d = sdxi_dev_attr_lookup(args->attr);
	if (!d)
		return -EOPNOTSUPP;

	args->argsz = sizeof(*args);

	return sdxi_dev_attr_read(sdxi, d, &args->val);
}

static int sdxi_ioctl_set_dev_attr(struct file *filep,
				   struct sdxi_file *sf, void *data)
{
	struct sdxi_dev_attr_args *args = data;
	struct sdxi_process *p = sf->process;
	struct sdxi_dev *sdxi = p->sdxi;
	const struct sdxi_dev_attr_desc *d;
	int err;

	if (!sdxi)
		return -ENODEV;

	if (!sdxi_dev_attr_args_valid(args))
		return -EINVAL;

	d = sdxi_dev_attr_lookup(args->attr);
	if (!d)
		return -EOPNOTSUPP;

	err = sdxi_dev_attr_write(sdxi, d, args->val);
	if (err)
		return err;

	args->argsz = sizeof(*args);
	/* Reflect the value actually applied (the device may mask bits). */

	return sdxi_dev_attr_read(sdxi, d, &args->val);
}
