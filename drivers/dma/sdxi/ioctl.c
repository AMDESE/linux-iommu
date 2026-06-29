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
