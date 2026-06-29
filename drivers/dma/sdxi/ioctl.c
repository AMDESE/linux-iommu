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
#include <linux/uuid.h>
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

static bool sdxi_u32_array_zero(const u32 *data, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (data[i])
			return false;
	}

	return true;
}

#define SDXI_OP_GROUP_DISC_TIMEOUT_MS	5000U

enum sdxi_op_group_user_policy {
	SDXI_OP_GROUP_UNKNOWN = 0,
	SDXI_OP_GROUP_USER,
	SDXI_OP_GROUP_ADMIN_ONLY,
};

struct sdxi_op_group_policy {
	guid_t guid;
	enum sdxi_op_group_user_policy policy;
};

static const struct sdxi_op_group_policy sdxi_op_group_policies[] = {
	/* SDXI standard dataplane operation groups. */
	{ GUID_INIT(0x193259fe, 0x150b, 0x4008, 0xa8, 0x3f, 0x6f, 0xaf, 0x59,
		    0xf5, 0x27, 0x2a),  SDXI_OP_GROUP_USER },
	{ GUID_INIT(0xd9bc29a1, 0x91dc, 0x4243, 0x97, 0x51, 0xb6, 0xb0, 0x32,
		    0x9d, 0xaf, 0xe1), SDXI_OP_GROUP_USER },
	{ GUID_INIT(0x3ac7630e, 0x7009, 0x424b, 0x82, 0x99, 0x20, 0xe2, 0x90,
		    0x1e, 0xcc, 0x5e), SDXI_OP_GROUP_USER },
	{ GUID_INIT(0x7fb16347, 0x4c3a, 0x4d16, 0x84, 0x42, 0xcb, 0xa5, 0x1e,
		    0x34, 0x08, 0x80), SDXI_OP_GROUP_USER },
	{ GUID_INIT(0x0af23293, 0x7595, 0x4939, 0xb0, 0x8a, 0x1c, 0x72, 0x93,
		    0xc2, 0xe9, 0x75), SDXI_OP_GROUP_USER },
	{ GUID_INIT(0x989b9a64, 0x28d9, 0x4294, 0x9c, 0x7b, 0x9a, 0x3f, 0x27,
		    0xaf, 0xaf, 0x5c), SDXI_OP_GROUP_USER },
	{ GUID_INIT(0x15114db9, 0x4a7e, 0x47ab, 0x97, 0xdd, 0xea, 0x86, 0xed,
		    0xa1, 0x0b, 0x6e), SDXI_OP_GROUP_USER },
	/* AMD dataplane extensions whose buffers are AKey/context scoped. */
	{ GUID_INIT(0xb3e551a3, 0xf1a9, 0x4c9a, 0x82, 0x52, 0xda, 0xf5, 0xc0,
		    0xd9, 0x1a, 0x44), SDXI_OP_GROUP_USER },
	{ GUID_INIT(0x2595c4dc, 0x6fac, 0x49d2, 0xa3, 0x31, 0xb1, 0x40, 0x0a,
		    0x7f, 0x69, 0x0f), SDXI_OP_GROUP_USER },
	/* AMD ASQOSE is PF-admin-context only. */
	{ GUID_INIT(0xf5b7610b, 0x0dc6, 0x4c03, 0xab, 0x79, 0x65, 0xf1, 0xf4,
		    0xef, 0xcf, 0x4c), SDXI_OP_GROUP_ADMIN_ONLY },
};

static enum sdxi_op_group_user_policy
sdxi_ucxt_op_group_policy(const guid_t *guid)
{
	size_t i;

	if (guid_is_null(guid))
		return SDXI_OP_GROUP_UNKNOWN;

	for (i = 0; i < ARRAY_SIZE(sdxi_op_group_policies); i++) {
		if (guid_equal(guid, &sdxi_op_group_policies[i].guid))
			return sdxi_op_group_policies[i].policy;
	}

	return SDXI_OP_GROUP_UNKNOWN;
}

static int sdxi_ucxt_discover_op_groups(struct sdxi_dev *sdxi, u32 available,
					u32 *allowed, u32 *deny)
{
	u16 first = 1, last = 31;
	size_t record_size = sizeof(guid_t);
	size_t size = (size_t)(last - first + 1) * record_size;
	dma_addr_t dma;
	u8 *buf;
	u16 index;
	int err;

	if (!sdxi_dev_compatible(sdxi, SDXI_VERSION_1_1))
		return 0;
	if (!(available & SDXI_OPB_000_DISC_MASK))
		return 0;

	buf = dma_alloc_coherent(sdxi_to_dev(sdxi), size, &dma, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	err = sdxi_adm_disc(sdxi, first, last, dma,
			    SDXI_OP_GROUP_DISC_TIMEOUT_MS, NULL);
	if (err)
		goto out_free;

	dma_rmb();
	for (index = first; index <= last; index++) {
		enum sdxi_op_group_user_policy policy;
		guid_t guid;
		u32 bit;

		bit = BIT(index);
		if (!(available & bit))
			continue;

		import_guid(&guid, buf + (size_t)(index - first) * record_size);
		policy = sdxi_ucxt_op_group_policy(&guid);
		switch (policy) {
		case SDXI_OP_GROUP_USER:
			*allowed |= bit;
			break;
		case SDXI_OP_GROUP_ADMIN_ONLY:
			*deny |= bit;
			break;
		default:
			break;
		}
	}

out_free:
	dma_free_coherent(sdxi_to_dev(sdxi), size, buf, dma);
	return err;
}

static int sdxi_ucxt_op_groups(struct sdxi_dev *sdxi, u32 requested,
			       u32 *opb_000_enb, u32 *applied)
{
	u32 available;
	u32 allowed = 0;
	u32 deny = SDXI_OPB_000_ADMIN;
	u32 enabled;
	bool default_request = !requested;
	int err;

	available = (u32)FIELD_GET(SDXI_MMIO_CTL2_OPB_000_AVL,
				   sdxi_read64(sdxi, SDXI_MMIO_CTL2));

	allowed |= available & SDXI_OPB_000_INTR;
	if (sdxi->atomic_ops_enabled)
		allowed |= available & SDXI_OPB_000_ATOMIC;

	err = sdxi_ucxt_discover_op_groups(sdxi, available, &allowed,
					       &deny);
	if (err && !default_request && (requested & SDXI_OPB_000_DISC_MASK))
		return err;

	if (default_request)
		requested = allowed;

	if (requested & deny)
		return -EPERM;
	if (requested & ~available)
		return -EINVAL;

	if ((requested & SDXI_OPB_000_ATOMIC) && !sdxi->atomic_ops_enabled)
		return -EOPNOTSUPP;
	if (requested & ~allowed)
		return -EOPNOTSUPP;

	enabled = requested;

	if (opb_000_enb)
		*opb_000_enb = enabled;
	if (applied)
		*applied = enabled;

	return 0;
}

static int sdxi_ioctl_create_cxt(struct file *filep,
				 struct sdxi_file *sf, void *data)
{
	struct sdxi_process *p = sf->process;
	struct sdxi_create_cxt_args *args = data;
	struct sdxi_file *cxt_sf = NULL;
	struct sdxi_cxt *cxt;
	bool bound = false;
	u32 ring_entries;
	size_t ring_bytes;
	size_t remaining;
	u32 opb_000_enb;
	u32 applied_op_groups;
	u16 intr_flags;
	int cxt_fd = -1;
	struct iommu_sva *unbind_sva = NULL;
	u32 pasid;
	u32 unbind_pasid = 0;
	int err = 0;

	if (!p->sdxi)
		return -ENODEV;

	if (args->argsz < sizeof(*args))
		return -EINVAL;
	if (args->flags)
		return -EINVAL;

	args->argsz = sizeof(*args);

	if (p->sdxi->db_stride < PAGE_SIZE)
		return -EOPNOTSUPP;

	err = sdxi_ucxt_op_groups(p->sdxi, args->opb_000_enb, &opb_000_enb,
				  &applied_op_groups);
	if (err)
		return err;

	ring_entries = args->ds_ring_entries;
	if (!ring_entries)
		ring_entries = SZ_1K;

	/* validate ds_ring size */
	if ((ring_entries < SZ_1K) || (ring_entries > p->sdxi->max_ring_entries))
		return -EINVAL;

	ring_bytes = (size_t)ring_entries * sizeof(struct sdxi_desc);

	if (!args->ds_ring_base || !args->write_index_base || !args->cxt_sts_base)
		return -EINVAL;

	if (!IS_ALIGNED(args->ds_ring_base, BIT_ULL(DESC_RING_BASE_PTR_SHIFT)) ||
	    !IS_ALIGNED(args->write_index_base, BIT_ULL(WRT_INDEX_PTR_SHIFT)) ||
	    !IS_ALIGNED(args->cxt_sts_base, BIT_ULL(CXT_STATUS_PTR_SHIFT)))
		return -EINVAL;

	if (!access_ok((void __user *)(uintptr_t)args->ds_ring_base, ring_bytes) ||
	    !access_ok((void __user *)(uintptr_t)args->write_index_base, sizeof(__le64)) ||
	    !access_ok((void __user *)(uintptr_t)args->cxt_sts_base, sizeof(struct sdxi_cxt_sts)))
		return -EFAULT;

	mutex_lock(&p->mutex);

	if (p->cxt) {
		err = -EBUSY;
		goto out_unlock;
	}

	if (!p->sva) {
		err = sdxi_bind_process_to_device(p);
		if (err)
			goto out_unlock;
		bound = true;
	}

	if (p->pasid > 0xFFFFF) {
		err = -EINVAL;
		goto out_unbind;
	}

	cxt = sdxi_ucxt_new(p->sdxi, ring_entries, args->ds_ring_base,
			    args->write_index_base, args->cxt_sts_base,
			    p->pasid, opb_000_enb);

	if (!cxt) {
		err = -ENOMEM;
		goto out_unbind;
	}

	if (WARN_ON_ONCE(cxt->id == SDXI_ADMIN_CXT_ID)) {
		err = -EPERM;
		goto out_free_context;
	}

	if (applied_op_groups & SDXI_OPB_000_INTR) {
		err = sdxi_cxt_init_intr(cxt);
		if (err)
			goto out_free_context;
	}

	remaining = clear_user((void __user *)(uintptr_t)args->write_index_base,
			       sizeof(__le64));
	remaining |= clear_user((void __user *)(uintptr_t)args->cxt_sts_base,
				sizeof(struct sdxi_cxt_sts));
	if (remaining) {
		err = -EFAULT;
		goto out_free_context;
	}

	err = sdxi_adm_start_cxt(cxt);
	if (err)
		goto out_free_context;

	/* Setup the default local userspace AKey used by libsdxi helpers. */
	pasid = FIELD_PREP(SDXI_AKEY_ENT_PASID, p->pasid);
	intr_flags = (FIELD_PREP(SDXI_AKEY_ENT_VL, 1) |
		      FIELD_PREP(SDXI_AKEY_ENT_PV, 1));
	cxt->akey_table->entry[1] = (struct sdxi_akey_ent) {
		.intr_num = cpu_to_le16(intr_flags),
		.pasid = cpu_to_le32(pasid),
	};

	cxt_sf = kzalloc_obj(*cxt_sf, GFP_KERNEL);
	if (!cxt_sf) {
		err = -ENOMEM;
		goto out_free_context;
	}

	cxt_sf->type = SDXI_FILE_CONTEXT;
	cxt_sf->process = p;
	cxt_sf->cxt = cxt;

	cxt->process = p;
	p->cxt = cxt;
	sdxi_get_process(p);
	sdxi_get_process(p);
	sdxi_cxt_get(cxt);

	cxt_fd = anon_inode_getfd(sdxi_cxt_file_name, &sdxi_cxt_fops, cxt_sf,
				  O_RDWR | O_CLOEXEC);
	if (cxt_fd < 0) {
		sdxi_working_cxt_exit(cxt);
		sdxi_cxt_put(cxt);
		sdxi_put_process(p);
		kfree(cxt_sf);
		err = cxt_fd;
		goto out_unlock;
	}

	/* return values to caller */
	args->flags = 0;
	args->opb_000_enb = applied_op_groups;
	args->pasid = p->pasid;
	args->cxt_fd = cxt_fd;
	args->ds_ring_entries = ring_entries;
	args->doorbell_mmap_base = sdxi_mmap_token(SDXI_MMAP_TYPE_DOORBELL,
						   cxt->id, cxt->mmap_gen);

	mutex_unlock(&p->mutex);

	pr_debug("Context id %u was created successfully\n", cxt->id);
	return 0;

out_free_context:
	sdxi_working_cxt_exit(cxt);
	kfree(cxt_sf);

out_unbind:
	if (bound)
		unbind_sva = sdxi_process_detach_sva_locked(p, &unbind_pasid);

out_unlock:
	mutex_unlock(&p->mutex);
	sdxi_process_unbind_sva(p, unbind_sva, unbind_pasid);
	return err;
}

static int sdxi_ioctl_quiesce_cxt(struct file *filep,
				  struct sdxi_file *sf, void *data)
{
	struct sdxi_quiesce_cxt_args *args = data;

	if (!sf->cxt)
		return -ENODEV;
	if (args->argsz < sizeof(*args))
		return -EINVAL;
	if (args->flags)
		return -EINVAL;

	args->argsz = sizeof(*args);

	return sdxi_cxt_quiesce(sf->cxt, args->timeout_ms, &args->cst_flags);
}

static int sdxi_ioctl_cxt_eventfd(struct file *filep,
				  struct sdxi_file *sf, void *data)
{
	struct sdxi_cxt_eventfd_args *args = data;
	struct sdxi_cxt *cxt = sf->cxt;

	if (!cxt)
		return -ENODEV;

	if (args->argsz < sizeof(*args))
		return -EINVAL;
	if (args->flags)
		return -EINVAL;
	if (args->rsvd0)
		return -EINVAL;
	if (!sdxi_u32_array_zero(args->rsvd1, ARRAY_SIZE(args->rsvd1)))
		return -EINVAL;

	args->argsz = sizeof(*args);

return sdxi_cxt_set_intr_fd(cxt, args->eventfd,
				    &args->intr_akey, &args->intr_num);
}
