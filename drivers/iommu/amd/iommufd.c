// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Advanced Micro Devices, Inc.
 */

#include <linux/iommu.h>
#include <linux/file.h>
#include <linux/amd-iommu.h>

#include "iommufd.h"
#include "amd_iommu.h"
#include "amd_viommu.h"
#include "amd_iommu_types.h"
#include "../iommufd/iommufd_private.h"

static const struct iommufd_viommu_ops amd_viommu_ops;

void *amd_iommufd_hw_info(struct device *dev, u32 *length, enum iommu_hw_info_type *type)
{
	struct iommu_hw_info_amd *hwinfo;

	if (*type != IOMMU_HW_INFO_TYPE_DEFAULT &&
	    *type != IOMMU_HW_INFO_TYPE_AMD)
		return ERR_PTR(-EOPNOTSUPP);

	hwinfo = kzalloc_obj(*hwinfo);
	if (!hwinfo)
		return ERR_PTR(-ENOMEM);

	*length = sizeof(*hwinfo);
	*type = IOMMU_HW_INFO_TYPE_AMD;

	hwinfo->efr = amd_iommu_efr;
	hwinfo->efr2 = amd_iommu_efr2;

	return hwinfo;
}

size_t amd_iommufd_get_viommu_size(struct device *dev, enum iommu_viommu_type viommu_type)
{
	if (!amd_iommu_viommu || (viommu_type != IOMMU_VIOMMU_TYPE_AMD))
		return 0;

	return VIOMMU_STRUCT_SIZE(struct amd_iommu_viommu, core);
}

static int amd_iommufd_set_ext_int_remap(struct iommufd_viommu *viommu,
					 const struct iommu_viommu_ext_int_remap *arg)
{
	struct fd f;
	struct kvm *kvm;
	enum ext_intremap_type type;
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);
	int ret;

	if (!svm_ops || !svm_ops->kvm_from_fd)
		return -ENODEV;

	switch (arg->type) {
	case IOMMU_VIOMMU_EXT_INT_EVENT:
		type = EXT_INTREMAP_EVENT;
		break;
	case IOMMU_VIOMMU_EXT_INT_PPR:
		type = EXT_INTREMAP_PPR;
		break;
	default:
		return -EINVAL;
	}

	kvm = svm_ops->kvm_from_fd(arg->kvmfd, &f);
	if (IS_ERR(kvm))
		return PTR_ERR(kvm);

	if (aviommu->ext_ir_kvm && aviommu->ext_ir_kvm != kvm) {
		ret = -EINVAL;
		goto out_fdput;
	}

	ret = amd_viommu_set_ext_int_remap_entry(viommu, kvm, type,
						 arg->vcpu_id, (u8)arg->vector);
	if (!ret && !aviommu->ext_ir_kvm)
		amd_viommu_attach_ext_ir_kvm(aviommu, kvm);

out_fdput:
	fdput(f);
	return ret;
}

int amd_iommufd_viommu_init(struct iommufd_viommu *viommu, struct iommu_domain *parent,
			    const struct iommu_user_data *user_data)
{
	int ret;
	phys_addr_t page_base;
	unsigned long flags;
	u16 trans_devid;
	bool trans_devid_allocated = false;
	bool trans_dte_set = false;
	struct iommu_viommu_amd data = {};
	struct protection_domain *pdom = to_pdomain(parent);
	struct amd_iommu *iommu = container_of(viommu->iommu_dev, struct amd_iommu, iommu);
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);

	xa_init_flags(&aviommu->gdomid_array, XA_FLAGS_ALLOC1);
	aviommu->parent = pdom;

	if (!user_data)
		return -EINVAL;

	ret = iommu_copy_struct_from_user(&data, user_data,
					  IOMMU_VIOMMU_TYPE_AMD,
					  out_vfmmio_mmap_offset);
	if (ret)
		return ret;

	ret = amd_iommu_gid_alloc(iommu);
	if (ret < 0)
		goto err_gid;
	aviommu->gid = ret;
	pr_debug("%s: gid=%#x", __func__, aviommu->gid);

	page_base = amd_viommu_get_vfmmio_addr(iommu, aviommu->gid);

	ret = iommufd_viommu_alloc_mmap(&aviommu->core,
					page_base, SZ_4K,
					&aviommu->vfmmio_mmap_offset);
	if (ret)
		goto err_mmap;

	data.out_vfmmio_mmap_offset = aviommu->vfmmio_mmap_offset;

	ret = amd_iommu_trans_devid_alloc(iommu->pci_seg);
	if (ret < 0)
		goto err_trans_devid;
	trans_devid = ret;
	trans_devid_allocated = true;
	aviommu->trans_devid = trans_devid;

	/* Reset vIOMMU MMIOs to initialize the vIOMMU */
	iommu_reset_vmmio(iommu, aviommu->gid);

	ret = amd_iommu_set_translate_dte(iommu, pdom, aviommu->gid, trans_devid);
	if (ret)
		goto err_init;
	trans_dte_set = true;
	amd_iommu_update_vfctrl_mmio_translate_devid(iommu, aviommu->gid, trans_devid);

	ret = amd_viommu_init_one(iommu, aviommu);
	if (ret)
		goto err_init;

	ret = iommu_copy_struct_to_user(user_data, &data,
					IOMMU_VIOMMU_TYPE_AMD,
					out_vfmmio_mmap_offset);
	if (ret)
		goto err_init;

	viommu->ops = &amd_viommu_ops;

	spin_lock_irqsave(&pdom->lock, flags);
	list_add(&aviommu->pdom_list, &pdom->viommu_list);
	spin_unlock_irqrestore(&pdom->lock, flags);

	return 0;
err_init:
	if (trans_dte_set) {
		amd_iommu_update_vfctrl_mmio_translate_devid(iommu, aviommu->gid, 0);
		amd_iommu_clear_translate_dte(iommu, trans_devid);
	}
	if (trans_devid_allocated)
		amd_iommu_trans_devid_free(iommu->pci_seg, trans_devid);
err_trans_devid:
	iommufd_viommu_destroy_mmap(&aviommu->core, aviommu->vfmmio_mmap_offset);
err_mmap:
	amd_iommu_gid_free(iommu, aviommu->gid);
err_gid:
	return ret;
}

static void amd_iommufd_viommu_destroy(struct iommufd_viommu *viommu)
{
	unsigned long flags;
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);
	struct protection_domain *pdom = aviommu->parent;
	struct amd_iommu *iommu = container_of(viommu->iommu_dev, struct amd_iommu, iommu);

	pr_debug("%s: gid=%#x, iommu devid=%#x\n", __func__, aviommu->gid, iommu->devid);

	spin_lock_irqsave(&pdom->lock, flags);
	list_del(&aviommu->pdom_list);
	spin_unlock_irqrestore(&pdom->lock, flags);
	xa_destroy(&aviommu->gdomid_array);
	iommufd_viommu_destroy_mmap(&aviommu->core, aviommu->vfmmio_mmap_offset);
	amd_viommu_uninit_one(iommu, aviommu);
	amd_iommu_clear_translate_dte(iommu, aviommu->trans_devid);
	amd_iommu_trans_devid_free(iommu->pci_seg, aviommu->trans_devid);
	amd_iommu_gid_free(iommu, aviommu->gid);
}

/*
 * Called from drivers/iommu/iommufd/viommu.c: iommufd_vdevice_alloc_ioctl()
 */
static int _amd_viommu_vdevice_init(struct iommufd_vdevice *vdev)
{
	struct iommu_dev_data *dev_data;
	struct pci_dev *pdev = to_pci_dev(vdev->idev->dev);
	struct iommufd_viommu *viommu = vdev->viommu;
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);
	struct amd_iommu *iommu = container_of(viommu->iommu_dev, struct amd_iommu, iommu);

	if (!pdev) {
		pr_err("%s: not a PCI device\n", __func__);
		return -EINVAL;
	}

	dev_data = dev_iommu_priv_get(&pdev->dev);
	if (!dev_data) {
		pr_err("%s: Device not found (devid=%#x)\n",
		       __func__, pci_dev_id(pdev));
		return -EINVAL;
	}

	dev_data->gid = aviommu->gid;
	dev_data->gDevId = vdev->virt_id;
	pr_debug("%s: gid=%#x, hdev_id=%#x, gdev_id=%#x\n", __func__,
			 dev_data->gid, pci_dev_id(pdev), dev_data->gDevId);

	amd_viommu_set_device_mapping(iommu, pci_dev_id(pdev), dev_data->gid, dev_data->gDevId);

	return 0;
}

static size_t amd_iommufd_get_hw_queue_size(struct iommufd_viommu *viommu,
					    enum iommu_hw_queue_type queue_type)
{
	/* Currently do not support Eventlog B and PPRlog B */
	if ((queue_type != IOMMU_HW_QUEUE_TYPE_AMD_CMD) &&
	    (queue_type != IOMMU_HW_QUEUE_TYPE_AMD_EVT) &&
	    (queue_type != IOMMU_HW_QUEUE_TYPE_AMD_PPR))
		return 0;

	return HW_QUEUE_STRUCT_SIZE(struct amd_iommu_hw_queue, core);
}

static int amd_iommufd_hw_queue_init(struct iommufd_hw_queue *hw_queue, u32 index)
{
	int ret = 0;

	switch (hw_queue->type) {
	case IOMMU_HW_QUEUE_TYPE_AMD_CMD:
		amd_viommu_set_cmdbuf_flags(hw_queue);
		break;
	case IOMMU_HW_QUEUE_TYPE_AMD_EVT:
		amd_viommu_set_evtbuf_flags(hw_queue);
		break;
	case IOMMU_HW_QUEUE_TYPE_AMD_PPR:
		amd_viommu_set_pprbuf_flags(hw_queue);
		break;
	default:
		pr_err("%s: Invalid type (%#x)\n", __func__, hw_queue->type);
		ret = -EINVAL;
	}

	return ret;
}

/*
 * See include/linux/iommufd.h
 * struct iommufd_viommu_ops - vIOMMU specific operations
 */
static const struct iommufd_viommu_ops amd_viommu_ops = {
	.alloc_domain_nested = amd_iommu_alloc_domain_nested,
	.destroy = amd_iommufd_viommu_destroy,
	.vdevice_size = VDEVICE_STRUCT_SIZE(struct amd_iommu_vdevice, core),
	.vdevice_init = _amd_viommu_vdevice_init,
	.get_hw_queue_size = amd_iommufd_get_hw_queue_size,
	.hw_queue_init = amd_iommufd_hw_queue_init,
	.set_ext_int_remap = amd_iommufd_set_ext_int_remap,

};
