// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Advanced Micro Devices, Inc.
 */

#include <linux/iommu.h>
#include <linux/amd-iommu.h>

#include "iommufd.h"
#include "amd_iommu.h"
#include "amd_viommu.h"
#include "amd_iommu_types.h"

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
	struct amd_iommu *iommu;

	if (viommu_type != IOMMU_VIOMMU_TYPE_AMD)
		return 0;

	iommu = get_amd_iommu_from_dev(dev);
	if (!amd_iommu_viommu_enabled(iommu))
		return 0;

	return VIOMMU_STRUCT_SIZE(struct amd_iommu_viommu, core);
}

int amd_iommufd_viommu_init(struct iommufd_viommu *viommu, struct iommu_domain *parent,
			    const struct iommu_user_data *user_data)
{
	int ret;
	unsigned long flags;
	phys_addr_t page_base;
	bool trans_devid_allocated = false;
	bool trans_dte_set = false;
	bool uninit_on_err = false;
	struct iommu_viommu_amd data = {};
	struct protection_domain *pdom = to_pdomain(parent);
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);
	struct amd_iommu *iommu = container_of(viommu->iommu_dev, struct amd_iommu, iommu);

	if (!amd_iommu_viommu_enabled(iommu))
		return -EOPNOTSUPP;

	if (!user_data)
		return -EINVAL;

	ret = iommu_copy_struct_from_user(&data, user_data,
					  IOMMU_VIOMMU_TYPE_AMD,
					  out_vfmmio_mmap_offset);
	if (ret)
		return ret;

	mutex_init(&aviommu->trans_devid_lock);
	mutex_init(&aviommu->vfctrl_lock);
	INIT_LIST_HEAD(&aviommu->pdom_list);
	xa_init_flags(&aviommu->gdomid_array, XA_FLAGS_ALLOC1);
	aviommu->parent = pdom;

	ret = amd_iommu_gid_alloc(iommu);
	if (ret < 0)
		goto err_gid;
	aviommu->gid = ret;

	page_base = amd_viommu_get_vfmmio_addr(iommu, aviommu->gid);
	if (!page_base) {
		ret = -EINVAL;
		goto err_mmap;
	}

	ret = iommufd_viommu_alloc_mmap(&aviommu->core,
					page_base, SZ_4K,
					&aviommu->vfmmio_mmap_offset);
	if (ret)
		goto err_mmap;

	data.out_vfmmio_mmap_offset = aviommu->vfmmio_mmap_offset;

	/* Reset vIOMMU MMIOs before the trans_devid is visible in the pool. */
	ret = amd_iommu_reset_vmmio(iommu, aviommu->gid);
	if (ret)
		goto err_trans_devid;

	mutex_lock(&aviommu->trans_devid_lock);
	ret = amd_iommu_trans_devid_alloc(iommu->pci_seg, aviommu);
	if (ret < 0) {
		mutex_unlock(&aviommu->trans_devid_lock);
		goto err_trans_devid;
	}
	trans_devid_allocated = true;
	aviommu->trans_devid = ret;

	ret = amd_iommu_set_translate_dte(viommu);
	if (ret)
		goto err_init_unlock;
	trans_dte_set = true;
	amd_iommu_update_vfctrl_mmio_translate_devid(iommu, aviommu->gid,
						     aviommu->trans_devid);
	mutex_unlock(&aviommu->trans_devid_lock);

	ret = amd_viommu_init_one(iommu, aviommu);
	if (ret)
		goto err_init;
	uninit_on_err = true;

	ret = iommu_copy_struct_to_user(user_data, &data,
					IOMMU_VIOMMU_TYPE_AMD,
					out_vfmmio_mmap_offset);
	if (ret)
		goto err_init;

	viommu->ops = &amd_viommu_ops;

	return 0;
err_init:
	mutex_lock(&aviommu->trans_devid_lock);
err_init_unlock:
	if (trans_dte_set) {
		spin_lock_irqsave(&pdom->lock, flags);
		if (!list_empty(&aviommu->pdom_list))
			list_del_init(&aviommu->pdom_list);
		spin_unlock_irqrestore(&pdom->lock, flags);
		amd_iommu_update_vfctrl_mmio_translate_devid(iommu, aviommu->gid, 0);
		amd_iommu_clear_translate_dte(iommu, aviommu->trans_dev_data,
					      aviommu->trans_devid);
		amd_iommu_free_dev_data(iommu, aviommu->trans_dev_data);
		aviommu->trans_dev_data = NULL;
	}
	if (trans_devid_allocated)
		amd_iommu_trans_devid_free(iommu->pci_seg, aviommu->trans_devid,
					   aviommu);
	mutex_unlock(&aviommu->trans_devid_lock);
	if (uninit_on_err)
		amd_viommu_uninit_one(iommu, aviommu);
err_trans_devid:
	iommufd_viommu_destroy_mmap(&aviommu->core, aviommu->vfmmio_mmap_offset);
err_mmap:
	amd_iommu_gid_free(iommu, aviommu->gid);
err_gid:
	mutex_destroy(&aviommu->trans_devid_lock);
	mutex_destroy(&aviommu->vfctrl_lock);
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

	mutex_lock(&aviommu->trans_devid_lock);
	amd_iommu_update_vfctrl_mmio_translate_devid(iommu, aviommu->gid, 0);
	amd_iommu_clear_translate_dte(iommu, aviommu->trans_dev_data,
				      aviommu->trans_devid);
	amd_iommu_free_dev_data(iommu, aviommu->trans_dev_data);
	aviommu->trans_dev_data = NULL;
	amd_iommu_trans_devid_free(iommu->pci_seg, aviommu->trans_devid,
				   aviommu);
	mutex_unlock(&aviommu->trans_devid_lock);

	amd_viommu_uninit_one(iommu, aviommu);
	amd_iommu_gid_free(iommu, aviommu->gid);
	mutex_destroy(&aviommu->trans_devid_lock);
	mutex_destroy(&aviommu->vfctrl_lock);
}

/*
 * Called from drivers/iommu/iommufd/viommu.c: iommufd_vdevice_abort()
 *
 * Restore an idle DevID map entry for this virt_id. Every DevID mapping
 * table slot must have V=1 for both active and non-active devices. A
 * non-valid entry raises INVALID_DEVICE_REQUEST when the IOMMU processes
 * INVALIDATE_IOMMU_ALL. Use host device ID 0: that RID is the IOMMU PCI
 * function and does not normally host an endpoint.
 */
static void _amd_viommu_vdevice_destroy(struct iommufd_vdevice *vdev)
{
	struct iommufd_viommu *viommu = vdev->viommu;
	struct amd_iommu_viommu *aviommu =
		container_of(viommu, struct amd_iommu_viommu, core);

	amd_viommu_set_device_mapping(aviommu, 0, (u16)vdev->virt_id);
}

/*
 * Called from drivers/iommu/iommufd/viommu.c: iommufd_vdevice_alloc_ioctl()
 */
static int _amd_viommu_vdevice_init(struct iommufd_vdevice *vdev)
{
	struct device *dev = iommufd_vdevice_to_device(vdev);
	struct pci_dev *pdev;
	struct iommufd_viommu *viommu = vdev->viommu;
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);

	if (!dev_is_pci(dev))
		return -EINVAL;
	pdev = to_pci_dev(dev);

	if (vdev->virt_id > VIOMMU_MAX_GDEVID) {
		pr_err("%s: Invalid virtual ID (virt_id=%#llx)\n", __func__, vdev->virt_id);
		return -EINVAL;
	}

	pr_debug("%s: gid=%#x, hdev_id=%#x, gdev_id=%#llx\n", __func__,
		 aviommu->gid, pci_dev_id(pdev), vdev->virt_id);

	amd_viommu_set_device_mapping(aviommu, pci_dev_id(pdev),
				      (u16)vdev->virt_id);
	vdev->destroy = _amd_viommu_vdevice_destroy;

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

static u32 amd_iommufd_get_hw_queue_flags(struct iommufd_viommu *viommu,
					   enum iommu_hw_queue_type queue_type)
{
	switch (queue_type) {
	case IOMMU_HW_QUEUE_TYPE_AMD_CMD:
		return AMD_HW_QUEUE_FLAGS_CMD;
	case IOMMU_HW_QUEUE_TYPE_AMD_EVT:
		return AMD_HW_QUEUE_FLAGS_EVT;
	case IOMMU_HW_QUEUE_TYPE_AMD_PPR:
		return AMD_HW_QUEUE_FLAGS_PPR;
	default:
		return 0;
	}
}

static int amd_iommufd_hw_queue_init(struct iommufd_hw_queue *hw_queue, u32 index)
{
	int ret = 0;

	if (index)
		return -EINVAL;

	switch (hw_queue->type) {
	case IOMMU_HW_QUEUE_TYPE_AMD_CMD:
		ret = amd_viommu_set_cmdbuf_flags(hw_queue);
		break;
	case IOMMU_HW_QUEUE_TYPE_AMD_EVT:
		ret = amd_viommu_set_evtbuf_flags(hw_queue);
		break;
	case IOMMU_HW_QUEUE_TYPE_AMD_PPR:
		ret = amd_viommu_set_pprbuf_flags(hw_queue);
		break;
	default:
		ret = -EINVAL;
		break;
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
	.get_hw_queue_flags = amd_iommufd_get_hw_queue_flags,
	.hw_queue_init = amd_iommufd_hw_queue_init,
};
