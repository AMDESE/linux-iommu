// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Advanced Micro Devices, Inc.
 */

#include <linux/iommu.h>

#include "iommufd.h"
#include "amd_iommu.h"
#include "amd_viommu.h"
#include "amd_iommu_types.h"
#include "../iommufd/iommufd_private.h"

static const struct iommufd_viommu_ops amd_viommu_ops;

void *amd_iommufd_hw_info(struct device *dev, u32 *length, u32 *type)
{
	struct iommu_hw_info_amd *hwinfo;

	if (*type != IOMMU_HW_INFO_TYPE_DEFAULT &&
	    *type != IOMMU_HW_INFO_TYPE_AMD)
		return ERR_PTR(-EOPNOTSUPP);

	hwinfo = kzalloc(sizeof(*hwinfo), GFP_KERNEL);
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
	if (viommu_type != IOMMU_VIOMMU_TYPE_AMD)
		return 0;

	return VIOMMU_STRUCT_SIZE(struct amd_iommu_viommu, core);
}

int amd_iommufd_viommu_init(struct iommufd_viommu *viommu, struct iommu_domain *parent,
			    const struct iommu_user_data *user_data)
{
	int ret;
	phys_addr_t page_base;
	unsigned long flags;
	struct iommu_viommu_amd data;
	struct protection_domain *pdom = to_pdomain(parent);
	struct amd_iommu *iommu = container_of(viommu->iommu_dev, struct amd_iommu, iommu);
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);

	xa_init_flags(&aviommu->gdomid_array, XA_FLAGS_ALLOC1);
	aviommu->parent = pdom;

	if (!user_data)
		return -EINVAL;

	ret = iommu_copy_struct_from_user(&data, user_data,
					  IOMMU_VIOMMU_TYPE_AMD,
					  reserved);
	if (ret)
		return ret;

	aviommu->gid = amd_iommu_gid_alloc();
	if (aviommu->gid < 0)
		return aviommu->gid;
	pr_debug("%s: gid=%#x", __func__, aviommu->gid);

	page_base = amd_viommu_get_vfmmio_addr(iommu, aviommu->gid);
	if (page_base <= 0)
		return -ENODEV;

	ret = iommufd_viommu_alloc_mmap(&aviommu->core,
					page_base, SZ_4K,
					(unsigned long *)&data.out_vfmmio_mmap_offset);
	if (ret)
		goto err_out;

	/* Reset vIOMMU MMIOs to initialize the vIOMMU */
	iommu_reset_vmmio(iommu, aviommu->gid);

	amd_iommu_set_translate_dte(iommu, aviommu->gid, pdom, data.trans_devid);

	/* Set translate devid in vfctrl mmio */
	writeq((data.trans_devid & 0xFFFFULL) << 16,
	       VIOMMU_VFCTRL_MMIO_BASE(iommu, aviommu->gid) +
	       VIOMMU_VFCTRL_GUEST_MISC_CONTROL_OFFSET);

	ret = amd_viommu_init_one(iommu, aviommu);
	if (ret)
		goto err_out;

	ret = iommu_copy_struct_to_user(user_data, &data,
					IOMMU_VIOMMU_TYPE_AMD,
					reserved);
	if (ret)
		goto free_mmap;

	aviommu->trans_devid = data.trans_devid;
	viommu->ops = &amd_viommu_ops;

	spin_lock_irqsave(&pdom->lock, flags);
	list_add(&aviommu->pdom_list, &pdom->viommu_list);
	spin_unlock_irqrestore(&pdom->lock, flags);

	return 0;
free_mmap:
	iommufd_viommu_destroy_mmap(&aviommu->core, data.out_vfmmio_mmap_offset);
err_out:
	amd_iommu_gid_free(aviommu->gid);
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
	amd_iommu_gid_free(aviommu->gid);
	amd_viommu_uninit_one(iommu, aviommu);
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
		pr_err();
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

static size_t _amd_viommu_get_hw_queue_size(struct iommufd_viommu *viommu,
					    enum iommu_hw_queue_type queue_type)
{
	/* Currently do not support Eventlog B and PPRlog B */
	if ((queue_type != IOMMU_HW_QUEUE_TYPE_AMD_CMD) &&
	    (queue_type != IOMMU_HW_QUEUE_TYPE_AMD_EVT) &&
	    (queue_type != IOMMU_HW_QUEUE_TYPE_AMD_PPR))
		return 0;

	return HW_QUEUE_STRUCT_SIZE(struct amd_iommu_hw_queue, core);
}

static int _amd_viommu_hw_queue_init(struct iommufd_hw_queue *hw_queue, u32 index)
{
	int ret = 0;
	u64 val, tmp;
	u8 __iomem *vfctrl, *vf;
	struct iommufd_viommu *viommu = hw_queue->viommu;
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);
	struct amd_iommu *iommu = container_of(viommu->iommu_dev, struct amd_iommu, iommu);
	int gid = aviommu->gid;

	vf = VIOMMU_VF_MMIO_BASE(iommu, gid);
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);

	switch (hw_queue->type) {
	case IOMMU_HW_QUEUE_TYPE_AMD_CMD:
	{
		val = readq(vfctrl + 0x20);
		val &= ~(0xFFFFFFFFFF00FULL);
		tmp = (hw_queue->length & 0xFULL);
		val = tmp | (hw_queue->base_addr & 0xFFFFFFFFFF000ULL);

		writeq(val, vfctrl + 0x20);
		break;
	}
	case IOMMU_HW_QUEUE_TYPE_AMD_EVT:
	{
		val = readq(vfctrl + 0x28);
		val &= ~(0xFFFFFFFFFF00FULL);
		tmp = (hw_queue->length & 0xFULL);
		val = tmp | (hw_queue->base_addr & 0xFFFFFFFFFF000ULL);
		writeq(val, vfctrl + 0x28);
		break;
	}
	case IOMMU_HW_QUEUE_TYPE_AMD_PPR:
	{
		val = readq(vfctrl + 0x30);
		val &= ~(0xFFFFFFFFFF00FULL);
		tmp = (hw_queue->length & 0xFULL);
		val = tmp | ((hw_queue->base_addr & 0xFFFFFFFFFF000ULL) << 4);
		writeq(val, vfctrl + 0x30);
		break;
	}
	default:
		pr_err("%s: Invalid type (%#x)\n", __func__, hw_queue->type);
		return -EINVAL;
	}

	pr_debug("%s: iommu_devid=%#x, gid=%#x, type=%#x, addr=%#llx, len=%#lx, val=%#llx\n",
		 __func__, iommu->devid, gid, hw_queue->type,
		 hw_queue->base_addr, hw_queue->length, val);

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
	.get_hw_queue_size = _amd_viommu_get_hw_queue_size,
	.hw_queue_init = _amd_viommu_hw_queue_init,
	.set_option = amd_viommu_guest_mmio_write,
	.get_option = amd_viommu_guest_mmio_read,
};
