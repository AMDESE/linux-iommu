// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Advanced Micro Devices, Inc.
 *
 * AMD vIOMMU translate-device-id management.
 *
 * The id must be allocated from unused range. It is used to program the vIOMMU VF Control
 * register to specify the DTE used to contain the GPA->SPA mapping (v1 page table).
 */

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/xarray.h>

#include "amd_iommu.h"

static inline enum trans_devid_state trans_devid_xa_get_state(void *entry)
{
	if (!entry)
		return TRANS_DEVID_FREE;
	if (WARN_ON_ONCE(!xa_is_value(entry)))
		return TRANS_DEVID_FREE;
	return (enum trans_devid_state)xa_to_value(entry);
}

static inline void *trans_devid_xa_mk_state(enum trans_devid_state s)
{
	return xa_mk_value((unsigned long)s);
}

void amd_iommu_pci_seg_trans_devid_init(struct amd_iommu_pci_seg *pci_seg)
{
	mutex_init(&pci_seg->trans_devid_mutex);
	xa_init(&pci_seg->trans_devid_xa);
}

void amd_iommu_pci_seg_trans_devid_fini(struct amd_iommu_pci_seg *pci_seg)
{
	xa_destroy(&pci_seg->trans_devid_xa);
}

/**
 * amd_iommu_trans_devid_reserve - occupy @id so it is never returned by alloc
 *
 * Reservation is done when attaching device to a domain (see amd_iommu_attach_device()).
 *
 * Note: Since PCI hot-plug devices are enumerated during runtime, they could clash
 * with the translate-device-id allocation. In such case, amd_iommu_trans_devid_reserve()
 * could fail with %-EBUSY. This can be avoided by reserving the hot-plug id range if it
 * is known in advance.
 *
 * Return: 0 on success, %-EBUSY if @id is already allocated. A second reserve of
 * an already-reserved @id succeeds.
 */
int amd_iommu_trans_devid_reserve(struct amd_iommu_pci_seg *pci_seg, u16 id)
{
	void *entry, *old;
	int ret = 0;

	mutex_lock(&pci_seg->trans_devid_mutex);
	entry = xa_load(&pci_seg->trans_devid_xa, id);
	switch (trans_devid_xa_get_state(entry)) {
	case TRANS_DEVID_ALLOCATED:
		ret = -EBUSY;
		break;
	case TRANS_DEVID_RESERVED:
		break;
	case TRANS_DEVID_FREE:
		old = xa_store(&pci_seg->trans_devid_xa, id,
			       trans_devid_xa_mk_state(TRANS_DEVID_RESERVED), GFP_KERNEL);
		if (xa_is_err(old)) {
			ret = xa_err(old);
			break;
		}
		WARN_ON_ONCE(old);
		break;
	}
	mutex_unlock(&pci_seg->trans_devid_mutex);

	if (!ret)
		pr_debug("%s: Reserved trans_devid %#x (seg %#x)\n", __func__, id,
			 pci_seg->id);
	return ret;
}

static int reserve_trans_devid_each_dma_alias(struct pci_dev *pdev, u16 alias,
					      void *data)
{
	struct amd_iommu_pci_seg *pci_seg = data;

	(void)pdev;
	return amd_iommu_trans_devid_reserve(pci_seg, alias);
}

/**
 * amd_iommu_trans_devid_reserve_pci_aliases - reserve translate-device-ids for
 * PCI DMA aliases and for the IVRS alias when it is not walked as a PCI DMA
 * alias (different bus). Idempotent for repeated attach; see
 * amd_iommu_trans_devid_reserve().
 *
 * Return: 0 on success or if @dev is not PCI; otherwise an errno from
 * amd_iommu_trans_devid_reserve() or pci_for_each_dma_alias().
 */
int amd_iommu_trans_devid_reserve_pci_aliases(struct amd_iommu *iommu,
					      struct device *dev)
{
	struct pci_dev *pdev;
	struct amd_iommu_pci_seg *pci_seg;
	u16 devid, ivrs_alias;
	int ret;

	if (!dev_is_pci(dev))
		return 0;

	pdev = to_pci_dev(dev);
	pci_seg = iommu->pci_seg;
	devid = pci_dev_id(pdev);

	ivrs_alias = pci_seg->alias_table[devid];
	if (ivrs_alias != devid) {
		ret = amd_iommu_trans_devid_reserve(pci_seg, ivrs_alias);
		if (ret)
			return ret;
	}

	return pci_for_each_dma_alias(pdev, reserve_trans_devid_each_dma_alias,
				      pci_seg);
}
