// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Advanced Micro Devices, Inc.
 *
 * AMD vIOMMU translate-device-id management.
 *
 * The pool is per PCI segment because the AMD IOMMU device table is
 * per-segment.  Each id must be allocated from unused slots in that
 * segment.  It is used to program the vIOMMU VF Control register to
 * specify the DTE used to contain the GPA->SPA mapping (v1 page table).
 */

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/xarray.h>

#include "amd_iommu.h"

static inline bool trans_devid_xa_is_reserved(void *entry)
{
	return entry && xa_is_value(entry) &&
	       xa_to_value(entry) == TRANS_DEVID_RESERVED;
}

static inline void *trans_devid_xa_mk_reserved(void)
{
	return xa_mk_value(TRANS_DEVID_RESERVED);
}

static int trans_devid_xa_install_reserved_locked(struct amd_iommu_pci_seg *pci_seg,
						  u16 id)
{
	void *old;

	old = xa_store(&pci_seg->trans_devid_xa, id,
		       trans_devid_xa_mk_reserved(), GFP_KERNEL);
	if (xa_is_err(old))
		return xa_err(old);
	WARN_ON_ONCE(old);
	return 0;
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
 * Return: 0 on success.  A second reserve of an already-reserved @id succeeds.
 */
int amd_iommu_trans_devid_reserve(struct amd_iommu_pci_seg *pci_seg, u16 id)
{
	void *entry;
	int ret = 0;

	mutex_lock(&pci_seg->trans_devid_mutex);
	entry = xa_load(&pci_seg->trans_devid_xa, id);
	if (trans_devid_xa_is_reserved(entry))
		goto unlock;

	ret = trans_devid_xa_install_reserved_locked(pci_seg, id);
unlock:
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
