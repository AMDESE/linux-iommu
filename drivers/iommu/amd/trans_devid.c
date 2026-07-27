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

static inline struct amd_iommu_viommu *trans_devid_xa_owner(void *entry)
{
	if (!entry || xa_is_value(entry))
		return NULL;
	return entry;
}

static inline void *trans_devid_xa_mk_reserved(void)
{
	return xa_mk_value(TRANS_DEVID_RESERVED);
}

static int trans_devid_find_free_locked(struct amd_iommu_pci_seg *pci_seg)
{
	int id;

	for (id = U16_MAX; id >= 0; id--) {
		if (!xa_load(&pci_seg->trans_devid_xa, id))
			return id;
	}
	return -ENOSPC;
}

static int trans_devid_xa_install_locked(struct amd_iommu_pci_seg *pci_seg,
					 u16 id, void *entry)
{
	void *old;

	old = xa_store(&pci_seg->trans_devid_xa, id, entry, GFP_KERNEL);
	if (xa_is_err(old))
		return xa_err(old);
	WARN_ON_ONCE(old);
	return 0;
}

static int trans_devid_xa_install_allocated_locked(struct amd_iommu_pci_seg *pci_seg,
						   u16 id,
						   struct amd_iommu_viommu *aviommu)
{
	return trans_devid_xa_install_locked(pci_seg, id, aviommu);
}

static int trans_devid_xa_install_reserved_locked(struct amd_iommu_pci_seg *pci_seg,
						u16 id)
{
	return trans_devid_xa_install_locked(pci_seg, id,
					      trans_devid_xa_mk_reserved());
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
 * trans_devid_do_relocate - move vIOMMU translation DTE from @old_id to @new_id
 *
 * Caller holds @aviommu->trans_devid_lock.  Pool xarray already records @new_id
 * as allocated to @aviommu and @old_id as reserved.
 */
static int trans_devid_do_relocate(struct amd_iommu_viommu *aviommu,
				   u16 old_id, u16 new_id)
{
	struct iommufd_viommu *viommu = &aviommu->core;
	struct amd_iommu *iommu =
		container_of(viommu->iommu_dev, struct amd_iommu, iommu);
	int ret;

	aviommu->trans_devid = new_id;

	ret = amd_iommu_set_translate_dte(viommu);
	if (ret)
		goto err_restore_id;

	amd_iommu_update_vfctrl_mmio_translate_devid(iommu, aviommu->gid, new_id);

	if (search_dev_data(iommu, old_id))
		amd_iommu_clear_translate_dte(iommu, old_id);

	return 0;

err_restore_id:
	aviommu->trans_devid = old_id;
	return ret;
}

/**
 * trans_devid_relocate - move an allocated id to a new slot and reserve @from_id
 *
 * Called when PCI attach needs a BDF that a vIOMMU already owns.  Updates the
 * per-segment pool, then reprograms DTE and VFctrl on the owning vIOMMU.
 *
 * Locking: takes @aviommu->trans_devid_lock, then pci_seg->trans_devid_mutex
 * (same order as destroy).  Hardware steps run with the viommu lock held and
 * the segment mutex dropped.
 */
static int trans_devid_relocate(struct amd_iommu_pci_seg *pci_seg, u16 from_id,
				struct amd_iommu_viommu *aviommu)
{
	u16 new_id;
	int ret;

	mutex_lock(&aviommu->trans_devid_lock);

	mutex_lock(&pci_seg->trans_devid_mutex);
	if (trans_devid_xa_owner(xa_load(&pci_seg->trans_devid_xa, from_id)) !=
	    aviommu) {
		ret = -ENOENT;
		goto unlock_seg;
	}

	if (aviommu->trans_devid != from_id) {
		ret = -EINVAL;
		goto unlock_seg;
	}

	new_id = trans_devid_find_free_locked(pci_seg);
	if (new_id < 0) {
		ret = new_id;
		goto unlock_seg;
	}

	ret = trans_devid_xa_install_allocated_locked(pci_seg, new_id, aviommu);
	if (ret)
		goto unlock_seg;

	ret = trans_devid_xa_install_reserved_locked(pci_seg, from_id);
	if (ret) {
		xa_erase(&pci_seg->trans_devid_xa, new_id);
		goto unlock_seg;
	}

	mutex_unlock(&pci_seg->trans_devid_mutex);

	ret = trans_devid_do_relocate(aviommu, from_id, new_id);
	if (ret) {
		mutex_lock(&pci_seg->trans_devid_mutex);
		xa_erase(&pci_seg->trans_devid_xa, new_id);
		trans_devid_xa_install_allocated_locked(pci_seg, from_id,
							aviommu);
		mutex_unlock(&pci_seg->trans_devid_mutex);
	}

	mutex_unlock(&aviommu->trans_devid_lock);
	return ret;

unlock_seg:
	mutex_unlock(&pci_seg->trans_devid_mutex);
	mutex_unlock(&aviommu->trans_devid_lock);
	return ret;
}

/**
 * amd_iommu_trans_devid_reserve - occupy @id so it is never returned by alloc
 *
 * Reservation is done when attaching device to a domain (see amd_iommu_attach_device()).
 *
 * When @id is allocated to a vIOMMU (e.g. after PCI hot-plug), the driver relocates
 * that vIOMMU to a newly allocated translate-device-id and reserves @id for the PCI
 * function.
 *
 * Return: 0 on success, %-ENOSPC if relocation cannot find a free id, or another
 * errno from relocation.  A second reserve of an already-reserved @id succeeds.
 */
int amd_iommu_trans_devid_reserve(struct amd_iommu_pci_seg *pci_seg, u16 id)
{
	void *entry;
	struct amd_iommu_viommu *aviommu;
	int ret = 0;

	mutex_lock(&pci_seg->trans_devid_mutex);
	entry = xa_load(&pci_seg->trans_devid_xa, id);
	if (trans_devid_xa_is_reserved(entry))
		goto unlock;

	aviommu = trans_devid_xa_owner(entry);
	if (aviommu) {
		mutex_unlock(&pci_seg->trans_devid_mutex);
		ret = trans_devid_relocate(pci_seg, id, aviommu);
		if (!ret)
			pr_debug("%s: Reserved trans_devid %#x after relocation (seg %#x)\n",
				 __func__, id, pci_seg->id);
		return ret;
	}

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

/**
 * amd_iommu_trans_devid_alloc - allocate a translate-device-id for @pci_seg
 *
 * The trans_devid is allocated from the highest id to the lowest id.
 * Generally, the PCI devices enumerated from the beginning of the bus range.
 * Therefore, ids in the high range are likely to not be used.
 *
 * Each vIOMMU receives its own translate-device-id from the per-segment pool.
 * @aviommu is stored in the xarray as the slot owner.
 *
 * Return: allocated id on success, negative errno on failure.
 */
int amd_iommu_trans_devid_alloc(struct amd_iommu_pci_seg *pci_seg,
				struct amd_iommu_viommu *aviommu)
{
	int id, ret;

	mutex_lock(&pci_seg->trans_devid_mutex);
	id = trans_devid_find_free_locked(pci_seg);
	if (id < 0) {
		ret = id;
		goto unlock;
	}

	ret = trans_devid_xa_install_allocated_locked(pci_seg, id, aviommu);
	if (ret)
		goto unlock;

	mutex_unlock(&pci_seg->trans_devid_mutex);
	pr_debug("%s: Allocated trans_devid %#x (seg %#x)\n", __func__, id,
		 pci_seg->id);
	return id;

unlock:
	mutex_unlock(&pci_seg->trans_devid_mutex);
	if (ret == -ENOSPC)
		pr_err("%s: No free trans_devid found (seg %#x)\n", __func__,
		       pci_seg->id);
	return ret;
}

/**
 * amd_iommu_trans_devid_free - return @id to the per-segment pool
 *
 * Caller must hold @aviommu->trans_devid_lock if racing with relocation.
 */
void amd_iommu_trans_devid_free(struct amd_iommu_pci_seg *pci_seg, u16 id,
				struct amd_iommu_viommu *aviommu)
{
	void *entry;

	mutex_lock(&pci_seg->trans_devid_mutex);
	entry = xa_erase(&pci_seg->trans_devid_xa, id);
	if (WARN_ON_ONCE(!entry || trans_devid_xa_owner(entry) != aviommu))
		goto out;
	pr_debug("%s: Freed trans_devid %#x (seg %#x)\n", __func__, id,
		 pci_seg->id);
out:
	mutex_unlock(&pci_seg->trans_devid_mutex);
}
