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
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/xarray.h>

#include "amd_iommu.h"

static void trans_devid_free(struct amd_iommu_pci_seg *pci_seg, u16 id);

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
	mutex_init(&pci_seg->kvmfd_xa_mutex);
	xa_init(&pci_seg->kvmfd_xa);
}

void amd_iommu_pci_seg_trans_devid_fini(struct amd_iommu_pci_seg *pci_seg)
{
	unsigned long index = 0;
	void *e;

	while ((e = xa_find(&pci_seg->kvmfd_xa, &index, ULONG_MAX, XA_PRESENT))) {
		unsigned long cur = index;

		if (xa_is_value(e))
			trans_devid_free(pci_seg, (u16)xa_to_value(e));
		else {
			struct amd_iommu_kvmfd_trans_entry *entry = e;

			trans_devid_free(pci_seg, entry->trans_devid);
			kfree(entry);
		}
		xa_erase(&pci_seg->kvmfd_xa, cur);
		if (cur == ULONG_MAX)
			break;
		index = cur + 1;
	}
	xa_destroy(&pci_seg->kvmfd_xa);
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

/**
 * trans_devid_alloc - allocate a translate-device-id for @pci_seg
 *
 * The trans_devid is allocated from the highest id to the lowest id.
 * Generally, the PCI devices enumerated from the beginning of the bus range.
 * Therefore, ids in the high range are likely to not be used.
 *
 * Return: allocated id on success, negative errno on failure.
 */
static int trans_devid_alloc(struct amd_iommu_pci_seg *pci_seg)
{
	int id;

	mutex_lock(&pci_seg->trans_devid_mutex);
	for (id = U16_MAX; id >= 0; id--) {
		void *entry, *old;

		entry = xa_load(&pci_seg->trans_devid_xa, id);
		if (entry)
			continue;

		old = xa_store(&pci_seg->trans_devid_xa, id,
			       trans_devid_xa_mk_state(TRANS_DEVID_ALLOCATED), GFP_KERNEL);
		if (xa_is_err(old)) {
			int err = xa_err(old);

			mutex_unlock(&pci_seg->trans_devid_mutex);
			return err;
		}
		WARN_ON_ONCE(old);
		mutex_unlock(&pci_seg->trans_devid_mutex);
		pr_debug("%s: Allocated trans_devid %#x (seg %#x)\n", __func__, id,
			 pci_seg->id);
		return id;
	}
	pr_err("%s: No free trans_devid found (seg %#x)\n", __func__, pci_seg->id);
	mutex_unlock(&pci_seg->trans_devid_mutex);
	return -ENOSPC;
}

static void trans_devid_free(struct amd_iommu_pci_seg *pci_seg, u16 id)
{
	void *old;

	mutex_lock(&pci_seg->trans_devid_mutex);
	old = xa_erase(&pci_seg->trans_devid_xa, id);
	if (WARN_ON_ONCE(!old || trans_devid_xa_get_state(old) == TRANS_DEVID_FREE))
		goto out;
	pr_debug("%s: Freed trans_devid %#x (seg %#x)\n", __func__, id, pci_seg->id);
out:
	mutex_unlock(&pci_seg->trans_devid_mutex);
}

/**
 * amd_iommu_get_trans_devid_by_kvmfd - look up or allocate trans_devid for @kvmfd
 *
 * If an entry already exists for @kvmfd, bumps its refcount and returns the same
 * @trans_devid. Otherwise allocates a new translate devid, inserts an entry with
 * refcount 1, and returns it.
 *
 * Note: Each translate-device-id is allocated per VM (kvmfd) since there is one
 * GPA->SPA mapping per VM. In case of multiple vIOMMUs, all vIOMMUs share the same
 * translate-device-id.
 *
 * Return: 0 on success, %-ENOMEM on allocation failure, %-EIO if the map holds an
 * unexpected entry type.
 */
int amd_iommu_get_trans_devid_by_kvmfd(struct amd_iommu_pci_seg *pci_seg, u32 kvmfd,
				       u16 *trans_devid)
{
	struct amd_iommu_kvmfd_trans_entry *entry;
	void *prev;
	int id, ret = 0;

	mutex_lock(&pci_seg->kvmfd_xa_mutex);
	entry = xa_load(&pci_seg->kvmfd_xa, kvmfd);
	if (entry) {
		if (WARN_ON_ONCE(xa_is_value(entry))) {
			ret = -EIO;
			goto out_unlock;
		}
		refcount_inc(&entry->refs);
		*trans_devid = entry->trans_devid;
		pr_debug("%s: Got trans_devid %#x for kvmfd %#x (seg %#x)\n",
			 __func__, *trans_devid, kvmfd, pci_seg->id);
		goto out_unlock;
	}

	id = trans_devid_alloc(pci_seg);
	if (id < 0) {
		pr_err("%s: Failed to allocate trans_devid (kvmfd=%#x seg=%#x err=%d)\n",
		       __func__, kvmfd, pci_seg->id, id);
		ret = id;
		goto out_unlock;
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		trans_devid_free(pci_seg, id);
		ret = -ENOMEM;
		goto out_unlock;
	}

	refcount_set(&entry->refs, 1);
	entry->trans_devid = id;

	prev = xa_store(&pci_seg->kvmfd_xa, kvmfd, entry, GFP_KERNEL);
	if (xa_is_err(prev)) {
		ret = xa_err(prev);
		kfree(entry);
		trans_devid_free(pci_seg, id);
		goto out_unlock;
	}
	WARN_ON_ONCE(prev);

	*trans_devid = id;
	pr_debug("%s: Allocated trans_devid %#x for kvmfd %#x (seg %#x)\n",
		 __func__, id, kvmfd, pci_seg->id);

out_unlock:
	mutex_unlock(&pci_seg->kvmfd_xa_mutex);
	return ret;
}

/**
 * amd_iommu_free_trans_devid_by_kvmfd - drop one reference for @kvmfd
 *
 * Decrements the per-kvmfd refcount. The translate devid is returned to the
 * segment pool and the map entry is removed only when the refcount reaches zero.
 */
void amd_iommu_free_trans_devid_by_kvmfd(struct amd_iommu_pci_seg *pci_seg, u32 kvmfd)
{
	struct amd_iommu_kvmfd_trans_entry *entry;
	u16 tid;

	mutex_lock(&pci_seg->kvmfd_xa_mutex);
	entry = xa_load(&pci_seg->kvmfd_xa, kvmfd);
	if (!entry) {
		mutex_unlock(&pci_seg->kvmfd_xa_mutex);
		return;
	}

	if (WARN_ON_ONCE(xa_is_value(entry))) {
		mutex_unlock(&pci_seg->kvmfd_xa_mutex);
		return;
	}

	if (!refcount_dec_and_test(&entry->refs)) {
		pr_debug("%s: kvmfd %#x, trans_devid %#x (seg %#x)\n",
			 __func__, kvmfd, entry->trans_devid, pci_seg->id);
		mutex_unlock(&pci_seg->kvmfd_xa_mutex);
		return;
	}

	tid = entry->trans_devid;
	trans_devid_free(pci_seg, tid);
	xa_erase(&pci_seg->kvmfd_xa, kvmfd);
	kfree(entry);
	mutex_unlock(&pci_seg->kvmfd_xa_mutex);
	pr_debug("%s: Freed trans_devid %#x for kvmfd %#x (seg %#x)\n", __func__, tid,
		 kvmfd, pci_seg->id);
}
