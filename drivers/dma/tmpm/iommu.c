// SPDX-License-Identifier: GPL-2.0-only
/*
 * TMPM interface driver
 *
 * Copyright (C) 2017-2022 Advanced Micro Devices, Inc.
 */

#include <linux/cleanup.h>
#include <linux/iommu.h>
#include <linux/amd-iommu.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <amd_iommu_types.h>
#include <amd_iommu.h>
#include "iommu.h"
#include "main.h"


static struct iommu_domain *tmpm_domain;
static bool tmpm_iommu_enabled;
static refcount_t domain_ref = REFCOUNT_INIT(1);
DEFINE_MUTEX(domain_mut);

static int tmpm_iommu_create_direct_mappings(struct device *dev)
{
	struct list_head group_resv_regions;
	struct iommu_resv_region *entry;
	struct iommu_group *group;
	unsigned long pg_size;
	int ret = 0;

	group = iommu_group_get(dev);
	if (!group) {
		dev_dbg(dev, "(%s): Fail to get iommu group.\n",
			__func__);
		return -ENODEV;
	}

	WARN_ON(!tmpm_domain->pgsize_bitmap);

	pg_size = 1UL << __ffs(tmpm_domain->pgsize_bitmap);
	INIT_LIST_HEAD(&group_resv_regions);

	ret = iommu_get_group_resv_regions(group, &group_resv_regions);
	if (ret) {
		dev_dbg(dev, "(%s): Fail to get iommu reserve regions.\n",
			__func__);
		return ret;
	}

	list_for_each_entry(entry, &group_resv_regions, list) {
		dma_addr_t start, end, addr;
		size_t map_size = 0;

		start = ALIGN(entry->start, pg_size);
		end   = ALIGN(entry->start + entry->length, pg_size);

		if (entry->type != IOMMU_RESV_DIRECT &&
			entry->type != IOMMU_RESV_DIRECT_RELAXABLE)
			continue;

		for (addr = start; addr <= end; addr += pg_size) {
			phys_addr_t phys_addr;

			if (addr == end)
				goto map_end;

			phys_addr = tmpm_iova_to_phys(addr);
			if (!phys_addr) {
				map_size += pg_size;
				continue;
			}

map_end:
			if (map_size) {
				ret = tmpm_iommu_map(addr - map_size,
						addr - map_size, map_size,
						entry->prot, GFP_KERNEL);
				if (ret)
					goto out;
				map_size = 0;
			}
		}
	}
out:
	dev_dbg(dev, "DEBUG: %s: dev_name=%s, ret=%d\n", __func__,
		dev_name(dev), ret);
	return ret;
}

/*
 * TMPM domain management helper functions
 */

/*
 * Allocating IOMMU domain w/ IOMMU_DOMAIN_UNMANAGE type.
 * The domain is allocated by the master TMPM, and globally shared
 * among all (i.e. master and slave) TMPM devices in the system.
 */
static int tmpm_iommu_domain_alloc(struct device *dev)
{
	struct protection_domain *pdom;

	if (tmpm_domain)
		return 0;

	tmpm_domain = iommu_paging_domain_alloc_flags(dev, 0);
	if (!tmpm_domain)
		return -EINVAL;

	dev_dbg(dev, "DEBUG: %s: dev_name=%s, ret=0\n", __func__,
		dev_name(dev));

	pdom = container_of(tmpm_domain, struct protection_domain, domain);
	dev_err(dev, "___K___ %s %u: root=%lx/%lx\n",
		__func__, __LINE__,
		pdom->amdv1.amdpt.common.top_of_table,
		__pa(pdom->amdv1.amdpt.common.top_of_table));
	return 0;
}

static void tmpm_iommu_domain_free(void)
{
	if (!tmpm_domain)
		return;
	printk(KERN_DEBUG "DEBUG: %s\n", __func__);
	iommu_domain_free(tmpm_domain);
	tmpm_domain = NULL;
}

struct iommu_domain *tmpm_iommu_get_domain(struct device *dev)
{
	guard(mutex)(&domain_mut);
	if (!tmpm_domain) {
		if (tmpm_iommu_domain_alloc(dev)) {
			return NULL;
		}
	}
	refcount_inc(&domain_ref);
	return tmpm_domain;
}

void tmpm_iommu_put_all_domain(void)
{
	guard(mutex)(&domain_mut);
	while (refcount_dec_not_one(&domain_ref)) {
		if (refcount_read(&domain_ref) == 1) {
			pr_debug("(%s): freeing domain\n", __func__);
			tmpm_iommu_domain_free();
			tmpm_domain = NULL;
		}
	}
}

/*
 * TMPM device management helper functions
 */
static LIST_HEAD(dev_stack);

struct dev_stack_el {
	struct list_head list;
	struct device *dev;
};

static void dev_push(struct list_head *stack, struct dev_stack_el *el)
{
	list_add(&el->list, stack);
}

static struct dev_stack_el *dev_pop(struct list_head *stack)
{
	struct dev_stack_el *el;

	if (list_empty(stack)) {
		return NULL;
	}

	el = list_first_entry(stack, struct dev_stack_el, list);
	list_del(&el->list);
	return el;
}

int tmpm_iommu_domain_attach_device(struct device *dev)
{
	struct dev_stack_el *el;
	int ret;

	if (!dev || !tmpm_domain)
		return -EINVAL;

	ret = iommu_attach_device(tmpm_domain, dev);
	if (ret) {
		dev_dbg(dev, "(%s): Fail to attach device to tmpm domain. ret=%d\n",
			__func__, ret);
		return ret;
	}

	el = kzalloc(sizeof(*el), GFP_KERNEL);
	if (el) {
		el->dev = dev;
		dev_push(&dev_stack, el);
	}

	ret = tmpm_iommu_create_direct_mappings(dev);
	if (ret) {
		dev_dbg(dev, "(%s): Fail to reserve regions and create mappings.\n",
			__func__);
		return ret;
	}

	printk(KERN_DEBUG "DEBUG: %s: dev_name=%s, ret=%d\n", __func__, dev_name(dev), ret);
	return ret;
}

void tmpm_iommu_detach_devices(void)
{
	struct dev_stack_el *el;

	if (!tmpm_domain)
		return;

	while (!list_empty(&dev_stack)) {
		el = dev_pop(&dev_stack);
		iommu_detach_device(tmpm_domain, el->dev);
		kfree(el);
	}
}

/*
 * TMPM IOMMU enable / disable helper functions
 */

int tmpm_iommu_enable(void)
{
	int ret;

	ret = amd_iommu_tmpm_enable();
	if (!ret) {
		tmpm_iommu_enabled = true;
		pr_debug("%s: TMPM iommu enabled\n", __func__);
	}

	return ret;
}

void tmpm_iommu_disable(void)
{
	if (!tmpm_iommu_enabled)
		return;

	amd_iommu_tmpm_disable();
	pr_debug("%s: TMPM iommu disabled\n", __func__);
}

/*
 * TMPM identity Map / Unmap helper functions
 */

int tmpm_iommu_map(unsigned long iova, phys_addr_t paddr,
		size_t size, int prot, gfp_t gfp)
{
	if (!tmpm_domain) {
		pr_debug("(%s): tmpm domain 0x%llx\n",
			__func__, (u64)tmpm_domain);
		return -EINVAL;
	}

	int ret = iommu_map(tmpm_domain, iova, paddr, size, prot, gfp);

	pr_err("___K___ %s %u: %lx..%lx (%ld) => %llx ret=%d\n",
		__func__, __LINE__, iova, iova + size, size >> PAGE_SHIFT, paddr, ret);

	return ret;
}

size_t tmpm_iommu_unmap(unsigned long iova, size_t size)
{
	int ret = iommu_unmap(tmpm_domain, iova, size);

	pr_err("___K___ %s %u: %lx..%lx (%ld) ret=%d\n",
		__func__, __LINE__, iova, iova + size, size, ret);

	return ret;
}

phys_addr_t tmpm_iova_to_phys(unsigned long iova)
{
	return iommu_iova_to_phys(tmpm_domain, iova);
}

int tmpm_iommu_get_domain_id(void)
{
	struct protection_domain *pdom;

	if (!tmpm_domain)
		return -EINVAL;
	pdom = container_of(tmpm_domain, struct protection_domain, domain);
	if (pdom)
		return pdom->id;
	return -ENXIO;
}
