// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt)     "AMD-Vi: " fmt
#define dev_fmt(fmt)    pr_fmt(fmt)

#include <linux/iommu.h>
#include <linux/amd-iommu.h>

#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/ioctl.h>
#include <linux/iommufd.h>
#include <linux/amd-iommu.h>
#include <uapi/linux/iommufd.h>
#include <linux/mem_encrypt.h>

#include <asm/iommu.h>
#include <asm/set_memory.h>

#include "iommufd.h"
#include "amd_iommu.h"
#include "amd_iommu_types.h"
#include "amd_viommu.h"
#include "../iommu-pages.h"

LIST_HEAD(viommu_devid_map);

static int viommu_init_pci_vsc(struct amd_iommu *iommu)
{
	iommu->vsc_offset = pci_find_capability(iommu->dev, PCI_CAP_ID_VNDR);
	if (!iommu->vsc_offset)
		return -ENODEV;

	DUMP_printk("device:%s, vsc offset:%04x\n",
		    pci_name(iommu->dev), iommu->vsc_offset);
	return 0;
}

static void amd_viommu_gid_ida_init(struct amd_iommu *iommu)
{
	ida_init(&iommu->gid_ida);
	iommu->gid_ida_inited = true;
}

static void amd_viommu_gid_ida_fini(struct amd_iommu *iommu)
{
	if (!iommu->gid_ida_inited)
		return;

	ida_destroy(&iommu->gid_ida);
	iommu->gid_ida_inited = false;
}

static void __init amd_viommu_vf_vfcntl_unmap(struct amd_iommu *iommu)
{
	if (iommu->vfctrl_base) {
		iounmap(iommu->vfctrl_base);
		iommu->vfctrl_base = NULL;
	}
	if (iommu->vf_cntl_phys)
		release_mem_region(iommu->vf_cntl_phys, VIOMMU_VF_CNTL_MMIO_MAP_SIZE);

	if (iommu->vf_base) {
		iounmap(iommu->vf_base);
		iommu->vf_base = NULL;
	}
	if (iommu->vf_base_phys)
		release_mem_region(iommu->vf_base_phys, VIOMMU_VF_MMIO_MAP_SIZE);
}

void __init amd_viommu_uninit(struct amd_iommu *iommu)
{
	amd_viommu_gid_ida_fini(iommu);
	amd_viommu_vf_vfcntl_unmap(iommu);
}

static int __init viommu_vf_vfcntl_init(struct amd_iommu *iommu)
{
	u32 lo, hi;
	u64 vf_phys, vf_cntl_phys;

	/* Setting up VF and VF_CNTL MMIOs */
	pci_read_config_dword(iommu->dev, iommu->vsc_offset + MMIO_VSC_VF_BAR_LO_OFFSET, &lo);
	pci_read_config_dword(iommu->dev, iommu->vsc_offset + MMIO_VSC_VF_BAR_HI_OFFSET, &hi);
	vf_phys = hi;
	vf_phys = (vf_phys << 32) | lo;
	if (!(vf_phys & 1)) {
		pr_err(FW_BUG "vf_phys disabled\n");
		return -EINVAL;
	}

	pci_read_config_dword(iommu->dev, iommu->vsc_offset + MMIO_VSC_VF_CNTL_BAR_LO_OFFSET, &lo);
	pci_read_config_dword(iommu->dev, iommu->vsc_offset + MMIO_VSC_VF_CNTL_BAR_HI_OFFSET, &hi);
	vf_cntl_phys = hi;
	vf_cntl_phys = (vf_cntl_phys << 32) | lo;
	if (!(vf_cntl_phys & 1)) {
		pr_err(FW_BUG "vf_cntl_phys disabled\n");
		return -EINVAL;
	}

	if (!vf_phys || !vf_cntl_phys) {
		pr_err(FW_BUG "AMD-Vi: Unassigned VF resources.\n");
		return -ENOMEM;
	}

	/* Mapping 256MB of VF and 4MB of VF_CNTL BARs */
	vf_phys &= ~1ULL;
	iommu->vf_base = iommu_map_mmio_space(vf_phys, VIOMMU_VF_MMIO_MAP_SIZE);
	if (!iommu->vf_base) {
		pr_err("Can't reserve vf_base\n");
		return -ENOMEM;
	}
	iommu->vf_base_phys = vf_phys;

	vf_cntl_phys &= ~1ULL;
	iommu->vfctrl_base = iommu_map_mmio_space(vf_cntl_phys, VIOMMU_VF_CNTL_MMIO_MAP_SIZE);
	if (!iommu->vfctrl_base) {
		pr_err("Can't reserve vfctrl_base\n");
		goto err_out;
	}
	iommu->vf_cntl_phys = vf_cntl_phys;

	pr_debug("%s: IOMMU device:%s, vf_base:%#llx, vfctrl_base:%#llx\n",
		 __func__, pci_name(iommu->dev), vf_phys, vf_cntl_phys);
	return 0;
err_out:
	amd_viommu_uninit(iommu);
	return -ENOMEM;
}

/*
 * Allocate backing pages, mark UC, and map at @iova in viommu_pdom.
 * *@out_va is NULL on any failure.
 */
static int viommu_priv_alloc_map_flush(struct amd_iommu *iommu, u64 iova, size_t size,
				       gfp_t gfp, void **out_va)
{
	int ret;
	void *va;
	int nid = iommu && iommu->dev ? dev_to_node(&iommu->dev->dev) : NUMA_NO_NODE;

	*out_va = NULL;

	if (!iommu || !iommu->viommu_pdom)
		return -EINVAL;

	va = iommu_alloc_pages_node_sz(nid, gfp, size);
	if (!va)
		return -ENOMEM;

	/*
	 * IOMMU spec mentions that the vIOMMU backing storage memory
	 * should be marked as UC.
	 */
	ret = set_memory_uc((unsigned long)va, size >> PAGE_SHIFT);
	if (ret)
		goto err_free_pages;

	ret = iommu_map(&iommu->viommu_pdom->domain, iova, iommu_virt_to_phys(va), size,
			IOMMU_PROT_IR | IOMMU_PROT_IW, GFP_KERNEL);
	if (ret)
		goto cleanup_mem_attr;

	*out_va = va;
	return 0;

cleanup_mem_attr:
	set_memory_wb((unsigned long)va, size >> PAGE_SHIFT);
err_free_pages:
	iommu_free_pages(va);
	return ret;
}

/*
 * Unmap @iova, flush the unmapped span on this IOMMU, WB, and free @cpu_va.
 * Returns 0, or the flush error if amd_iommu_flush_private_vm_region() fails.
 */
static int viommu_priv_unmap_flush_free(struct amd_iommu *iommu, u64 iova, size_t size,
					void *cpu_va)
{
	size_t unmapped;
	int ret = 0;

	if (!cpu_va)
		return 0;
	if (!iommu || !iommu->viommu_pdom)
		return -EINVAL;

	unmapped = iommu_unmap(&iommu->viommu_pdom->domain, iova, size);
	if (unmapped != size)
		pr_warn("%s: unmapped %#zx of %#lx at %#llx\n", __func__, unmapped, size, iova);

	if (unmapped) {
		ret = amd_iommu_flush_private_vm_region(iommu, iommu->viommu_pdom, iova,
							unmapped);
		if (ret)
			pr_warn("%s: IOTLB flush failed (%d) for %#zx at %#llx\n",
				__func__, ret, unmapped, iova);
	}

	set_memory_wb((unsigned long)cpu_va, size >> PAGE_SHIFT);
	iommu_free_pages(cpu_va);
	return ret;
}

static void *alloc_private_subregion(struct amd_iommu *iommu, u64 base, size_t size)
{
	void *region = NULL;
	int ret;

	ret = viommu_priv_alloc_map_flush(iommu, base, size, GFP_KERNEL | __GFP_ZERO, &region);
	if (ret)
		return NULL;

	pr_debug("%s: base=%#llx, size=%#lx, subregion=%#llx(%#llx)\n",
		 __func__, base, size, (unsigned long long)region, iommu_virt_to_phys(region));

	return region;
}

static void viommu_private_space_uninit(struct amd_iommu *iommu)
{
	int i, ret, first_err = 0;
	u64 base;
	struct iommu_domain *dom;

	if (!iommu->viommu_pdom)
		return;

	for (i = 0; i < VIOMMU_PRIV_SUBREGION_CNT; i++) {
		if (!iommu->viommu_priv_region[i])
			continue;
		base = VIOMMU_PRIV_REGION_BASE + (i * VIOMMU_PRIV_SUBREGION_SIZE);
		ret = viommu_priv_unmap_flush_free(iommu, base, VIOMMU_PRIV_SUBREGION_SIZE,
						   iommu->viommu_priv_region[i]);
		if (ret && !first_err)
			first_err = ret;
		iommu->viommu_priv_region[i] = NULL;
	}

	dom = &iommu->viommu_pdom->domain;
	amd_iommu_domain_free(dom);
	iommu->viommu_pdom = NULL;

	if (first_err)
		pr_err("%s: private subregion teardown failed (%d)\n", __func__, first_err);
}
static int viommu_private_space_init(struct amd_iommu *iommu)
{
	int i;
	u64 base;
	struct iommu_domain *dom;
	struct protection_domain *pdom;
	struct pt_iommu_amdv1_hw_info pt_info;

	/*
	 * Setup page table root pointer, Guest MMIO and
	 * Cmdbuf Dirty Status regions.
	 */
	dom = amd_iommu_domain_alloc_paging_v1(&iommu->dev->dev, 0);
	if (!dom) {
		pr_err("%s: Failed to initialize private space\n", __func__);
		return -ENOMEM;
	}

	pdom = to_pdomain(dom);
	iommu->viommu_pdom = pdom;

	/*
	 * Each private region requires to 8MB of memory to be allocated
	 * and mapped. Split the region into 4 x 2MB-subregion.
	 */
	for (i = 0; i < VIOMMU_PRIV_SUBREGION_CNT; i++) {
		base = VIOMMU_PRIV_REGION_BASE + (i * VIOMMU_PRIV_SUBREGION_SIZE);
		iommu->viommu_priv_region[i] = alloc_private_subregion(iommu, base,
								       VIOMMU_PRIV_SUBREGION_SIZE);
		if (!iommu->viommu_priv_region[i]) {
			pr_err("%s: Failed to allocate vIOMMU private subregion %d\n", __func__, i);
			viommu_private_space_uninit(iommu);
			return -ENOMEM;
		}
	}

	pt_iommu_amdv1_hw_info(&pdom->amdv1, &pt_info);
	pr_debug("%s: devid=%#x, pte_root=%#llx\n",
		 __func__, iommu->devid,
		 (unsigned long long)pt_info.host_pt_root);

	return 0;
}

/*
 * Returns VF MMIO BAR offset for the give guest ID which will be
 * mapped to guest vIOMMU 3rd 4K MMIO address
 */
u64 amd_viommu_get_vfmmio_addr(struct amd_iommu *iommu, u16 gid)
{
	/* TODO: Add check for sVIOMMU and set gid[bit 15] */
	return iommu->vf_base_phys + gid * VIOMMU_VF_MMIO_ENTRY_SIZE;
}
EXPORT_SYMBOL(amd_viommu_get_vfmmio_addr);

int __init amd_viommu_init(struct amd_iommu *iommu)
{
	int ret;

	if (!amd_iommu_viommu ||
	    !check_feature(FEATURE_VIOMMU))
		return 0;

	ret = viommu_init_pci_vsc(iommu);
	if (ret)
		return ret;

	ret = viommu_vf_vfcntl_init(iommu);
	if (ret)
		return ret;

	amd_viommu_gid_ida_init(iommu);

	ret = viommu_private_space_init(iommu);
	if (ret)
		return ret;

	return 0;
}
