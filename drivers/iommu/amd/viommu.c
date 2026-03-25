// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt)     "AMD-Vi: " fmt
#define dev_fmt(fmt)    pr_fmt(fmt)

#include <linux/iommu.h>
#include <linux/iommufd.h>
#include <uapi/linux/iommufd.h>

#include <asm/iommu.h>
#include <asm/set_memory.h>

#include "iommufd.h"
#include "amd_iommu.h"
#include "amd_iommu_types.h"
#include "amd_viommu.h"
#include "../iommu-pages.h"

/*
 * Per-vIOMMU DevID / DomID tables share iommu->viommu_pdom:
 *   IOVA = base + gid * entry_size, gid in [1, VIOMMU_MAX_GID].
 * The 64GB gap between these bases is 0x10000 1MB DevID slots.
 * VIOMMU_MAX_GID is 0x7FFF, so a max-gid DevID window ends at
 * 0x1800000000 and cannot meet VIOMMU_DOMID_MAPPING_BASE.
 *
 * VIOMMU_MAX_GDEVID / VIOMMU_MAX_GDOMID are 16-bit guest DevID
 * and DomID table indices (hardware mapping-table width), not GID.
 */
#define VIOMMU_MAX_GDEVID		0xFFFF
#define VIOMMU_DEVID_MAPPING_BASE	0x1000000000ULL
#define VIOMMU_DEVID_MAPPING_ENTRY_SIZE	(1 << 20)

#define VIOMMU_MAX_GDOMID		0xFFFF
#define VIOMMU_DOMID_MAPPING_BASE	0x2000000000ULL
#define VIOMMU_DOMID_MAPPING_ENTRY_SIZE	(1 << 19)

static_assert(VIOMMU_DEVID_MAPPING_BASE +
	      (VIOMMU_MAX_GID + 1ULL) * VIOMMU_DEVID_MAPPING_ENTRY_SIZE <=
	      VIOMMU_DOMID_MAPPING_BASE);
static_assert(VIOMMU_DEVID_MAPPING_ENTRY_SIZE >=
	      (VIOMMU_MAX_GDEVID + 1ULL) * sizeof(u64));
static_assert(VIOMMU_DOMID_MAPPING_ENTRY_SIZE >=
	      (VIOMMU_MAX_GDOMID + 1ULL) * sizeof(u64));

static void __init amd_viommu_vf_vfcntl_unmap(struct amd_iommu *iommu)
{
	if (iommu->vfctrl_base) {
		iounmap(iommu->vfctrl_base);
		iommu->vfctrl_base = NULL;
	}
	if (iommu->vf_cntl_phys) {
		release_mem_region(iommu->vf_cntl_phys, VIOMMU_VF_CNTL_MMIO_MAP_SIZE);
		iommu->vf_cntl_phys = 0;
	}

	if (iommu->vf_base) {
		iounmap(iommu->vf_base);
		iommu->vf_base = NULL;
	}
	if (iommu->vf_base_phys) {
		release_mem_region(iommu->vf_base_phys, VIOMMU_VF_MMIO_MAP_SIZE);
		iommu->vf_base_phys = 0;
	}
}


static bool viommu_cmdbuf_enabled(struct amd_iommu *iommu);

static void viommu_free_self_dev_data(struct amd_iommu *iommu)
{
	struct iommu_dev_data *dev_data = iommu->viommu_dev_data;
	struct dev_table_entry new = {};

	if (!dev_data)
		return;

	/*
	 * INV_DTE needs the command buffer. Skip it after
	 * disable_iommus() clears CONTROL_CMDBUF_EN. The init
	 * unwind still flushes while the buffer is enabled.
	 */
	if (viommu_cmdbuf_enabled(iommu)) {
		amd_iommu_make_clear_dte(iommu, dev_data->devid, &new);
		amd_iommu_update_dte(iommu, dev_data, &new);
	}
	amd_iommu_free_dev_data(iommu, dev_data);
	iommu->viommu_dev_data = NULL;
}

static int viommu_alloc_self_dev_data(struct amd_iommu *iommu)
{
	struct protection_domain *pdom = iommu->viommu_pdom;
	struct pt_iommu_amdv1_hw_info pt_info;
	struct iommu_dev_data *dev_data;
	struct dev_table_entry new = {};

	dev_data = amd_iommu_alloc_dev_data(iommu->devid);
	if (!dev_data) {
		pr_err("%s: Failed to allocate dev_data\n", __func__);
		return -ENOMEM;
	}
	/*
	 * Synthetic DTE for iommu->devid only: no struct device, so
	 * amd_iommu_update_dte() skips clone_aliases(), and not on
	 * pdom->dev_list (not an IOMMU-API attach).
	 */
	dev_data->dev = NULL;
	dev_data->domain = pdom;
	iommu->viommu_dev_data = dev_data;

	amd_iommu_make_clear_dte(iommu, iommu->devid, &new);
	pt_iommu_amdv1_hw_info(&pdom->amdv1, &pt_info);
	amd_iommu_set_dte_v1(dev_data, pdom, pdom->id, &pt_info, &new);
	amd_iommu_update_dte(iommu, dev_data, &new);
	return 0;
}

static void viommu_private_space_uninit(struct amd_iommu *iommu);

void __init amd_viommu_uninit(struct amd_iommu *iommu)
{
	iommu->flags &= ~AMD_IOMMU_FLAG_VIOMMU_EN;
	viommu_free_self_dev_data(iommu);
	viommu_private_space_uninit(iommu);
	amd_viommu_vf_vfcntl_unmap(iommu);
}

static int __init viommu_vf_vfcntl_init(struct amd_iommu *iommu)
{
	u32 lo, hi;
	u16 vsc;
	u64 vf_phys, vf_cntl_phys;

	vsc = pci_find_capability(iommu->dev, PCI_CAP_ID_VNDR);
	if (!vsc)
		return -ENODEV;

	pr_debug("device:%s, vsc offset:%04x\n",
		 pci_name(iommu->dev), vsc);

	/* Setting up VF and VF_CNTL MMIOs */
	pci_read_config_dword(iommu->dev, vsc + MMIO_VSC_VF_BAR_LO_OFFSET, &lo);
	pci_read_config_dword(iommu->dev, vsc + MMIO_VSC_VF_BAR_HI_OFFSET, &hi);
	vf_phys = hi;
	vf_phys = (vf_phys << 32) | lo;
	if (!(vf_phys & 1)) {
		pr_err(FW_BUG "vf_phys disabled\n");
		return -EINVAL;
	}
	vf_phys &= ~1ULL;
	if (!vf_phys) {
		pr_err(FW_BUG "vf_phys address is zero\n");
		return -EINVAL;
	}

	pci_read_config_dword(iommu->dev, vsc + MMIO_VSC_VF_CNTL_BAR_LO_OFFSET, &lo);
	pci_read_config_dword(iommu->dev, vsc + MMIO_VSC_VF_CNTL_BAR_HI_OFFSET, &hi);
	vf_cntl_phys = hi;
	vf_cntl_phys = (vf_cntl_phys << 32) | lo;
	if (!(vf_cntl_phys & 1)) {
		pr_err(FW_BUG "vf_cntl_phys disabled\n");
		return -EINVAL;
	}
	vf_cntl_phys &= ~1ULL;
	if (!vf_cntl_phys) {
		pr_err(FW_BUG "vf_cntl_phys address is zero\n");
		return -EINVAL;
	}

	/* Mapping 256MB of VF and 4MB of VF_CNTL BARs */
	iommu->vf_base = iommu_map_mmio_space(vf_phys, VIOMMU_VF_MMIO_MAP_SIZE);
	if (!iommu->vf_base) {
		pr_err("Can't reserve vf_base\n");
		goto err_out;
	}
	iommu->vf_base_phys = vf_phys;

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
	amd_viommu_vf_vfcntl_unmap(iommu);
	return -ENOMEM;
}

/*
 * Restore WB and free @va. If WB restore fails, leak the pages so
 * UC-MINUS direct-map PTEs and the PAT memtype reservation are not
 * returned to the buddy allocator.
 */
static void viommu_priv_wb_free(void *va, size_t size)
{
	if (WARN_ON_ONCE(set_memory_wb((unsigned long)va,
				       size >> PAGE_SHIFT)))
		return;
	iommu_free_pages(va);
}

/*
 * Allocate backing pages, mark UC, and map at @iova in viommu_pdom.
 * *@out_va is NULL on any failure. @gfp is used for the backing
 * folio and iommu_map() page tables.
 */
static int viommu_priv_alloc_map(struct amd_iommu *iommu, u64 iova, size_t size,
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
	 * IOMMU spec: backing storage must be UC. set_memory_uc()
	 * splits covering 2MB direct-map pages to 4K; set_memory_wb()
	 * does not re-coalesce them.
	 */
	ret = set_memory_uc((unsigned long)va, size >> PAGE_SHIFT);
	if (ret)
		goto err_uc;

	ret = iommu_map(&iommu->viommu_pdom->domain, iova,
			iommu_virt_to_phys(va), size,
			IOMMU_READ | IOMMU_WRITE, gfp);
	if (ret)
		goto err_uc;

	*out_va = va;
	return 0;

err_uc:
	viommu_priv_wb_free(va, size);
	return ret;
}

static bool viommu_cmdbuf_enabled(struct amd_iommu *iommu)
{
	if (!iommu->mmio_base)
		return false;
	return readq(iommu->mmio_base + MMIO_CONTROL_OFFSET) &
	       BIT_ULL(CONTROL_CMDBUF_EN);
}

/*
 * Unmap @iova if the command buffer is still enabled, restore WB, and
 * free @cpu_va. Skip IOTLB invalidation after disable_iommus().
 */
static void viommu_priv_unmap_free(struct amd_iommu *iommu, u64 iova, size_t size,
				   void *cpu_va)
{
	size_t unmapped;

	if (!cpu_va)
		return;
	if (!iommu || !iommu->viommu_pdom)
		return;

	if (viommu_cmdbuf_enabled(iommu)) {
		unmapped = iommu_unmap(&iommu->viommu_pdom->domain, iova, size);
		WARN_ON(unmapped != size);
	}

	viommu_priv_wb_free(cpu_va, size);
}

static void *alloc_private_subregion(struct amd_iommu *iommu, u64 base, size_t size)
{
	void *region = NULL;
	int ret;

	ret = viommu_priv_alloc_map(iommu, base, size, GFP_KERNEL, &region);
	if (ret)
		return NULL;

	pr_debug("%s: base=%#llx, size=%#lx, subregion=%#llx(%#llx)\n",
		 __func__, base, size, (unsigned long long)region, iommu_virt_to_phys(region));

	return region;
}

static void viommu_private_space_uninit(struct amd_iommu *iommu)
{
	int i;
	u64 base;
	struct protection_domain *pdom;
	struct iommu_domain *dom;

	pdom = iommu->viommu_pdom;
	if (!pdom)
		return;

	for (i = 0; i < VIOMMU_PRIV_SUBREGION_CNT; i++) {
		if (!iommu->viommu_priv_region[i])
			continue;
		base = VIOMMU_PRIV_REGION_BASE + (i * VIOMMU_PRIV_SUBREGION_SIZE);
		viommu_priv_unmap_free(iommu, base, VIOMMU_PRIV_SUBREGION_SIZE,
					     iommu->viommu_priv_region[i]);
		iommu->viommu_priv_region[i] = NULL;
	}

	dom = &pdom->domain;
	amd_iommu_pdom_unbind_iommu(iommu, pdom);
	amd_iommu_domain_free(dom);
	iommu->viommu_pdom = NULL;
}

static int viommu_private_space_init(struct amd_iommu *iommu)
{
	int i, ret;
	u64 base;
	struct iommu_domain *dom;
	struct protection_domain *pdom;
	struct pt_iommu_amdv1_hw_info pt_info;

	dom = amd_iommu_domain_alloc_paging_v1(&iommu->dev->dev, 0);
	if (IS_ERR(dom)) {
		pr_err("%s: Failed to initialize private space\n", __func__);
		return PTR_ERR(dom);
	}

	/*
	 * Skipped iommu_domain_init(). set_dte_entry() only programs
	 * v1 when type has __IOMMU_DOMAIN_PAGING.
	 */
	dom->type = IOMMU_DOMAIN_UNMANAGED;

	pdom = to_pdomain(dom);
	iommu->viommu_pdom = pdom;

	ret = amd_iommu_pdom_bind_iommu(iommu, pdom);
	if (ret) {
		amd_iommu_domain_free(dom);
		iommu->viommu_pdom = NULL;
		return ret;
	}

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
 * Returns VF MMIO BAR offset for the given guest ID which will be
 * mapped to guest vIOMMU 3rd 4K MMIO address
 */
u64 amd_viommu_get_vfmmio_addr(struct amd_iommu *iommu, u16 gid)
{
	if (WARN_ON(!iommu->vf_base_phys || gid > VIOMMU_MAX_GID))
		return 0;

	return iommu->vf_base_phys + gid * VIOMMU_VF_MMIO_ENTRY_SIZE;
}

int __init amd_viommu_init(struct amd_iommu *iommu)
{
	int ret;

	ret = viommu_vf_vfcntl_init(iommu);
	if (ret)
		return ret;

	ret = viommu_private_space_init(iommu);
	if (ret)
		goto err;

	ret = viommu_alloc_self_dev_data(iommu);
	if (ret)
		goto err;

	iommu->flags |= AMD_IOMMU_FLAG_VIOMMU_EN;
	return 0;
err:
	amd_viommu_uninit(iommu);
	return ret;
}

static int __maybe_unused alloc_private_vm_region(struct amd_iommu *iommu, u64 **entry,
						 u64 base, size_t size, u16 gid)
{
	int ret;
	void *va = NULL;
	u64 addr = base + (gid * size);

	/* Charge the caller; boot IPA stays GFP_KERNEL. */
	ret = viommu_priv_alloc_map(iommu, addr, size, GFP_KERNEL_ACCOUNT, &va);
	if (ret) {
		*entry = NULL;
		return ret;
	}

	*entry = (u64 *)va;

	pr_debug("%s: entry=%#llx(%#llx), addr=%#llx, size=%#lx\n", __func__,
		 (unsigned long long)*entry, iommu_virt_to_phys(*entry), addr, size);

	return 0;
}

static void __maybe_unused free_private_vm_region(struct amd_iommu *iommu, u64 **entry,
						  u64 base, size_t size, u16 gid)
{
	u64 addr = base + (gid * size);

	if (!iommu || !iommu->viommu_pdom || !*entry)
		return;

	pr_debug("%s: entry=%#llx(%#llx), base=%#llx, addr=%#llx, size=%#lx\n",
		 __func__, (unsigned long long)*entry,
		 iommu_virt_to_phys(*entry), base, addr, size);

	viommu_priv_unmap_free(iommu, addr, size, *entry);

	*entry = NULL;
}

void amd_viommu_uninit_one(struct amd_iommu *iommu, struct amd_iommu_viommu *aviommu)
{
	pr_debug("%s: gid=%u\n", __func__, aviommu->gid);

	free_private_vm_region(iommu, &aviommu->devid_table,
			       VIOMMU_DEVID_MAPPING_BASE,
			       VIOMMU_DEVID_MAPPING_ENTRY_SIZE,
			       aviommu->gid);
	free_private_vm_region(iommu, &aviommu->domid_table,
			       VIOMMU_DOMID_MAPPING_BASE,
			       VIOMMU_DOMID_MAPPING_ENTRY_SIZE,
			       aviommu->gid);
}

int amd_viommu_init_one(struct amd_iommu *iommu, struct amd_iommu_viommu *viommu)
{
	int ret;

	ret = alloc_private_vm_region(iommu, &viommu->devid_table,
				      VIOMMU_DEVID_MAPPING_BASE,
				      VIOMMU_DEVID_MAPPING_ENTRY_SIZE,
				      viommu->gid);
	if (ret)
		goto err_out;

	ret = alloc_private_vm_region(iommu, &viommu->domid_table,
				      VIOMMU_DOMID_MAPPING_BASE,
				      VIOMMU_DOMID_MAPPING_ENTRY_SIZE,
				      viommu->gid);
	if (ret)
		goto err_out;

	return 0;
err_out:
	amd_viommu_uninit_one(iommu, viommu);
	return ret;
}
