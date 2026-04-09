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

/*
 * Guest Device ID Mapping Table
 */
#define VIOMMU_MAX_GDEVID	0xFFFF
#define VIOMMU_DEVID_MAPPING_BASE	0x1000000000ULL
#define VIOMMU_DEVID_MAPPING_ENTRY_SIZE	(1 << 20)

/*
 * Guest Domain ID Mapping Table
 */
#define VIOMMU_MAX_GDOMID	0xFFFF
#define VIOMMU_DOMID_MAPPING_BASE	0x2000000000ULL
#define VIOMMU_DOMID_MAPPING_ENTRY_SIZE	(1 << 19)

#define VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL0_OFFSET	0x00
#define VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL1_OFFSET	0x08

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

static void *alloc_private_subregion(struct amd_iommu *iommu, u64 base, size_t size)
{
	int ret;
	void *region;
	int nid = iommu && iommu->dev ? dev_to_node(&iommu->dev->dev) : NUMA_NO_NODE;

	region = (void *)iommu_alloc_pages_node_sz(nid, GFP_KERNEL | __GFP_ZERO, size);
	if (!region)
		return NULL;

	ret = set_memory_uc((unsigned long)region, size >> PAGE_SHIFT);
	if (ret)
		goto err_out;

	ret = iommu_map(&iommu->viommu_pdom->domain, base,
			iommu_virt_to_phys(region), size,
			IOMMU_PROT_IR | IOMMU_PROT_IW, GFP_KERNEL);

	if (ret)
		goto cleanup_mem_attr;

	pr_debug("%s: base=%#llx, size=%#lx, subregion=%#llx(%#llx)\n",
		 __func__, base, size, (unsigned long long)region, iommu_virt_to_phys(region));

	amd_iommu_flush_private_vm_region(iommu, iommu->viommu_pdom, base, size);

	return region;
cleanup_mem_attr:
	set_memory_wb((unsigned long)region, size >> PAGE_SHIFT);
err_out:
	iommu_free_pages(region);
	return NULL;
}

static void viommu_private_space_uninit(struct amd_iommu *iommu)
{
	int i;
	struct iommu_domain *dom;

	if (!iommu->viommu_pdom)
		return;

	for (i = 0; i < VIOMMU_PRIV_SUBREGION_CNT; i++) {
		if (!iommu->viommu_priv_region[i])
			continue;
		set_memory_wb((unsigned long)iommu->viommu_priv_region[i],
			      VIOMMU_PRIV_SUBREGION_SIZE >> PAGE_SHIFT);
		iommu_free_pages(iommu->viommu_priv_region[i]);
		iommu->viommu_priv_region[i] = NULL;
	}

	dom = &iommu->viommu_pdom->domain;
	amd_iommu_domain_free(dom);
	iommu->viommu_pdom = NULL;
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

/* Set DTE for IOMMU device */
static void set_iommu_dte(struct amd_iommu *iommu)
{
	u64 dte0, dte1;
	u16 devid = iommu->devid;
	struct pt_iommu_amdv1_hw_info pt_info;
	struct protection_domain *pdom = iommu->viommu_pdom;
	struct dev_table_entry *dev_table = get_dev_table(iommu);

	pt_iommu_amdv1_hw_info(&pdom->amdv1, &pt_info);

	pr_debug("%s: host_pt_root=%#llx, mode=%#x\n",
		 __func__, pt_info.host_pt_root, pt_info.mode);

	dte0 = FIELD_PREP(DTE_HOST_TRP, pt_info.host_pt_root >> 12);
	dte0 |= (pt_info.mode & DEV_ENTRY_MODE_MASK) << DEV_ENTRY_MODE_SHIFT;
	dte0 |= DTE_FLAG_IR | DTE_FLAG_IW | DTE_FLAG_V | DTE_FLAG_TV;

	dte1 = dev_table[devid].data[1];
	dte1 &= ~DTE_DOMID_MASK;
	dte1 |= pdom->id;

	dev_table[devid].data[1] = dte1;
	dev_table[devid].data[0] = dte0;

	iommu_flush_dte(iommu, devid);
	amd_iommu_completion_wait(iommu);
}

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

	set_iommu_dte(iommu);

	return 0;
}

static int __maybe_unused alloc_private_vm_region(struct amd_iommu *iommu, u64 **entry,
						 u64 base, size_t size, u16 gid)
{
	int ret;
	u64 addr = base + (gid * size);
	int nid = iommu && iommu->dev ? dev_to_node(&iommu->dev->dev) : NUMA_NO_NODE;

	*entry = (void *)iommu_alloc_pages_node_sz(nid, GFP_KERNEL | __GFP_ZERO, size);
	if (!*entry)
		return -ENOMEM;

	ret = set_memory_uc((unsigned long)*entry, size >> PAGE_SHIFT);
	if (ret)
		goto err_out;

	pr_debug("%s: entry=%#llx(%#llx), addr=%#llx, size=%#lx\n", __func__,
		 (unsigned long  long)*entry, iommu_virt_to_phys(*entry), addr, size);

	ret = iommu_map(&iommu->viommu_pdom->domain, addr,
			iommu_virt_to_phys(*entry), size,
			IOMMU_PROT_IR | IOMMU_PROT_IW, GFP_KERNEL);
	if (ret)
		goto cleanup_mem_attr;

	return amd_iommu_flush_private_vm_region(iommu, iommu->viommu_pdom, addr, size);
cleanup_mem_attr:
	set_memory_wb((unsigned long)*entry, size >> PAGE_SHIFT);
err_out:
	iommu_free_pages(*entry);
	*entry = NULL;
	return ret;
}

static void __maybe_unused free_private_vm_region(struct amd_iommu *iommu, u64 **entry,
						  u64 base, size_t size, u16 gid)
{
	size_t unmapped;
	u64 addr = base + (gid * size);

	pr_debug("%s: entry=%#llx(%#llx), base=%#llx, addr=%#llx, size=%#lx\n",
		 __func__, (unsigned long  long)*entry,
		 iommu_virt_to_phys(*entry), base, addr, size);

	if (!iommu || !iommu->viommu_pdom)
		return;

	unmapped = iommu_unmap(&iommu->viommu_pdom->domain, addr, size);
	if (unmapped != size)
		pr_warn("%s: unmapped %#zx of %#lx at %#llx\n", __func__, unmapped, size, addr);

	set_memory_wb((unsigned long)*entry, size >> PAGE_SHIFT);
	iommu_free_pages(*entry);
	*entry = NULL;
}

#define DEVID_ENTRY_GDEVID_MASK		GENMASK_ULL(61, 46)
#define DEVID_ENTRY_HDEVID_MASK		GENMASK_ULL(29, 14)
#define DEVID_ENTRY_WRITE		BIT_ULL(63)
#define DEVID_ENTRY_VALID		BIT_ULL(0)

/*
 * Program the DevID via VFCTRL registers
 * This function will be called during VM init via VFIO.
 */
void amd_viommu_set_device_mapping(struct amd_iommu *iommu, u16 hDevId,
				   u16 guestId, u16 gDevId)
{
	u64 val;
	u8 __iomem *vfctrl;

	pr_debug("%s: iommu_devid=%#x, gid=%#x, hDevId=%#x, gDevId=%#x\n",
		__func__, pci_dev_id(iommu->dev), guestId, hDevId, gDevId);

	val = FIELD_PREP(DEVID_ENTRY_GDEVID_MASK, gDevId) |
	      FIELD_PREP(DEVID_ENTRY_HDEVID_MASK, hDevId) |
	      DEVID_ENTRY_WRITE | DEVID_ENTRY_VALID;

	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, guestId);

	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL0_OFFSET);
}

/*
 * Clear the DevID via VFCTRL registers
 * This function will be called during VM destroy via VFIO.
 */
static void clear_device_mapping(struct amd_iommu *iommu, u16 guestId, u16 gDevId)
{
	u64 val;
	u8 __iomem *vfctrl;

	/*
	 * Clear the DevID in VFCTRL registers
	 */
	val = FIELD_PREP(DEVID_ENTRY_GDEVID_MASK, gDevId) |
	      FIELD_PREP(DEVID_ENTRY_HDEVID_MASK, 0) |
	      DEVID_ENTRY_WRITE | DEVID_ENTRY_VALID;

	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, guestId);
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL0_OFFSET);
}

static void viommu_clear_mapping(struct amd_iommu *iommu,
				 struct amd_iommu_viommu *aviommu)
{
	int i;
	u16 gid = aviommu->gid;

	/*
	 * IOMMU hardware uses the domain ID mapping table to map gdom ID to hdom ID.
	 * If the mapping does not exist, the hardware would generate error in the event log.
	 * Therefore, initialize all gdom ID entries to map to parent domain ID to prevent
	 * unknown mapping scenario.
	 */
	for (i = 0; i <= VIOMMU_MAX_GDOMID; i++)
		amd_viommu_domain_id_update(iommu, gid, aviommu->parent->id, i);

	for (i = 0; i <= VIOMMU_MAX_GDEVID; i++)
		clear_device_mapping(iommu, gid, i);

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

	amd_iommu_update_vfctrl_mmio_translate_devid(iommu, aviommu->gid, 0);
	amd_iommu_clear_translate_dte(iommu, aviommu->gid, aviommu->trans_devid);
	viommu_clear_mapping(iommu, aviommu);
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

	viommu_clear_mapping(iommu, viommu);

	return 0;
err_out:
	amd_viommu_uninit_one(iommu, viommu);
	return -ENOMEM;
}

/*
 * Program the DomID via VFCTRL registers
 * This function will be called during VM init via VFIO.
 */

 #define DOMID_ENTRY_GDOMID_MASK	GENMASK_ULL(61, 46)
 #define DOMID_ENTRY_HDOMID_MASK	GENMASK_ULL(29, 14)
 #define DOMID_ENTRY_VALID		BIT_ULL(0)
 #define DOMID_ENTRY_WRITE		BIT_ULL(63)

int amd_viommu_domain_id_update(struct amd_iommu *iommu, u16 gid,
				u16 hdom_id, u16 gdom_id)
{
	u64 val;
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);

	val = FIELD_PREP(DOMID_ENTRY_GDOMID_MASK, gdom_id) |
	      FIELD_PREP(DOMID_ENTRY_HDOMID_MASK, hdom_id) |
	      DOMID_ENTRY_WRITE | DOMID_ENTRY_VALID;

	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL1_OFFSET);
	return 0;
}
EXPORT_SYMBOL(amd_viommu_domain_id_update);
