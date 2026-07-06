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

static LIST_HEAD(ext_ir_attached_viommus);
static DEFINE_SPINLOCK(ext_ir_attached_lock);

void amd_viommu_attach_ext_ir_kvm(struct amd_iommu_viommu *aviommu,
				  struct kvm *kvm)
{
	unsigned long flags;

	spin_lock_irqsave(&ext_ir_attached_lock, flags);
	if (!aviommu->ext_ir_kvm) {
		aviommu->ext_ir_kvm = kvm;
		list_add(&aviommu->kvm_ext_ir_node, &ext_ir_attached_viommus);
	}
	spin_unlock_irqrestore(&ext_ir_attached_lock, flags);
}

static void amd_viommu_detach_ext_ir_kvm(struct amd_iommu_viommu *aviommu)
{
	unsigned long flags;

	spin_lock_irqsave(&ext_ir_attached_lock, flags);
	if (aviommu->ext_ir_kvm) {
		list_del_init(&aviommu->kvm_ext_ir_node);
		aviommu->ext_ir_kvm = NULL;
	}
	spin_unlock_irqrestore(&ext_ir_attached_lock, flags);
}

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

#define EXT_INT_REMAP_TBL_L1_SIZE (PAGE_SIZE * 2)

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

static void viommu_free_self_dev_data(struct amd_iommu *iommu, bool clear_dte)
{
	struct iommu_dev_data *dev_data = iommu->viommu_dev_data;

	if (!dev_data)
		return;

	if (clear_dte) {
		struct dev_table_entry new = {};

		amd_iommu_make_clear_dte(iommu, dev_data->devid, &new);
		amd_iommu_update_dte(iommu, dev_data, &new);
	}

	amd_iommu_free_dev_data(iommu, dev_data);
	iommu->viommu_dev_data = NULL;
}

void __init amd_viommu_uninit(struct amd_iommu *iommu)
{
	viommu_free_self_dev_data(iommu, true);
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

static int alloc_ext_int_remap_tbl(struct amd_iommu *iommu)
{
	iommu->ext_ir_table = (void *) __get_free_pages(GFP_KERNEL | __GFP_ZERO,
							get_order(EXT_INT_REMAP_TBL_L1_SIZE));

	return iommu->ext_ir_table ? 0 : -ENOMEM;
}

static void free_ext_int_remap_tbl(struct amd_iommu *iommu)
{
	if (!iommu->ext_ir_table)
		return;

	free_pages((unsigned long)iommu->ext_ir_table,
		   get_order(EXT_INT_REMAP_TBL_L1_SIZE));
	iommu->ext_ir_table = NULL;
}

/* Set DTE for IOMMU device */
static void set_dte_ipa(struct amd_iommu *iommu, struct dev_table_entry *new)
{
	struct pt_iommu_amdv1_hw_info pt_info;
	struct protection_domain *pdom = iommu->viommu_pdom;

	pt_iommu_amdv1_hw_info(&pdom->amdv1, &pt_info);
	amd_iommu_set_dte_v1(iommu->viommu_dev_data, pdom, pdom->id, &pt_info, new);
}

int __init amd_viommu_init(struct amd_iommu *iommu)
{
	int ret;
	bool dte_set = false;
	struct dev_table_entry new = {};

	if (!amd_iommu_viommu ||
	    !check_feature(FEATURE_VIOMMU))
		return 0;

	iommu->viommu_dev_data = amd_iommu_alloc_dev_data(iommu, iommu->devid);
	if (!iommu->viommu_dev_data) {
		pr_err("%s: Failed to allocate dev_data\n", __func__);
		return -ENOMEM;
	}
	iommu->viommu_dev_data->dev = &iommu->dev->dev;

	ret = viommu_init_pci_vsc(iommu);
	if (ret)
		goto err_dev_data;

	ret = viommu_vf_vfcntl_init(iommu);
	if (ret)
		goto err_dev_data;

	amd_viommu_gid_ida_init(iommu);

	ret = viommu_private_space_init(iommu);
	if (ret)
		goto err_unmap_vf;

	ret = alloc_ext_int_remap_tbl(iommu);
	if (ret)
		goto err_private_space;

	/* Set DTE for IOMMU device */
	amd_iommu_make_clear_dte(iommu, iommu->devid, &new);
	set_dte_ipa(iommu, &new);
	amd_iommu_update_dte(iommu, iommu->viommu_dev_data, &new);
	amd_iommu_update_dte_ir(iommu, iommu->viommu_dev_data,
				iommu_virt_to_phys(iommu->ext_ir_table),
				DTE_EXT_INTTABLEN_L1);
	dte_set = true;

	hash_init(iommu->ext_irte_hlist);
	spin_lock_init(&iommu->ext_irte_hlist_lock);

	return 0;

err_private_space:
	viommu_private_space_uninit(iommu);
	free_ext_int_remap_tbl(iommu);
err_unmap_vf:
	amd_viommu_uninit(iommu);
err_dev_data:
	viommu_free_self_dev_data(iommu, dte_set);
	return ret;
}

static int __maybe_unused alloc_private_vm_region(struct amd_iommu *iommu, u64 **entry,
						 u64 base, size_t size, u16 gid)
{
	int ret;
	void *va = NULL;
	u64 addr = base + (gid * size);

	ret = viommu_priv_alloc_map_flush(iommu, addr, size, GFP_KERNEL | __GFP_ZERO, &va);
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

	viommu_priv_unmap_flush_free(iommu, addr, size, *entry);

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
	viommu_clear_mapping(iommu, aviommu);
}

int amd_viommu_init_one(struct amd_iommu *iommu, struct amd_iommu_viommu *viommu)
{
	int ret;

	INIT_LIST_HEAD(&viommu->kvm_ext_ir_node);

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

void amd_viommu_set_cmdbuf_flags(struct iommufd_hw_queue *hw_queue)
{
	u8 __iomem *vfctrl, *vf;
	u32 flags = hw_queue->flags;
	u64 val;
	struct iommufd_viommu *viommu = hw_queue->viommu;
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);
	struct amd_iommu *iommu = container_of(viommu->iommu_dev, struct amd_iommu, iommu);
	int gid = aviommu->gid;

	vf = VIOMMU_VF_MMIO_BASE(iommu, gid);
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);

	/* Clear fields in VFCTRL MMIO */
	val = readq(vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_COMMAND_CONTROL_OFFSET);
	val &= ~(GENMASK_ULL(51, 12) | GENMASK_ULL(9, 8) | GENMASK_ULL(3, 0));

	/* Set Command buffer base, length, enable, command wait enable */
	val |= FIELD_PREP(GENMASK_ULL(3, 0), hw_queue->length);
	val |= FIELD_PREP(GENMASK_ULL(51, 12), (hw_queue->base_addr >> 12));
	val |= FIELD_PREP(BIT_ULL_MASK(8), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_CMDBUF_EN));
	val |= FIELD_PREP(BIT_ULL_MASK(9), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_COMWAIT_EN));

	writeq(val, vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_COMMAND_CONTROL_OFFSET);

	pr_debug("%s: iommu_devid=%#x, gid=%#x, type=%#x, addr=%#llx, len=%#lx, flags=%#x, val=%#llx\n",
		 __func__, iommu->devid, gid, hw_queue->type,
		 hw_queue->base_addr, hw_queue->length, flags, val);
}

void amd_viommu_set_evtbuf_flags(struct iommufd_hw_queue *hw_queue)
{
	u8 __iomem *vfctrl, *vf;
	u32 flags = hw_queue->flags;
	u64 val;
	struct iommufd_viommu *viommu = hw_queue->viommu;
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);
	struct amd_iommu *iommu = container_of(viommu->iommu_dev, struct amd_iommu, iommu);
	int gid = aviommu->gid;

	vf = VIOMMU_VF_MMIO_BASE(iommu, gid);
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);

	/* Clear fields in VFCTRL MMIO */
	val = readq(vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_EVENT_CONTROL_OFFSET);
	val &= ~GENMASK_ULL(51, 0);

	/* Set Event buffer base and length */
	val |= FIELD_PREP(GENMASK_ULL(3, 0), hw_queue->length);
	val |= FIELD_PREP(GENMASK_ULL(51, 12), (hw_queue->base_addr >> 12));
	val |= FIELD_PREP(BIT_ULL_MASK(8), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_EVT_LOG_EN));
	val |= FIELD_PREP(BIT_ULL_MASK(9), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_EVT_INT_EN));
	writeq(val, vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_EVENT_CONTROL_OFFSET);

	pr_debug("%s: iommu_devid=%#x, gid=%#x, type=%#x, addr=%#llx, len=%#lx, flags=%#x, val=%#llx\n",
		 __func__, iommu->devid, gid, hw_queue->type,
		 hw_queue->base_addr, hw_queue->length, flags, val);
}

void amd_viommu_set_pprbuf_flags(struct iommufd_hw_queue *hw_queue)
{
	u8 __iomem *vfctrl, *vf;
	u32 flags = hw_queue->flags;
	u64 val;
	struct iommufd_viommu *viommu = hw_queue->viommu;
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);
	struct amd_iommu *iommu = container_of(viommu->iommu_dev, struct amd_iommu, iommu);
	int gid = aviommu->gid;

	vf = VIOMMU_VF_MMIO_BASE(iommu, gid);
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);

	/* Clear fields in VFCTRL MMIO */
	val = readq(vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_PPR_CONTROL_OFFSET);
	val &= ~GENMASK_ULL(55, 0);

	/* Set PPR buffer base and length */
	val |= FIELD_PREP(GENMASK_ULL(3, 0), hw_queue->length);
	val |= FIELD_PREP(GENMASK_ULL(55, 16), (hw_queue->base_addr >> 12));
	val |= FIELD_PREP(BIT_ULL_MASK(8), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_PPRLOG_EN));
	val |= FIELD_PREP(BIT_ULL_MASK(9), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_PPRINT_EN));
	val |= FIELD_PREP(BIT_ULL_MASK(10), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_PPR_EN));
	val |= FIELD_PREP(BIT_ULL_MASK(13), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_PPR_AUTO_RSP_EN));
	val |= FIELD_PREP(BIT_ULL_MASK(14), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_BLKSTOPMRK_EN));
	val |= FIELD_PREP(BIT_ULL_MASK(15), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_PPR_AUTO_RSP_AON));
	writeq(val, vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_PPR_CONTROL_OFFSET);

	pr_debug("%s: iommu_devid=%#x, gid=%#x, type=%#x, addr=%#llx, len=%#lx, flags=%#x, val=%#llx\n",
		 __func__, iommu->devid, gid, hw_queue->type,
		 hw_queue->base_addr, hw_queue->length, flags, val);
}

/*****************************************************
 * Extended interrupt remapping support
 */
#define EXT_IR_ID(x, y)		(((x & 0x3) << 16) | (y & 0xFFFF))
#define EXT_IR_ID_2_TYPE(x)	((x >> 16) & 0x3)
#define EXT_IR_ID_2_L1(x)	((x >> 8) & 0x3FF)
#define EXT_IR_ID_2_L2(x)	(x & 0xFF)

static struct irte_ga *_get_ext_intremap_entry(struct amd_iommu *iommu, u32 ext_id)
{
	u64 *l1_entry, *l2_entry;
	struct irte_ga *l2_table;
	u32 l1_index = EXT_IR_ID_2_L1(ext_id);
	u32 l2_index = EXT_IR_ID_2_L2(ext_id);

	l1_entry = &iommu->ext_ir_table[l1_index];

	/* Check if the l1_entry is valid */
	if (*l1_entry & 1ULL) {
		l2_table = iommu_phys_to_virt(*l1_entry & 0x000FFFFFFFFFFFC0);
	} else {
		int size = get_irq_table_size(MAX_IRQS_PER_TABLE_512);

		l2_table = iommu_alloc_pages_node_sz(dev_to_node(&iommu->dev->dev),
						     GFP_KERNEL, size);
		if (!l2_table)
			return NULL;

		/* Setup the L1 entry */
		*l1_entry = iommu_virt_to_phys(l2_table) & 0x000FFFFFFFFFFFC0;
		*l1_entry |= (EXT_INTTABLEN_L2_VALUE << 2);
		*l1_entry |= 1ULL; /* Valid */
	}
	l2_entry = (u64*) &l2_table[l2_index];

	pr_debug("%s: type=%#x, ext_intremap_tbl=%#llx, l1_entry=%#llx(%#llx, %u), l2_entry=%#llx(%#llx, %u)\n",
		__func__, EXT_IR_ID_2_TYPE(ext_id),
		iommu_virt_to_phys(iommu->ext_ir_table),
		iommu_virt_to_phys(l1_entry), *l1_entry, l1_index,
		iommu_virt_to_phys(l2_entry), *l2_entry, l2_index);

	return &l2_table[l2_index];
}

static struct ext_irte *get_ext_intremap_entry(struct amd_iommu *iommu, u32 ext_id)
{
	unsigned long flags;
	struct ext_irte *tmp, *eirte = NULL;

	spin_lock_irqsave(&iommu->ext_irte_hlist_lock, flags);

	hash_for_each_possible(iommu->ext_irte_hlist, tmp, hnode, ext_id) {
		if (tmp->ext_id == ext_id) {
			eirte = tmp;
			break;
		}
	}

	if (eirte)
		goto out;

	/* Allocate new ext-irte */
	eirte = kzalloc(sizeof(*eirte), GFP_KERNEL);
	if (!eirte)
		goto out;

	eirte->entry_ptr = _get_ext_intremap_entry(iommu, ext_id);
	if (!eirte->entry_ptr)
		goto out_free_eirte;

	eirte->ext_id = ext_id;
	hash_add(iommu->ext_irte_hlist, &eirte->hnode, ext_id);
	goto out;

out_free_eirte:
	kfree(eirte);
	eirte = NULL;
out:
	spin_unlock_irqrestore(&iommu->ext_irte_hlist_lock, flags);
	return eirte;
}

int amd_viommu_set_ext_int_remap_entry(struct iommufd_viommu *viommu,
				       struct kvm *kvm,
				       enum ext_intremap_type type, u32 vcpu_id,
				       u8 vector)
{
	struct ext_irte *eirte;
	struct amd_ir_data *ir_data;
	struct amd_iommu_pi_data pi;
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);
	struct amd_iommu *iommu = container_of(viommu->iommu_dev, struct amd_iommu, iommu);
	u64 pa;
	u32 ga_tag;
	u32 ext_id = EXT_IR_ID(type, aviommu->gid);

	if (!svm_ops)
		return -ENODEV;

	if (svm_ops->prepare_ext_ir_rebind)
		svm_ops->prepare_ext_ir_rebind(kvm);

	ga_tag = svm_ops->get_ga_tag(kvm, vcpu_id);
	pa = svm_ops->get_apic_backing_page(kvm, vcpu_id);
	if (!ga_tag || !pa)
		return -EINVAL;

	eirte = get_ext_intremap_entry(iommu, ext_id);
	if (!eirte)
		return -ENOMEM;

	ir_data = &eirte->ir_data;
	ir_data->iommu = iommu;
	ir_data->is_ext = true;
	ir_data->ext_id = ext_id;
	ir_data->entry = &eirte->entry;

	/*
	 * Drop stale hardware programming left in the table when teardown did
	 * not fully clear the entry (e.g. after a prior QEMU session).
	 */
	if (eirte->entry_ptr->lo.fields_vapic.guest_mode)
		amd_iommu_reset_ext_irte(iommu, eirte);

	pr_debug("%s: type=%#x, vcpu_id=%#x, vector=%#x, backing_page=%#llx, ga_tag=%#x\n",
		 __func__, type, vcpu_id, vector, pa, ga_tag);

	/* This is normally setup during prepare */
	eirte->entry.lo.fields_vapic.valid = 1;

	/*
	 * Initialize ir_data, which will be used in
	 * amd_iommu_activate_guest_mode()
	 */
	ir_data->ga_root_ptr = (pa & 0xFFFFFFFFFFFFFULL) >> 12;
	ir_data->ga_tag = ga_tag;
	ir_data->ga_vector = vector;

	pi.ir_data = ir_data;
	pi.ga_tag = ga_tag;

	svm_ops->set_ext_ir_affinity(kvm, vcpu_id, &pi);

	return 0;
}
