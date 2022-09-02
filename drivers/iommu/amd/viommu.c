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

#define EXT_INT_REMAP_TBL_L1_SIZE (PAGE_SIZE * 2)

LIST_HEAD(viommu_devid_map);

static int viommu_enable(struct amd_iommu *iommu)
{
	/* The GstBufferTRPMode feature is checked by set and test */
	if (!iommu_feature_enable_and_check(iommu, CONTROL_GSTBUFFERTRPMODE))
		return -EINVAL;

	iommu_feature_enable(iommu, CONTROL_VCMD_EN);
	iommu_feature_enable(iommu, CONTROL_VIOMMU_EN);

	return 0;
}

static int viommu_init_pci_vsc(struct amd_iommu *iommu)
{
	iommu->vsc_offset = pci_find_capability(iommu->dev, PCI_CAP_ID_VNDR);
	if (!iommu->vsc_offset)
		return -ENODEV;

	DUMP_printk("device:%s, vsc offset:%04x\n",
		    pci_name(iommu->dev), iommu->vsc_offset);
	return 0;
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
	iommu->vf_base = iommu_map_mmio_space(vf_phys, 0x10000000);
	if (!iommu->vf_base) {
		pr_err("Can't reserve vf_base\n");
		return -ENOMEM;
	}

	vf_cntl_phys &= ~1ULL;
	iommu->vfctrl_base = iommu_map_mmio_space(vf_cntl_phys, 0x400000);

	if (!iommu->vfctrl_base) {
		pr_err("Can't reserve vfctrl_base\n");
		return -ENOMEM;
	}

	/* Track VF MMIO base addess */
	iommu->vf_base_phys = vf_phys;

	pr_debug("%s: IOMMU device:%s, vf_base:%#llx, vfctrl_base:%#llx\n",
		 __func__, pci_name(iommu->dev), vf_phys, vf_cntl_phys);
	return 0;
}

static struct iommu_domain *
viommu_domain_alloc(struct amd_iommu *iommu)
{
	int ret;
	struct pt_iommu_amdv1_cfg cfg = {};
	struct protection_domain *domain;

	domain = protection_domain_alloc();
	if (!domain)
		return NULL;

	domain->pd_mode = PD_MODE_V1;
	domain->iommu.driver_ops = &amd_hw_driver_ops_v1;
	domain->iommu.nid = dev_to_node(&iommu->dev->dev);

	cfg.common.features = BIT(PT_FEAT_DYNAMIC_TOP) |
			      BIT(PT_FEAT_AMDV1_ENCRYPT_TABLES) |
			      BIT(PT_FEAT_AMDV1_FORCE_COHERENCE);
	cfg.common.features |= BIT(PT_FEAT_FLUSH_RANGE);
	cfg.common.hw_max_vasz_lg2 =
		min(64, (amd_iommu_hpt_level - 1) * 9 + 21);
	cfg.common.hw_max_oasz_lg2 = 52;
	cfg.starting_level = 2;
	domain->domain.ops = &amdv1_ops;

	ret = pt_iommu_amdv1_init(&domain->amdv1, &cfg, GFP_KERNEL);
	if (ret) {
		amd_iommu_domain_free(&domain->domain);
		return ERR_PTR(ret);
	}

	/*
	 * Narrow the supported page sizes to those selected by the kernel
	 * command line.
	 */
	domain->domain.pgsize_bitmap &= amd_iommu_pgsize_bitmap;
	domain->domain.type = IOMMU_DOMAIN_UNMANAGED;

	return &domain->domain;
}

static void *alloc_private_subregion(struct amd_iommu *iommu, u64 base, size_t size)
{
	int ret;
	void *region;
	size_t mapped;
	int nid = iommu && iommu->dev ? dev_to_node(&iommu->dev->dev) : NUMA_NO_NODE;

	region = (void *)iommu_alloc_pages_node_sz(nid, GFP_KERNEL | __GFP_ZERO, size);
	if (!region)
		return NULL;

	ret = set_memory_uc((unsigned long)region, size >> PAGE_SHIFT);
	if (ret)
		goto err_out;

	ret = pt_iommu_amdv1_map_pages(&iommu->viommu_pdom->domain, base,
				     iommu_virt_to_phys(region), PAGE_SIZE, (size / PAGE_SIZE),
				     IOMMU_PROT_IR | IOMMU_PROT_IW, GFP_KERNEL, &mapped);

	if (ret)
		goto err_out;

	pr_debug("%s: base=%#llx, size=%#lx, subregion=%#llx(%#llx)\n",
		 __func__, base, size, (unsigned long long)region, iommu_virt_to_phys(region));

	amd_iommu_flush_private_vm_region(iommu, iommu->viommu_pdom, base, size);

	return region;

err_out:
	free_pages((unsigned long)region, get_order(size));
	return NULL;
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
	dom = viommu_domain_alloc(iommu);
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
			goto err_out;
		}
	}

	pt_iommu_amdv1_hw_info(&pdom->amdv1, &pt_info);
	pr_debug("%s: devid=%#x, pte_root=%#llx\n",
		 __func__, iommu->devid,
		 (unsigned long long)pt_info.host_pt_root);

	return 0;
err_out:
	for (i = 0; i < VIOMMU_PRIV_SUBREGION_CNT; i++) {
		if (iommu->viommu_priv_region[i])
			free_pages((unsigned long)iommu->viommu_priv_region[i],
				    get_order(VIOMMU_PRIV_SUBREGION_SIZE));
	}
	if (dom)
		amd_iommu_domain_free(dom);
	return -ENOMEM;
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

static int alloc_ext_int_remap_tbl_entry(struct amd_iommu *iommu)
{
	iommu->ext_ir_table = (void *) __get_free_pages(GFP_KERNEL | __GFP_ZERO,
							get_order(EXT_INT_REMAP_TBL_L1_SIZE));

	return iommu->ext_ir_table ? 0 : -ENOMEM;
}

/* Set DTE for IOMMU device */
static void set_iommu_dte(struct amd_iommu *iommu)
{
	u64 dte0, dte1, dte2;
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

	/* For Extended Interrupt Remapping Table */
	dte2 = dev_table[devid].data[2];
	dte2 &= ~DTE_IRQ_PHYS_ADDR_MASK;
	dte2 |= iommu_virt_to_phys(iommu->ext_ir_table);
	dte2 |= DTE_IRQ_REMAP_INTCTL;
	dte2 |= DTE_EXT_INTTABLEN_L1;
	dte2 |= DTE_IRQ_REMAP_ENABLE;

	dev_table[devid].data[2] = dte2;
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

	ret = alloc_ext_int_remap_tbl_entry(iommu);
	if (ret)
		return ret;

	ret = viommu_private_space_init(iommu);
	if (ret)
		return ret;

	set_iommu_dte(iommu);

	hash_init(iommu->ext_irte_hlist);
	spin_lock_init(&iommu->ext_irte_hlist_lock);

	ret = viommu_enable(iommu);
	if (ret)
		return ret;

	return 0;
}

static int alloc_private_vm_region(struct amd_iommu *iommu, u64 **entry,
				   u64 base, size_t size, u16 gid)
{
	int ret;
	size_t mapped;
	u64 addr = base + (gid * size);
	int nid = iommu && iommu->dev ? dev_to_node(&iommu->dev->dev) : NUMA_NO_NODE;

	*entry = (void *)iommu_alloc_pages_node_sz(nid, GFP_KERNEL | __GFP_ZERO, size);
	if (!*entry)
		return -ENOMEM;

	ret = set_memory_uc((unsigned long)*entry, size >> PAGE_SHIFT);
	if (ret)
		return ret;

	pr_debug("%s: entry=%#llx(%#llx), addr=%#llx, size=%#lx\n", __func__,
		 (unsigned long  long)*entry, iommu_virt_to_phys(*entry), addr, size);

	ret = pt_iommu_amdv1_map_pages(&iommu->viommu_pdom->domain, addr,
				       iommu_virt_to_phys(*entry), PAGE_SIZE, (size / PAGE_SIZE),
				       IOMMU_PROT_IR | IOMMU_PROT_IW, GFP_KERNEL, &mapped);
	if (ret)
		return ret;

	return amd_iommu_flush_private_vm_region(iommu, iommu->viommu_pdom, addr, size);
}

static void free_private_vm_region(struct amd_iommu *iommu, u64 **entry,
					u64 base, size_t size, u16 gid)
{
	size_t ret;
	struct iommu_iotlb_gather gather;
	u64 addr = base + (gid * size);

	pr_debug("%s: entry=%#llx(%#llx), base=%#llx, addr=%#llx, size=%#lx\n",
		 __func__, (unsigned long  long)*entry,
		 iommu_virt_to_phys(*entry), base, addr, size);

	if (!iommu || !iommu->viommu_pdom)
		return;

	iommu_iotlb_gather_init(&gather);
	ret = pt_iommu_amdv1_unmap_pages(&iommu->viommu_pdom->domain,
					 addr, PAGE_SIZE, (size / PAGE_SIZE), &gather);
	if (ret)
		amd_iommu_iotlb_sync(&iommu->viommu_pdom->domain, &gather);

	iommu_free_pages(*entry);
	*entry = NULL;
}

/*
 * Program the DevID via VFCTRL registers
 * This function will be called during VM init via VFIO.
 */
void amd_viommu_set_device_mapping(struct amd_iommu *iommu, u16 hDevId,
				   u16 guestId, u16 gDevId)
{
	u64 val, tmp1, tmp2;
	u8 __iomem *vfctrl;

	pr_debug("%s: iommu_devid=%#x, gid=%#x, hDevId=%#x, gDevId=%#x\n",
		__func__, pci_dev_id(iommu->dev), guestId, hDevId, gDevId);

	tmp1 = gDevId;
	tmp1 = ((tmp1 & 0xFFFFULL) << 46);
	tmp2 = hDevId;
	tmp2 = ((tmp2 & 0xFFFFULL) << 14);
	val = tmp1 | tmp2 | 0x8000000000000001ULL;
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, guestId);
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL0_OFFSET);
}

/*
 * Clear the DevID via VFCTRL registers
 * This function will be called during VM destroy via VFIO.
 */
static void clear_device_mapping(struct amd_iommu *iommu, u16 guestId, u16 gDevId)
{
	u64 val, tmp1, tmp2;
	u8 __iomem *vfctrl;

	/*
	 * Clear the DevID in VFCTRL registers
	 */
	tmp1 = gDevId;
	tmp1 = ((tmp1 & 0xFFFFULL) << 46);
	tmp2 = 0; /* hDevId */
	tmp2 = ((tmp2 & 0xFFFFULL) << 14);
	val = tmp1 | tmp2 | 0x8000000000000001ULL;
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
int amd_viommu_domain_id_update(struct amd_iommu *iommu, u16 gid,
				u16 hdom_id, u16 gdom_id)
{
	u64 val, tmp1, tmp2;
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);

	tmp1 = gdom_id;
	tmp1 = ((tmp1 & 0xFFFFULL) << 46);
	tmp2 = hdom_id;
	tmp2 = ((tmp2 & 0xFFFFULL) << 14);
	val = tmp1 | tmp2 | 0x8000000000000001UL;
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL1_OFFSET);

	return 0;
}
EXPORT_SYMBOL(amd_viommu_domain_id_update);

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

struct ext_irte * amd_viommu_get_ext_irte(struct amd_iommu *iommu, u32 ext_id)
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
				       enum ext_intremap_type type, u64 val)
{
	struct ext_irte *eirte;
	struct amd_ir_data *ir_data;
	struct amd_iommu_pi_data pi;
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);
	struct amd_iommu *iommu = container_of(viommu->iommu_dev, struct amd_iommu, iommu);
	u64 pa;
	u32 ga_tag;
	u32 dest1 = (val >> 8) & 0xFFFFFF;
	u32 dest2 = (val >> 56) & 0xFF;
	u32 dest = (dest2 << 24) | dest1;
	u8 vector = (val >> 32) & 0xFF;
	u32 ext_id = EXT_IR_ID(type, aviommu->gid);

	if (!svm_ops)
		return -EINVAL;

	ga_tag = svm_ops->get_ga_tag(aviommu->kvm, dest);
	pa = svm_ops->get_apic_backing_page(aviommu->kvm, dest);
	if (!ga_tag || !pa)
		return -EINVAL;

	eirte = amd_viommu_get_ext_irte(iommu, ext_id);
	if (!eirte)
		return -EINVAL;

	pr_debug("%s: type=%#x, dest=%#x, vector=%#x, backing_page=%#llx, ga_tag=%#x\n",
		 __func__, type, dest, vector, pa, ga_tag);

	/* This is normally setup during prepare */
	eirte->entry.lo.fields_vapic.valid = 1;

	/*
	 * Initialize ir_data, which will be used in
	 * amd_iommu_activate_guest_mode()
	 */
	ir_data = &eirte->ir_data;
	ir_data->iommu = iommu;
	ir_data->is_ext = true;
	ir_data->ext_id = ext_id;
	ir_data->ga_root_ptr = (pa & 0xFFFFFFFFFFFFFULL) >> 12;
	ir_data->ga_tag = ga_tag;
	ir_data->ga_vector = vector;
	ir_data->entry = &eirte->entry;

	pi.ir_data = ir_data;
	pi.ga_tag = ga_tag;

	svm_ops->set_ext_ir_affinity(aviommu->kvm, dest, &pi);

	return 0;
}
