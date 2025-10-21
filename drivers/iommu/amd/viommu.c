// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Advanced Micro Devices, Inc.
 * Author: Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>
 */

#define pr_fmt(fmt)     "AMD-Vi: " fmt
#define dev_fmt(fmt)    pr_fmt(fmt)

#include <linux/iommu.h>
#include <linux/amd-iommu.h>

#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/ioctl.h>
#include <linux/iommufd.h>
#include <uapi/linux/iommufd.h>
#include <linux/mem_encrypt.h>

#include <asm/iommu.h>
#include <asm/set_memory.h>

#include "amd_iommu.h"
#include "amd_iommu_types.h"
#include "amd_viommu.h"
#include "../iommu-pages.h"

#define VIOMMU_MAX_GDEVID	0xFFFF
#define VIOMMU_MAX_GDOMID	0xFFFF

#define EXT_INT_REMAP_TBL_L1_SIZE (PAGE_SIZE * 2)

LIST_HEAD(viommu_devid_map);

static void viommu_clear_mapping(struct amd_iommu *iommu, u16 guestId);

static void viommu_clear_dirty_status_mask(struct amd_iommu *iommu, unsigned int gid);

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

static void *alloc_private_region(struct amd_iommu *iommu,
				  u64 base, size_t size)
{
	int ret;
	void *region;

	region  = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
						get_order(size));
	if (!region)
		return NULL;

	ret = set_memory_uc((unsigned long)region, size >> PAGE_SHIFT);
	if (ret)
		goto err_out;

	if (amd_iommu_v1_map_pages(&iommu->viommu_pdom->iop.pgtbl.ops, base,
				   iommu_virt_to_phys(region), PAGE_SIZE, (size / PAGE_SIZE),
				   IOMMU_PROT_IR | IOMMU_PROT_IW, GFP_KERNEL, NULL))
		goto err_out;

	pr_debug("%s: base=%#llx, size=%#lx\n", __func__, base, size);

	return region;

err_out:
	free_pages((unsigned long)region, get_order(size));
	return NULL;
}

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
	struct protection_domain *pdom = iommu->viommu_pdom;
	struct dev_table_entry *dev_table = get_dev_table(iommu);

	dte0 = iommu_virt_to_phys(pdom->iop.root);
	dte0 |= (pdom->iop.mode & DEV_ENTRY_MODE_MASK) << DEV_ENTRY_MODE_SHIFT;
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
	iommu_completion_wait(iommu);
}

static struct iommu_domain *
viommu_domain_alloc(struct amd_iommu *iommu)
{
	struct protection_domain *domain;
	struct io_pgtable_ops *pgtbl_ops;

	domain = protection_domain_alloc();
	if (!domain)
		return NULL;

	pgtbl_ops = alloc_io_pgtable_ops(AMD_IOMMU_V1, &domain->iop.pgtbl.cfg, domain);
	if (!pgtbl_ops)
		goto err_out;

	domain->pd_mode = PD_MODE_V1;
	domain->iop.pgtbl.cfg.amd.nid = dev_to_node(&iommu->dev->dev);

	domain->domain.geometry.aperture_start = 0;
	domain->domain.geometry.aperture_end   = ~0ULL;
	domain->domain.geometry.force_aperture = true;
	domain->domain.pgsize_bitmap = domain->iop.pgtbl.cfg.pgsize_bitmap;
	domain->domain.type = IOMMU_DOMAIN_UNMANAGED;
	domain->domain.ops = amd_iommu_ops.default_domain_ops;

	return &domain->domain;

err_out:
	amd_iommu_domain_free(&domain->domain);
	return NULL;
}

static int viommu_private_space_init(struct amd_iommu *iommu)
{
	u64 pte_root = 0;
	struct iommu_domain *dom;
	struct protection_domain *pdom;

	/*
	 * Setup page table root pointer, Guest MMIO and
	 * Cmdbuf Dirty Status regions.
	 */
	dom = viommu_domain_alloc(iommu);
	if (!dom) {
		pr_err("%s: Failed to initialize private space\n", __func__);
		goto err_out;
	}

	pdom = to_pdomain(dom);
	iommu->viommu_pdom = pdom;

	iommu->guest_mmio1 = alloc_private_region(iommu,
						 VIOMMU_GUEST_MMIO_BASE1,
						 VIOMMU_GUEST_MMIO_SIZE1);
	if (!iommu->guest_mmio1)
		goto err_out;

	iommu->guest_mmio2 = alloc_private_region(iommu,
						 VIOMMU_GUEST_MMIO_BASE2,
						 VIOMMU_GUEST_MMIO_SIZE2);
	if (!iommu->guest_mmio2)
		goto err_out;

	iommu->cmdbuf_dirty_mask = alloc_private_region(iommu,
							VIOMMU_CMDBUF_DIRTY_STATUS_BASE,
							VIOMMU_CMDBUF_DIRTY_STATUS_SIZE);
	if (!iommu->cmdbuf_dirty_mask)
		goto err_out;

	pte_root = iommu_virt_to_phys(pdom->iop.root);
	pr_debug("%s: devid=%#x, pte_root=%#llx(%#llx), guest_mmio1=%#llx(%#llx), guest_mmio2=%#llx(%#llx), cmdbuf_dirty_mask=%#llx(%#llx)\n",
		 __func__, iommu->devid, (unsigned long long)pdom->iop.root, pte_root,
		 (unsigned long long)iommu->guest_mmio1, iommu_virt_to_phys(iommu->guest_mmio1),
		 (unsigned long long)iommu->guest_mmio2, iommu_virt_to_phys(iommu->guest_mmio2),
		 (unsigned long long)iommu->cmdbuf_dirty_mask,
		 iommu_virt_to_phys(iommu->cmdbuf_dirty_mask));

	return 0;
err_out:
	if (iommu->guest_mmio1)
		free_pages((unsigned long)iommu->guest_mmio1, get_order(VIOMMU_GUEST_MMIO_SIZE1));
	if (iommu->guest_mmio2)
		free_pages((unsigned long)iommu->guest_mmio2, get_order(VIOMMU_GUEST_MMIO_SIZE2));

	if (dom)
		amd_iommu_domain_free(dom);
	return -ENOMEM;
}

/*
 * Returns VF MMIO BAR offset for the give guest ID which will be
 * mapped to guest vIOMMU 3rd 4K MMIO address
 */
u64 amd_viommu_get_vfmmio_addr(struct iommu_viommu_amd *data)
{
	unsigned int iommu_devid = data->iommu_devid;
	u64 addr;
	struct amd_iommu *iommu = get_amd_iommu_from_devid(iommu_devid);

	if (!iommu)
		return -ENODEV;

	/* TODO: Add check for sVIOMMU and set gid[bit 15] */
	addr = iommu->vf_base_phys + data->gid * VIOMMU_VF_MMIO_ENTRY_SIZE;

	return addr;
}
EXPORT_SYMBOL(amd_viommu_get_vfmmio_addr);

/*
 * When IOMMU Virtualization is enabled, host software must:
 *	- allocate system memory for IOMMU private space
 *	- program IOMMU as an I/O device in Device Table
 *	- maintain the I/O page table for IOMMU private addressing to SPA translations.
 *	- specify the base address of the IOMMU Virtual Function MMIO and
 *	  IOMMU Virtual Function Control MMIO region.
 *	- enable Guest Virtual APIC enable (MMIO Offset 0x18[GAEn]).
 */
int __init amd_viommu_init(struct amd_iommu *iommu)
{
	int ret;

	/* Note: vIOMMU support is disabled from boot option */
	if (!amd_iommu_viommu)
		return 0;

	if (!check_feature(FEATURE_VIOMMU))
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
				   u64 base, size_t size, u16 guestId)
{
	int ret;
	u64 addr = base + (guestId * size);

	*entry = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(size));

	ret = set_memory_uc((unsigned long)*entry, size >> PAGE_SHIFT);
	if (ret)
		return ret;

	pr_debug("%s: entry=%#llx(%#llx), addr=%#llx\n", __func__,
		 (unsigned long  long)*entry, iommu_virt_to_phys(*entry), addr);

	ret = amd_iommu_v1_map_pages(&iommu->viommu_pdom->iop.pgtbl.ops, addr,
				     iommu_virt_to_phys(*entry), PAGE_SIZE, (size / PAGE_SIZE),
				     IOMMU_PROT_IR | IOMMU_PROT_IW, GFP_KERNEL, NULL);
	if (ret)
		return ret;

	return amd_iommu_flush_private_vm_region(iommu, iommu->viommu_pdom, addr, size);
}

static void free_private_vm_region(struct amd_iommu *iommu, u64 **entry,
					u64 base, size_t size, u16 guestId)
{
	size_t ret;
	struct iommu_iotlb_gather gather;
	u64 addr = base + (guestId * size);

	pr_debug("entry=%#llx(%#llx), addr=%#llx\n",
		 (unsigned long  long)*entry,
		 iommu_virt_to_phys(*entry), addr);

	if (!iommu || !iommu->viommu_pdom)
		return;

	ret = amd_iommu_v1_unmap_pages(&iommu->viommu_pdom->iop.pgtbl.ops,
				       addr, PAGE_SIZE, (size / PAGE_SIZE), &gather);
	if (ret)
		amd_iommu_iotlb_sync(&iommu->viommu_pdom->domain, &gather);

	free_pages((unsigned long)*entry, get_order(size));
	*entry = NULL;
}

/*
 * Clear the DevID via VFCTRL registers
 * This function will be called during VM destroy via VFIO.
 */
static void clear_device_mapping(struct amd_iommu *iommu, u16 hDevId, u16 guestId,
				 u16 queueId, u16 gDevId)
{
	u64 val, tmp1, tmp2;
	u8 __iomem *vfctrl;

	/*
	 * Clear the DevID in VFCTRL registers
	 */
	tmp1 = gDevId;
	tmp1 = ((tmp1 & 0xFFFFULL) << 46);
	tmp2 = hDevId;
	tmp2 = ((tmp2 & 0xFFFFULL) << 14);
	val = tmp1 | tmp2 | 0x8000000000000001ULL;
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, guestId);
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL0_OFFSET);
}

/*
 * Clear the DomID via VFCTRL registers
 * This function will be called during VM destroy via VFIO.
 */
static void clear_domain_mapping(struct amd_iommu *iommu, u16 hDomId, u16 guestId, u16 gDomId)
{
	u64 val, tmp1, tmp2;
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, guestId);

	tmp1 = gDomId;
	tmp1 = ((tmp1 & 0xFFFFULL) << 46);
	tmp2 = hDomId;
	tmp2 = ((tmp2 & 0xFFFFULL) << 14);
	val = tmp1 | tmp2 | 0x8000000000000001UL;
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL1_OFFSET);
}

static void viommu_clear_mapping(struct amd_iommu *iommu, u16 guestId)
{
	int i;

	for (i = 0; i <= VIOMMU_MAX_GDEVID; i++)
		clear_device_mapping(iommu, 0, guestId, 0, i);

	for (i = 0; i <= VIOMMU_MAX_GDOMID; i++)
		clear_domain_mapping(iommu, 0, guestId, i);
}

static void viommu_clear_dirty_status_mask(struct amd_iommu *iommu, unsigned int gid)
{
	u32 offset, index, bits;
	u64 *group, val;

	if (gid >= 256 * 256)
		return;

	group = (u64 *)(iommu->cmdbuf_dirty_mask +
		(((gid & 0xFF) << 4) | (((gid >> 13) & 0x7) << 2)));
	offset = (gid >> 8) & 0x1F;
	index = offset >> 6;
	bits = offset & 0x3F;

	val = READ_ONCE(group[index]);
	val &= ~(1ULL << bits);
	WRITE_ONCE(group[index], val);
}

static void viommu_uninit_one(struct amd_iommu *iommu, struct amd_iommu_vminfo *vminfo)
{
	pr_debug("%s: gid=%u\n", __func__, vminfo->gid);

	free_private_vm_region(iommu, &vminfo->devid_table,
			       VIOMMU_DEVID_MAPPING_BASE,
			       VIOMMU_DEVID_MAPPING_ENTRY_SIZE,
			       vminfo->gid);
	free_private_vm_region(iommu, &vminfo->domid_table,
			       VIOMMU_DOMID_MAPPING_BASE,
			       VIOMMU_DOMID_MAPPING_ENTRY_SIZE,
			       vminfo->gid);

	viommu_clear_mapping(iommu, vminfo->gid);
	viommu_clear_dirty_status_mask(iommu, vminfo->gid);
}

/*
 * Allocate pages for the following regions:
 * - Guest MMIO
 * - DeviceID/DomainId Mapping Table
 * - Cmd buffer
 * - Event/PRR (A/B) logs
 */
int amd_viommu_init_one(struct amd_iommu *iommu, struct amd_iommu_vminfo *vminfo)
{
	int ret;

	ret = alloc_private_vm_region(iommu, &vminfo->devid_table,
				      VIOMMU_DEVID_MAPPING_BASE,
				      VIOMMU_DEVID_MAPPING_ENTRY_SIZE,
				      vminfo->gid);
	if (ret)
		goto err_out;

	ret = alloc_private_vm_region(iommu, &vminfo->domid_table,
				      VIOMMU_DOMID_MAPPING_BASE,
				      VIOMMU_DOMID_MAPPING_ENTRY_SIZE,
				      vminfo->gid);
	if (ret)
		goto err_out;

	viommu_clear_mapping(iommu, vminfo->gid);
	viommu_clear_dirty_status_mask(iommu, vminfo->gid);

	return 0;
err_out:
	viommu_uninit_one(iommu, vminfo);
	return -ENOMEM;
}

static void _amd_viommu_destroy(struct iommufd_viommu *viommu)
{
	struct amd_iommu_vminfo *vminfo = container_of(viommu, struct amd_iommu_vminfo, core);
	struct amd_iommu *iommu = get_amd_iommu_from_devid(vminfo->iommu_devid);

	pr_debug("DEBUG: %s: gid:%#x, iommu_devid=%#x\n", __func__,
		 vminfo->gid, vminfo->iommu_devid);

	if (!iommu) {
		pr_err("%s: Invalid iommu devid=%#x\n",
		       __func__, vminfo->iommu_devid);
		return;
	}

	viommu_uninit_one(iommu, vminfo);

	amd_iommu_vminfo_free(iommu, vminfo);
}

/*
 * Program the DomID via VFCTRL registers
 * This function will be called during VM init via VFIO.
 */
static void set_domain_mapping(struct amd_iommu *iommu, u16 guestId, u16 hDomId, u16 gDomId)
{
	u64 val, tmp1, tmp2;
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, guestId);

	pr_debug("%s: iommu_devid=%#x, gid=%#x, dom_id=%#x, gdom_id=%#x, val=%#llx\n",
		 __func__, pci_dev_id(iommu->dev), guestId, hDomId, gDomId, val);

	tmp1 = gDomId;
	tmp1 = ((tmp1 & 0xFFFFULL) << 46);
	tmp2 = hDomId;
	tmp2 = ((tmp2 & 0xFFFFULL) << 14);
	val = tmp1 | tmp2 | 0x8000000000000001UL;
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL1_OFFSET);
	wbinvd_on_all_cpus();
}

static void dump_domain_mapping(struct amd_iommu *iommu, u16 gid, u16 gdom_id)
{
	void *addr;
	u64 offset, val;
	struct amd_iommu_vminfo *vminfo;

	vminfo = amd_iommu_get_vminfo(gid);
	if (!vminfo)
		return;

	addr = vminfo->domid_table;
	offset = gdom_id << 3;
	val = *((u64 *)(addr + offset));

	pr_debug("%s: offset=%#llx(val=%#llx)\n", __func__,
		(unsigned long long)offset,
		(unsigned long long)val);
}

int amd_viommu_domain_id_update(struct amd_iommu *iommu, u16 gid,
				u16 hdom_id, u16 gdom_id,
				bool is_set)
{
	pr_debug("%s: guest_id %#x is %s domain id (host:%#x, guest:%#x)\n",
		__func__, gid,
		 is_set? "Mapping": "Unmapping",
		 hdom_id, gdom_id);

	if (is_set)
		set_domain_mapping(iommu, gid, hdom_id, gdom_id);
	else
		clear_domain_mapping(iommu, gid, hdom_id, gdom_id);

	dump_domain_mapping(iommu, gid, gdom_id);

	return 0;
}
EXPORT_SYMBOL(amd_viommu_domain_id_update);

static void set_dev_data_viommu(struct amd_iommu *iommu, u16 hDevId, u16 gid, u16 gDevId)
{
	struct iommu_dev_data *dev_data = search_dev_data(iommu, hDevId);

	if (!dev_data) {
		pr_err("%s: Failed to get host devid %#x\n", __func__, hDevId);
		return;
	}

	dev_data->vImuEn = true;
	dev_data->gid = gid;
	dev_data->gDevId = gDevId;
}

static void dump_device_mapping(struct amd_iommu *iommu, u16 guestId, u16 gdev_id)
{
	void *addr;
	u64 offset, val;
	struct amd_iommu_vminfo *vminfo;

	vminfo = amd_iommu_get_vminfo(guestId);
	if (!vminfo)
		return;

	addr = vminfo->devid_table;
	offset = gdev_id << 4;
	val = *((u64 *)(addr + offset));

	pr_debug("%s: guestId=%#x, gdev_id=%#x, base=%#llx, offset=%#llx(val=%#llx)\n", __func__,
		 guestId, gdev_id, (unsigned long long)iommu_virt_to_phys(vminfo->devid_table),
		 (unsigned long long)offset, (unsigned long long)val);
}

/*
 * Program the DevID via VFCTRL registers
 * This function will be called during VM init via VFIO.
 */
static void set_device_mapping(struct amd_iommu *iommu, u16 hDevId,
			       u16 guestId, u16 queueId, u16 gDevId)
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

	wbinvd_on_all_cpus();
}

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

int amd_viommu_set_ext_int_remap_entry(struct amd_iommu *iommu, enum ext_intremap_type type,
				       u64 val, u16 gid)
{
	struct ext_irte *eirte;
	struct amd_ir_data *ir_data;
	struct amd_iommu_pi_data pi;
	u64 pa;
	u32 ga_tag;
	u32 dest1 = (val >> 8) & 0xFFFFFF;
	u32 dest2 = (val >> 56) & 0xFF;
	u32 dest = (dest2 << 24) | dest1;
	u8 vector = (val >> 32) & 0xFF;
	u32 ext_id = EXT_IR_ID(type, gid);

	if (!svm_ops)
		return -EINVAL;

	ga_tag = svm_ops->get_ga_tag(gid, dest);
	pa = svm_ops->get_apic_backing_page(gid, dest);
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
	ir_data->ext_id = EXT_IR_ID(type, gid);
	ir_data->ga_root_ptr = (pa & 0xFFFFFFFFFFFFFULL) >> 12;
	ir_data->ga_tag = ga_tag;
	ir_data->ga_vector = vector;
	ir_data->entry = &eirte->entry;

	pi.ir_data = ir_data;
	pi.prev_ga_tag = 0;
	pi.ga_tag = ga_tag;
	pi.base = (pa & 0xFFFFFFFFFFFFFULL) >> 12;

	svm_ops->set_ext_ir_affinity(gid, dest, &pi);

	return 0;
}

/*
 * Called from drivers/iommu/iommufd/viommu.c: iommufd_vdevice_alloc_ioctl()
 */
static int _amd_viommu_vdevice_init(struct iommufd_vdevice *vdev)
{
	unsigned long flags;
	struct iommu_domain *dom;
	struct protection_domain *pdom;
	struct iommufd_viommu *viommu = vdev->viommu;
	struct amd_iommu_vminfo *vminfo = container_of(viommu, struct amd_iommu_vminfo, core);
	struct amd_iommu *iommu = get_amd_iommu_from_devid(vminfo->iommu_devid);
	struct pci_dev *pdev = to_pci_dev(vdev->dev);
	u16 hdev_id = pci_dev_id(pdev);
	u16 gdev_id = vdev->virt_id;
	struct iommu_dev_data *dev_data;

	if (!iommu || !pdev) {
		pr_err();
		return -EINVAL;
	}

	dev_data = dev_iommu_priv_get(&pdev->dev);
	if (!dev_data) {
		pr_err("%s: Device not found (devid=%#x)\n",
		       __func__, pci_dev_id(pdev));
		return -EINVAL;
	}

	dom = iommu_get_domain_for_dev(&pdev->dev);
	if (!dom) {
		pr_err("%s: Domain not found (devid=%#x)\n",
		       __func__, pci_dev_id(pdev));
		return -EINVAL;
	}

	pr_debug("%s: gid=%#x, iommu_devid=%#x, hdev_id=%#x, gdev_id=%#x\n",
		 __func__, vminfo->gid, vminfo->iommu_devid, hdev_id, gdev_id);

	/* TODO: Hardcode queueid to 0 for now */
	set_device_mapping(iommu, hdev_id, vminfo->gid, 0, gdev_id);

	set_dev_data_viommu(iommu, dev_data->devid, vminfo->gid, gdev_id);

	pdom = to_pdomain(dom);
	spin_lock_irqsave(&pdom->lock, flags);
	amd_iommu_domain_flush_all(pdom);
	spin_unlock_irqrestore(&pdom->lock, flags);

	return 0;
}

static size_t _amd_viommu_get_hw_queue_size(struct iommufd_viommu *viommu,
					    enum iommu_hw_queue_type queue_type)
{
	/* Currently do not support Eventlog B and PPRlog B */
	if ((queue_type != IOMMU_HW_QUEUE_TYPE_AMD_CMD) &&
	    (queue_type != IOMMU_HW_QUEUE_TYPE_AMD_EVT) &&
	    (queue_type != IOMMU_HW_QUEUE_TYPE_AMD_PPR))
		return 0;

	return HW_QUEUE_STRUCT_SIZE(struct amd_iommu_hw_queue, core);
}

static int _amd_viommu_hw_queue_init(struct iommufd_hw_queue *hw_queue, u32 index)
{
	int ret = 0;
	u64 val, tmp;
	u8 __iomem *vfctrl, *vf;
	struct iommufd_viommu *viommu = hw_queue->viommu;
	struct amd_iommu_vminfo *vminfo = container_of(viommu, struct amd_iommu_vminfo, core);
	int gid = vminfo->gid;
	struct amd_iommu *iommu = get_amd_iommu_from_devid(vminfo->iommu_devid);

	if (!iommu)
		return -ENODEV;

	vf = VIOMMU_VF_MMIO_BASE(iommu, gid);
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);

	switch (hw_queue->type) {
	case IOMMU_HW_QUEUE_TYPE_AMD_CMD:
	{
		val = readq(vfctrl + 0x20);
		val &= ~(0xFFFFFFFFFF00FULL);
		tmp = (hw_queue->length & 0xFULL);
		val = tmp | (hw_queue->base_addr & 0xFFFFFFFFFF000ULL);

		writeq(val, vfctrl + 0x20);
		break;
	}
	case IOMMU_HW_QUEUE_TYPE_AMD_EVT:
	{
		val = readq(vfctrl + 0x28);
		val &= ~(0xFFFFFFFFFF00FULL);
		tmp = (hw_queue->length & 0xFULL);
		val = tmp | (hw_queue->base_addr & 0xFFFFFFFFFF000ULL);
		writeq(val, vfctrl + 0x28);
		break;
	}
	case IOMMU_HW_QUEUE_TYPE_AMD_PPR:
	{
		val = readq(vfctrl + 0x30);
		val &= ~(0xFFFFFFFFFF00FULL);
		tmp = (hw_queue->length & 0xFULL);
		val = tmp | ((hw_queue->base_addr & 0xFFFFFFFFFF000ULL) << 4);
		writeq(val, vfctrl + 0x30);
		break;
	}
	default:
		pr_err("%s: Invalid type (%#x)\n", __func__, hw_queue->type);
		return -EINVAL;
	}

	pr_debug("%s: iommu_devid=%#x, gid=%#x, type=%#x, addr=%#llx, len=%#lx, val=%#llx\n",
		 __func__, iommu->devid, gid, hw_queue->type,
		 hw_queue->base_addr, hw_queue->length, val);

	return ret;
}

/*
 * See include/linux/iommufd.h
 * struct iommufd_viommu_ops - vIOMMU specific operations
 */
const struct iommufd_viommu_ops amd_viommu_ops = {
	.destroy = _amd_viommu_destroy,
	.vdevice_size = VDEVICE_STRUCT_SIZE(struct amd_iommu_vdevice, core),
	.vdevice_init = _amd_viommu_vdevice_init,
	.get_hw_queue_size = _amd_viommu_get_hw_queue_size,
	.hw_queue_init = _amd_viommu_hw_queue_init,
};
