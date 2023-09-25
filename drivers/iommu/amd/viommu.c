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

static int viommu_private_space_init(struct amd_iommu *iommu)
{
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
		goto err_out;
	}

	pdom = to_pdomain(dom);
	iommu->viommu_pdom = pdom;

	pt_iommu_amdv1_hw_info(&pdom->amdv1, &pt_info);
	pr_debug("%s: devid=%#x, pte_root=%#llx\n",
		 __func__, iommu->devid,
		 (unsigned long long)pt_info.host_pt_root);

	return 0;
err_out:
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

	ret = viommu_private_space_init(iommu);
	if (ret)
		return ret;

	return 0;
}
