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

void __init amd_viommu_uninit(struct amd_iommu *iommu)
{
	iommu->flags &= ~AMD_IOMMU_FLAG_VIOMMU_EN;
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

	iommu->flags |= AMD_IOMMU_FLAG_VIOMMU_EN;
	return 0;
}
