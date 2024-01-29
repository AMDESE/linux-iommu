// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 * vIOMMU iommufd: translate DTE and VFCTRL translate-device-id programming.
 */

#define pr_fmt(fmt)	"AMD-Vi: " fmt

#include <linux/generic_pt/iommu.h>
#include <linux/io.h>
#include <linux/iommu.h>

#include "amd_iommu.h"
#include "amd_iommu_types.h"
#include "amd_viommu.h"

void amd_iommu_update_vfctrl_mmio_translate_devid(struct amd_iommu *iommu,
						  u16 gid, u32 devid)
{
	writeq((devid & 0xFFFFULL) << 16,
	       VIOMMU_VFCTRL_MMIO_BASE(iommu, gid) +
	       VIOMMU_VFCTRL_GUEST_MISC_CONTROL_OFFSET);
}

void amd_iommu_set_translate_dte(struct amd_iommu *iommu, u16 gid,
				 struct protection_domain *pdom,
				 u32 devid)
{
	u64 tmp0 = 0ULL, tmp1 = 0ULL;
	struct pt_iommu_amdv1_hw_info pt_info;
	struct dev_table_entry *dev_table = get_dev_table(iommu);

	pt_iommu_amdv1_hw_info(&pdom->amdv1, &pt_info);

	pr_debug("%s: gid=%#x, iommu_devid=%#x, devid=%#x, host_pt_root=%#llx, mode=%#x\n",
		 __func__, gid, iommu->devid, devid, pt_info.host_pt_root, pt_info.mode);

	tmp0 |= FIELD_PREP(DTE_HOST_TRP, pt_info.host_pt_root >> 12);
	tmp0 |= FIELD_PREP(DTE_MODE_MASK, pt_info.mode);
	tmp0 |= (DTE_FLAG_IR | DTE_FLAG_IW | DTE_FLAG_TV | DTE_FLAG_V);
	tmp1 |= FIELD_PREP(DTE_DOMID_MASK, pdom->id);

	dev_table[devid].data[0] = tmp0;
	dev_table[devid].data[1] = tmp1;

	iommu_flush_dte(iommu, devid);
	amd_iommu_completion_wait(iommu);
}

void amd_iommu_clear_translate_dte(struct amd_iommu *iommu, u16 gid, u32 devid)
{
	struct dev_table_entry *dev_table = get_dev_table(iommu);

	pr_debug("%s: gid=%#x, iommu_devid=%#x, devid=%#x\n",
		 __func__, gid, iommu->devid, devid);

	dev_table[devid].data[0] = 0ULL;
	dev_table[devid].data[1] = 0ULL;

	iommu_flush_dte(iommu, devid);
	amd_iommu_completion_wait(iommu);
}
