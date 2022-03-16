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

int __init amd_viommu_init(struct amd_iommu *iommu)
{
	iommu->flags |= AMD_IOMMU_FLAG_VIOMMU_EN;
	return 0;
}
