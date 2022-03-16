/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef AMD_VIOMMU_H
#define AMD_VIOMMU_H

struct amd_iommu;

#if IS_ENABLED(CONFIG_AMD_IOMMU_IOMMUFD)

int amd_viommu_init(struct amd_iommu *iommu);

#else

/*
 * CONFIG_AMD_IOMMU_IOMMUFD is off: host vIOMMU is not compiled in.
 * Succeed as a no-op so iommu_init_pci() does not pr_err on
 * EFR[VIOMMUSup] hardware.
 */
static inline int amd_viommu_init(struct amd_iommu *iommu)
{
	return 0;
}

#endif /* CONFIG_AMD_IOMMU_IOMMUFD */

#endif /* AMD_VIOMMU_H */
