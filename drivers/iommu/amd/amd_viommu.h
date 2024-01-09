/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef AMD_VIOMMU_H
#define AMD_VIOMMU_H

#if IS_ENABLED(CONFIG_AMD_IOMMU_IOMMUFD)

int amd_viommu_init(struct amd_iommu *iommu);

int amd_viommu_domain_id_update(struct amd_iommu *iommu, u16 gid,
				u16 hdom_id, u16 gdom_id);

int amd_viommu_init_one(struct amd_iommu *iommu, struct amd_iommu_viommu *viommu);

void amd_viommu_uninit_one(struct amd_iommu *iommu, struct amd_iommu_viommu *viommu);

#else

static inline int amd_viommu_init(struct amd_iommu *iommu)
{
	return 0;
}

static inline int amd_viommu_init_one(struct amd_iommu *iommu, struct amd_iommu_viommu *viommu)
{
	return -EOPNOTSUPP;
}

static inline void amd_viommu_uninit_one(struct amd_iommu *iommu, struct amd_iommu_viommu *viommu)
{
	return;
}

#endif /* CONFIG_AMD_IOMMU_IOMMUFD */

#endif /* AMD_VIOMMU_H */
