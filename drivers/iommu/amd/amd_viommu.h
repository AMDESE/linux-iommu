/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef AMD_VIOMMU_H
#define AMD_VIOMMU_H

struct amd_iommu;

/* 16-bit guest DevID index; not VIOMMU_MAX_GID. */
#define VIOMMU_MAX_GDEVID	0xFFFF

#if IS_ENABLED(CONFIG_AMD_IOMMU_IOMMUFD)

int amd_viommu_init(struct amd_iommu *iommu);

void __init amd_viommu_uninit(struct amd_iommu *iommu);

u64 amd_viommu_get_vfmmio_addr(struct amd_iommu *iommu, u16 gid);

int amd_viommu_init_one(struct amd_iommu *iommu, struct amd_iommu_viommu *viommu);

void amd_viommu_uninit_one(struct amd_iommu *iommu, struct amd_iommu_viommu *viommu);

void amd_viommu_set_device_mapping(struct amd_iommu_viommu *aviommu,
				   u16 hdev_id, u16 gdev_id);
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

static inline void amd_viommu_uninit(struct amd_iommu *iommu)
{
}

static inline u64 amd_viommu_get_vfmmio_addr(struct amd_iommu *iommu, u16 gid)
{
	return 0;
}

static inline void amd_viommu_set_device_mapping(struct amd_iommu_viommu *aviommu,
						 u16 hdev_id, u16 gdev_id)
{
}

#endif /* CONFIG_AMD_IOMMU_IOMMUFD */

#endif /* AMD_VIOMMU_H */
