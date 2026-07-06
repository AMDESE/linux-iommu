/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef AMD_VIOMMU_H
#define AMD_VIOMMU_H

struct kvm;

/* Extended Interrupt Remapping */
enum ext_intremap_type {
	EXT_INTREMAP_EVENT = 0,
	EXT_INTREMAP_PPR,
};

#if IS_ENABLED(CONFIG_AMD_IOMMU_IOMMUFD)

int amd_viommu_init(struct amd_iommu *iommu);

void __init amd_viommu_uninit(struct amd_iommu *iommu);

u64 amd_viommu_get_vfmmio_addr(struct amd_iommu *iommu, u16 gid);

int amd_viommu_init_one(struct amd_iommu *iommu, struct amd_iommu_viommu *viommu);

void amd_viommu_uninit_one(struct amd_iommu *iommu, struct amd_iommu_viommu *viommu);

int amd_viommu_domain_id_update(struct amd_iommu *iommu, u16 gid,
				u16 hdom_id, u16 gdom_id);

void amd_viommu_set_device_mapping(struct amd_iommu *iommu, u16 hDevId,
				   u16 guestId, u16 gDevId);

struct iommufd_hw_queue;

void amd_viommu_set_cmdbuf_flags(struct iommufd_hw_queue *hw_queue);
void amd_viommu_set_evtbuf_flags(struct iommufd_hw_queue *hw_queue);
void amd_viommu_set_pprbuf_flags(struct iommufd_hw_queue *hw_queue);

int amd_viommu_set_ext_int_remap_entry(struct iommufd_viommu *viommu,
				       struct kvm *kvm,
				       enum ext_intremap_type type, u32 vcpu_id,
				       u8 vector);

#else

static inline int amd_viommu_init(struct amd_iommu *iommu)
{
	return -EOPNOTSUPP;
}

static inline void amd_viommu_uninit(struct amd_iommu *iommu)
{
}

static inline u64 amd_viommu_get_vfmmio_addr(struct amd_iommu *iommu, u16 gid)
{
	return 0;
}

static inline int amd_viommu_init_one(struct amd_iommu *iommu, struct amd_iommu_viommu *viommu)
{
	return -EOPNOTSUPP;
}

static inline void amd_viommu_uninit_one(struct amd_iommu *iommu, struct amd_iommu_viommu *viommu)
{
}

static inline void amd_viommu_set_device_mapping(struct amd_iommu *iommu, u16 hDevId,
						 u16 guestId, u16 gDevId)
{
}

static inline void amd_viommu_set_cmdbuf_flags(struct iommufd_hw_queue *hw_queue)
{
}

static inline void amd_viommu_set_evtbuf_flags(struct iommufd_hw_queue *hw_queue)
{
}

static inline void amd_viommu_set_pprbuf_flags(struct iommufd_hw_queue *hw_queue)
{
}

#endif /* CONFIG_AMD_IOMMU_IOMMUFD */

#endif /* AMD_VIOMMU_H */
