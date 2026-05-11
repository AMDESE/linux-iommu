/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef AMD_VIOMMU_H
#define AMD_VIOMMU_H

#include <linux/amd-iommu.h>

/* Extended Interrupt Remapping */
enum ext_intremap_type {
	EXT_INTREMAP_EVENT = 0,
	EXT_INTREMAP_PPR,
};

#if IS_ENABLED(CONFIG_AMD_IOMMU_IOMMUFD)

int amd_viommu_init(struct amd_iommu *iommu);

u64 amd_viommu_get_vfmmio_addr(struct amd_iommu *iommu, u16 gid);

int amd_viommu_init_one(struct amd_iommu *iommu, struct amd_iommu_viommu *viommu);

void amd_viommu_uninit_one(struct amd_iommu *iommu, struct amd_iommu_viommu *viommu);

int amd_viommu_domain_id_update(struct amd_iommu *iommu, u16 gid,
				u16 hdom_id, u16 gdom_id);

void amd_viommu_set_device_mapping(struct amd_iommu *iommu, u16 hDevId,
				   u16 guestId, u16 gDevId);

int amd_viommu_guest_mmio_write(struct iommufd_viommu *viommu, u16 offset, u64 value);

int amd_viommu_guest_mmio_read(struct iommufd_viommu *viommu, u16 offset, u64 *value);

int amd_viommu_set_ext_int_remap_entry(struct iommufd_viommu *viommu,
				       enum ext_intremap_type type, u64 val);

struct ext_irte * amd_viommu_get_ext_irte(struct amd_iommu *iommu, u32 ext_id);

int amd_sviommu_setup_cmd_buf(struct amd_iommu *iommu, bool enable);
int amd_sviommu_setup_evt_log(struct amd_iommu *iommu, bool enable);
int amd_sviommu_setup_ppr_log(struct amd_iommu *iommu, bool enable);
int amd_sviommu_setup_mmio(struct amd_iommu *iommu);
int amd_sviommu_setup_trans_sdte(struct amd_iommu *iommu, u64 vtom, bool enable);
int amd_sviommu_mapping_update(struct amd_iommu *iommu, u16 domid,
			       struct iommu_dev_data *dev_data, bool set);
int amd_sviommu_sdte_update(u16 iommu_devid,
			    struct iommu_dev_data *dev_data, struct sdte *s);

#else

static inline int amd_viommu_init(struct amd_iommu *iommu)
{
	return 0;
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

static inline int amd_viommu_guest_mmio_write(struct iommufd_viommu *viommu, u16 offset, u64 value)
{
	return -EOPNOTSUPP;
}

static inline int amd_viommu_guest_mmio_read(struct iommufd_viommu *viommu, u16 offset, u64 *value)
{
	return -EOPNOTSUPP;
}

static inline struct ext_irte *
amd_viommu_get_ext_irte(struct amd_iommu *iommu,u32 ext_id)
{
	return NULL;
}

static inline int amd_sviommu_setup_cmd_buf(struct amd_iommu *iommu, bool enable)
{
	return -EOPNOTSUPP;
}

static inline int amd_sviommu_setup_evt_log(struct amd_iommu *iommu, bool enable)
{
	return -EOPNOTSUPP;
}

static inline int amd_sviommu_setup_ppr_log(struct amd_iommu *iommu, bool enable)
{
	return -EOPNOTSUPP;
}

static inline int amd_sviommu_setup_mmio(struct amd_iommu *iommu)
{
	return -EOPNOTSUPP;
}

static inline int amd_sviommu_setup_trans_sdte(struct amd_iommu *iommu, u64 vtom, bool enable)
{
	return -EOPNOTSUPP;
}

static inline int amd_sviommu_mapping_update(struct amd_iommu *iommu, u16 domid,
					     struct iommu_dev_data *dev_data, bool set)
{
	return -EOPNOTSUPP;
}

static inline int amd_sviommu_sdte_update(u16 iommu_devid,
					  struct iommu_dev_data *dev_data, struct sdte *s)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_AMD_IOMMU_IOMMUFD */

#endif /* AMD_VIOMMU_H */
