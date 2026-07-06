/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef AMD_VIOMMU_H
#define AMD_VIOMMU_H

struct amd_iommu;

/* 16-bit guest DevID index; not VIOMMU_MAX_GID. */
#define VIOMMU_MAX_GDEVID	0xFFFF

struct kvm;
struct amd_iommu_svm_ops;

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

void amd_viommu_domain_id_update(struct amd_iommu_viommu *aviommu,
				 u16 hdom_id, u16 gdom_id);
void amd_viommu_domain_id_update_locked(struct amd_iommu_viommu *aviommu,
					u16 hdom_id, u16 gdom_id);

void amd_viommu_set_device_mapping(struct amd_iommu_viommu *aviommu,
				   u16 hdev_id, u16 gdev_id);

void amd_iommu_pci_seg_trans_devid_init(struct amd_iommu_pci_seg *pci_seg);
void amd_iommu_pci_seg_trans_devid_fini(struct amd_iommu_pci_seg *pci_seg);
int amd_iommu_trans_devid_reserve(struct amd_iommu_pci_seg *pci_seg, u16 id);
int amd_iommu_trans_devid_reserve_pci_aliases(struct amd_iommu *iommu,
					      struct device *dev);
int amd_iommu_trans_devid_alloc(struct amd_iommu_pci_seg *pci_seg,
				struct amd_iommu_viommu *aviommu);
void amd_iommu_trans_devid_free(struct amd_iommu_pci_seg *pci_seg, u16 id,
				struct amd_iommu_viommu *aviommu);

struct iommufd_hw_queue;

#define AMD_HW_QUEUE_FLAGS_CMD						\
	(IOMMU_HW_QUEUE_FLAG_AMD_CMDBUF_EN |				\
	 IOMMU_HW_QUEUE_FLAG_AMD_COMWAIT_EN)

#define AMD_HW_QUEUE_FLAGS_EVT						\
	(IOMMU_HW_QUEUE_FLAG_AMD_EVT_LOG_EN |				\
	 IOMMU_HW_QUEUE_FLAG_AMD_EVT_INT_EN)

#define AMD_HW_QUEUE_FLAGS_PPR						\
	(IOMMU_HW_QUEUE_FLAG_AMD_PPRLOG_EN |				\
	 IOMMU_HW_QUEUE_FLAG_AMD_PPRINT_EN |				\
	 IOMMU_HW_QUEUE_FLAG_AMD_PPR_EN |				\
	 IOMMU_HW_QUEUE_FLAG_AMD_PPR_AUTO_RSP_EN |			\
	 IOMMU_HW_QUEUE_FLAG_AMD_BLKSTOPMRK_EN |			\
	 IOMMU_HW_QUEUE_FLAG_AMD_PPR_AUTO_RSP_AON)

int amd_viommu_set_cmdbuf_flags(struct iommufd_hw_queue *hw_queue);
int amd_viommu_set_evtbuf_flags(struct iommufd_hw_queue *hw_queue);
int amd_viommu_set_pprbuf_flags(struct iommufd_hw_queue *hw_queue);

int amd_viommu_set_ext_int_remap_entry(struct iommufd_viommu *viommu,
				       const struct amd_iommu_svm_ops *ops,
				       struct kvm *kvm,
				       enum ext_intremap_type type, u32 vcpu_id,
				       u8 vector);
/* Caller must hold aviommu->vfctrl_lock. */
bool amd_viommu_attach_ext_ir_kvm(struct amd_iommu_viommu *aviommu,
				  struct kvm *kvm,
				  void (*put_kvm)(struct kvm *kvm));
void amd_viommu_detach_ext_ir_kvm(struct amd_iommu_viommu *aviommu);
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

static inline void amd_viommu_domain_id_update(struct amd_iommu_viommu *aviommu,
					       u16 hdom_id, u16 gdom_id)
{
}

static inline void amd_viommu_domain_id_update_locked(struct amd_iommu_viommu *aviommu,
						      u16 hdom_id, u16 gdom_id)
{
}

static inline void
amd_iommu_pci_seg_trans_devid_init(struct amd_iommu_pci_seg *pci_seg)
{
}

static inline void
amd_iommu_pci_seg_trans_devid_fini(struct amd_iommu_pci_seg *pci_seg)
{
}

static inline int amd_viommu_set_cmdbuf_flags(struct iommufd_hw_queue *hw_queue)
{
	return 0;
}

static inline int amd_viommu_set_evtbuf_flags(struct iommufd_hw_queue *hw_queue)
{
	return 0;
}

static inline int amd_viommu_set_pprbuf_flags(struct iommufd_hw_queue *hw_queue)
{
	return 0;
}

#endif /* CONFIG_AMD_IOMMU_IOMMUFD */

#endif /* AMD_VIOMMU_H */
