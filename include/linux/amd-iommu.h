/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2007-2010 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <joerg.roedel@amd.com>
 *         Leo Duran <leo.duran@amd.com>
 */

#ifndef _ASM_X86_AMD_IOMMU_H
#define _ASM_X86_AMD_IOMMU_H

#include <linux/types.h>
#include <linux/kvm_host.h>

#include <asm/irq_remapping.h>

struct amd_iommu;

struct amd_iommu_svm_ops {
	int (*ga_log_notifier)(u32 ga_tag);
	u32 (*get_ga_tag)(struct kvm *kvm, u32 vcpu_id);
	u64 (*get_apic_backing_page)(struct kvm *kvm, u32 vcpu_id);
	int (*set_ext_ir_affinity)(struct kvm *kvm, u32 vcpu_id, struct amd_iommu_pi_data *pi);
};

/* TODO: Replace it w/ VIOMMU_PRIV_SUBREGION_CNT? also rename backing_page w/ viommu_priv_region */
#define VIOMMU_BACKING_PAGE_COUNT	(4)
struct amd_sviommu {
	u16 segid;
	u16 devid;
	void *backing_page[VIOMMU_BACKING_PAGE_COUNT]; /* 4 2MB pages */
	u32 backing_page_size; /* 2MB */
};

struct amd_sviommu_guest {
	u16 segid;
	u16 devid;
	s32 kvmfd;
	void *kvm;

	u16 guest_viommu_devid;
	u16 host_viommu_devid;
	u16 host_domid;
	void *devid_map;
	u32 devid_map_size;
	void *domid_map;
	u32 domid_map_size;
	u64 vfmmio_addr;
};

struct amd_iommu_ccp_ops {
	int (*sev_tio_viommu_init)(struct amd_sviommu *sv);
	int (*sev_tio_viommu_guest_init)(struct amd_sviommu_guest *g);
	int (*sev_tio_viommu_guest_shutdown)(struct amd_sviommu_guest *g);
};

struct amd_sviommu_guest_ops {
	int (*setup_cmdbuf)(u16 devid, void *data);
	int (*setup_evtlog)(u16 devid, void *data);
	int (*setup_pprlog)(u16 devid, void *data);
};

#ifdef CONFIG_AMD_IOMMU

struct task_struct;
struct pci_dev;

extern void amd_iommu_detect(void);
int amd_iommu_get_dev_domid(struct pci_dev *pdev);
void amd_iommu_clear_dev_domid(struct pci_dev *pdev);
void amd_iommu_register_ccp_ops(const struct amd_iommu_ccp_ops *ops);
int amd_iommu_sviommu_init(void);
bool amd_iommu_sviommu_guest(void);
/* SNP Guest SVIOMMU Function */
int amd_sviommu_register_guest_ops(const struct amd_sviommu_guest_ops *ops);

#else /* CONFIG_AMD_IOMMU */

static inline void amd_iommu_detect(void) { }
static inline u16 amd_iommu_get_dev_domid(struct pci_dev *pdev) { return -EOPNOTSUPP; }
static inline void amd_iommu_clear_dev_domid(struct pci_dev *pdev) {}
static inline void amd_iommu_register_ccp_ops(const struct amd_iommu_ccp_ops *ops) {}
static inline int amd_iommu_sviommu_init(void) { return -ENODEV; }
static inline bool amd_iommu_sviommu_guest(void) { return false; }
static inline int amd_sviommu_register_guest_ops(const struct amd_sviommu_guest_ops *ops)
{
	return -ENODEV;
}

#endif /* CONFIG_AMD_IOMMU */

#if defined(CONFIG_AMD_IOMMU) && defined(CONFIG_IRQ_REMAP)

/* IOMMU AVIC Function */
extern int amd_iommu_register_svm_ops(const struct amd_iommu_svm_ops *ops);

extern int amd_iommu_update_ga(void *data, int cpu, bool ga_log_intr);
extern int amd_iommu_activate_guest_mode(void *data, int cpu, bool ga_log_intr);
extern int amd_iommu_deactivate_guest_mode(void *data);

#else /* defined(CONFIG_AMD_IOMMU) && defined(CONFIG_IRQ_REMAP) */

static inline int amd_iommu_register_svm_ops(const struct amd_iommu_svm_ops *ops)
{
	return 0;
}

static inline int amd_iommu_update_ga(void *data, int cpu, bool ga_log_intr)
{
	return 0;
}

static inline int amd_iommu_activate_guest_mode(void *data, int cpu, bool ga_log_intr)
{
	return 0;
}

static inline int amd_iommu_deactivate_guest_mode(void *data)
{
	return 0;
}
#endif /* defined(CONFIG_AMD_IOMMU) && defined(CONFIG_IRQ_REMAP) */

int amd_iommu_get_num_iommus(void);
bool amd_iommu_pc_supported(void);
u8 amd_iommu_pc_get_max_banks(unsigned int idx);
u8 amd_iommu_pc_get_max_counters(unsigned int idx);
int amd_iommu_pc_set_reg(struct amd_iommu *iommu, u8 bank, u8 cntr, u8 fxn,
		u64 *value);
int amd_iommu_pc_get_reg(struct amd_iommu *iommu, u8 bank, u8 cntr, u8 fxn,
		u64 *value);
struct amd_iommu *get_amd_iommu(unsigned int idx);

#ifdef CONFIG_KVM_AMD_SEV
int amd_iommu_snp_disable(void);
extern bool amd_iommu_sev_tio_supported(void);
bool amd_iommu_sviommu_supported(void);
#else
static inline int amd_iommu_snp_disable(void) { return 0; }
static inline bool amd_iommu_sev_tio_supported(void) { return false; }
static inline bool amd_iommu_sviommu_supported(void) { return false; }
#endif

int amd_iommu_tmpm_enable(void);
void amd_iommu_tmpm_disable(void);

#endif /* _ASM_X86_AMD_IOMMU_H */
