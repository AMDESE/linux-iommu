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

#ifdef CONFIG_AMD_IOMMU

struct task_struct;
struct pci_dev;

extern void amd_iommu_detect(void);

#else /* CONFIG_AMD_IOMMU */

static inline void amd_iommu_detect(void) { }

#endif /* CONFIG_AMD_IOMMU */

#if defined(CONFIG_AMD_IOMMU) && defined(CONFIG_IRQ_REMAP)

/* IOMMU AVIC Function */
extern int amd_iommu_register_svm_ops(const struct amd_iommu_svm_ops *ops);

extern int amd_iommu_update_ga(void *data, int cpu, bool ga_log_intr);
extern int amd_iommu_activate_guest_mode(void *data, int cpu, bool ga_log_intr);
extern int amd_iommu_deactivate_guest_mode(void *data);

#else /* defined(CONFIG_AMD_IOMMU) && defined(CONFIG_IRQ_REMAP) */

static int amd_iommu_register_ops(struct amd_iommu_ops *ops);
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
#else
static inline int amd_iommu_snp_disable(void) { return 0; }
static inline bool amd_iommu_sev_tio_supported(void) { return false; }
#endif

#endif /* _ASM_X86_AMD_IOMMU_H */
