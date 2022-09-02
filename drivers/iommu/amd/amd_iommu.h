/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2009-2010 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#ifndef AMD_IOMMU_H
#define AMD_IOMMU_H

#include <linux/iommu.h>
#include <uapi/linux/iommufd.h>

#include "amd_iommu_types.h"

void iommu_reset_vmmio(struct amd_iommu *iommu, u16 guestId);
irqreturn_t amd_iommu_int_thread(int irq, void *data);
irqreturn_t amd_iommu_int_thread_evtlog(int irq, void *data);
irqreturn_t amd_iommu_int_thread_pprlog(int irq, void *data);
irqreturn_t amd_iommu_int_thread_galog(int irq, void *data);
irqreturn_t amd_iommu_int_handler(int irq, void *data);
void amd_iommu_restart_log(struct amd_iommu *iommu, const char *evt_type,
			   u8 cntrl_intr, u8 cntrl_log,
			   u32 status_run_mask, u32 status_overflow_mask);
void amd_iommu_restart_event_logging(struct amd_iommu *iommu);
void amd_iommu_restart_ga_log(struct amd_iommu *iommu);
void amd_iommu_restart_ppr_log(struct amd_iommu *iommu);
void amd_iommu_set_rlookup_table(struct amd_iommu *iommu, u16 devid);
void iommu_feature_enable(struct amd_iommu *iommu, u8 bit);
bool iommu_feature_enable_and_check(struct amd_iommu *iommu, u8 bit);
void *__init iommu_alloc_4k_pages(struct amd_iommu *iommu,
				  gfp_t gfp, size_t size);
int amd_iommu_pdom_id_alloc(void);
int amd_iommu_pdev_enable_cap_ats(struct pci_dev *pdev);
bool amd_iommu_hd_support(struct amd_iommu *iommu);
u8 __iomem * __init iommu_map_mmio_space(u64 address, u64 end);
int iommu_flush_dte(struct amd_iommu *iommu, u16 devid);
int amd_iommu_v1_map_pages(struct io_pgtable_ops *ops, unsigned long iova,
			   phys_addr_t paddr, size_t pgsize, size_t pgcount,
			   int prot, gfp_t gfp, size_t *mapped);
unsigned long amd_iommu_v1_unmap_pages(struct io_pgtable_ops *ops,
				       unsigned long iova,
				       size_t pgsize, size_t pgcount,
				       struct iommu_iotlb_gather *gather);

#ifdef CONFIG_AMD_IOMMU_DEBUGFS
void amd_iommu_debugfs_setup(struct amd_iommu *iommu);
#else
static inline void amd_iommu_debugfs_setup(struct amd_iommu *iommu) {}
#endif

extern bool amd_iommu_viommu;

/* Needed for interrupt remapping */
int amd_iommu_prepare(void);
int amd_iommu_enable(void);
void amd_iommu_disable(void);
int amd_iommu_reenable(int mode);
int amd_iommu_enable_faulting(unsigned int cpu);
extern int amd_iommu_guest_ir;
extern enum protection_domain_mode amd_iommu_pgtable;
extern int amd_iommu_gpt_level;
extern unsigned long amd_iommu_pgsize_bitmap;

/* Protection domain ops */
void amd_iommu_init_identity_domain(void);
struct protection_domain *protection_domain_alloc(void);
struct iommu_domain *amd_iommu_domain_alloc_sva(struct device *dev,
						struct mm_struct *mm);
void amd_iommu_domain_free(struct iommu_domain *dom);
int iommu_sva_set_dev_pasid(struct iommu_domain *domain,
			    struct device *dev, ioasid_t pasid,
			    struct iommu_domain *old);
void amd_iommu_remove_dev_pasid(struct device *dev, ioasid_t pasid,
				struct iommu_domain *domain);

/* SVA/PASID */
bool amd_iommu_pasid_supported(void);

/* IOPF */
int amd_iommu_iopf_init(struct amd_iommu *iommu);
void amd_iommu_iopf_uninit(struct amd_iommu *iommu);
void amd_iommu_page_response(struct device *dev, struct iopf_fault *evt,
			     struct iommu_page_response *resp);
int amd_iommu_iopf_add_device(struct amd_iommu *iommu,
			      struct iommu_dev_data *dev_data);
void amd_iommu_iopf_remove_device(struct amd_iommu *iommu,
				  struct iommu_dev_data *dev_data);

/* GCR3 setup */
int amd_iommu_set_gcr3(struct iommu_dev_data *dev_data,
		       ioasid_t pasid, unsigned long gcr3);
int amd_iommu_clear_gcr3(struct iommu_dev_data *dev_data, ioasid_t pasid);

/* PPR */
int __init amd_iommu_alloc_ppr_log(struct amd_iommu *iommu);
void __init amd_iommu_free_ppr_log(struct amd_iommu *iommu);
void amd_iommu_enable_ppr_log(struct amd_iommu *iommu);
void amd_iommu_poll_ppr_log(struct amd_iommu *iommu);
int amd_iommu_complete_ppr(struct device *dev, u32 pasid, int status, int tag);

/*
 * This function flushes all internal caches of
 * the IOMMU used by this driver.
 */
int __amd_iommu_attach_device(struct device *dev, struct protection_domain *domain);
void amd_iommu_detach_device(struct device *dev);
void amd_iommu_flush_all_caches(struct amd_iommu *iommu);
void amd_iommu_update_and_flush_device_table(struct protection_domain *domain);
void amd_iommu_dev_update_dte(struct iommu_dev_data *dev_data, bool set);
void amd_iommu_domain_flush_all(struct protection_domain *domain);
void amd_iommu_domain_flush_pages(struct protection_domain *domain,
				  u64 address, size_t size);
void amd_iommu_dev_flush_pasid_pages(struct iommu_dev_data *dev_data,
				     ioasid_t pasid, u64 address, size_t size);

void amd_iommu_iotlb_sync(struct iommu_domain *domain,
			  struct iommu_iotlb_gather *gather);
int amd_iommu_flush_private_vm_region(struct amd_iommu *iommu, struct protection_domain *pdom,
				      u64 address, size_t size);

#ifdef CONFIG_IRQ_REMAP
int amd_iommu_create_irq_domain(struct amd_iommu *iommu);
#else
static inline int amd_iommu_create_irq_domain(struct amd_iommu *iommu)
{
	return 0;
}
#endif

static inline bool is_rd890_iommu(struct pci_dev *pdev)
{
	return (pdev->vendor == PCI_VENDOR_ID_ATI) &&
	       (pdev->device == PCI_DEVICE_ID_RD890_IOMMU);
}

static inline bool check_feature(u64 mask)
{
	return (amd_iommu_efr & mask);
}

static inline bool check_feature2(u64 mask)
{
	return (amd_iommu_efr2 & mask);
}

static inline bool amd_iommu_v2_pgtbl_supported(void)
{
	return (check_feature(FEATURE_GIOSUP) && check_feature(FEATURE_GT));
}

static inline bool amd_iommu_gt_ppr_supported(void)
{
	return (amd_iommu_v2_pgtbl_supported() &&
		check_feature(FEATURE_PPR) &&
		check_feature(FEATURE_EPHSUP));
}

static inline u64 iommu_virt_to_phys(void *vaddr)
{
	return (u64)__sme_set(virt_to_phys(vaddr));
}

static inline void *iommu_phys_to_virt(unsigned long paddr)
{
	return phys_to_virt(__sme_clr(paddr));
}

static inline int get_pci_sbdf_id(struct pci_dev *pdev)
{
	int seg = pci_domain_nr(pdev->bus);
	u16 devid = pci_dev_id(pdev);

	return PCI_SEG_DEVID_TO_SBDF(seg, devid);
}

bool amd_iommu_ht_range_ignore(void);

/*
 * This must be called after device probe completes. During probe
 * use rlookup_amd_iommu() get the iommu.
 */
static inline struct amd_iommu *get_amd_iommu_from_dev(struct device *dev)
{
	return iommu_get_iommu_dev(dev, struct amd_iommu, iommu);
}

/* This must be called after device probe completes. */
static inline struct amd_iommu *get_amd_iommu_from_dev_data(struct iommu_dev_data *dev_data)
{
	return iommu_get_iommu_dev(dev_data->dev, struct amd_iommu, iommu);
}

static inline struct protection_domain *to_pdomain(struct iommu_domain *dom)
{
	return container_of(dom, struct protection_domain, domain);
}

bool translation_pre_enabled(struct amd_iommu *iommu);
int __init add_special_device(u8 type, u8 id, u32 *devid, bool cmd_line);

#ifdef CONFIG_DMI
void amd_iommu_apply_ivrs_quirks(void);
#else
static inline void amd_iommu_apply_ivrs_quirks(void) { }
#endif
struct dev_table_entry *amd_iommu_get_ivhd_dte_flags(u16 segid, u16 devid);

void amd_iommu_domain_set_pgtable(struct protection_domain *domain,
				  u64 *root, int mode);
struct dev_table_entry *get_dev_table(struct amd_iommu *iommu);
struct iommu_dev_data *search_dev_data(struct amd_iommu *iommu, u16 devid);

int iommu_completion_wait(struct amd_iommu *iommu);

/* NESTED */
struct iommu_domain *
amd_iommu_domain_alloc_nested(struct device *dev, struct iommu_domain *parent,
			      u32 flags, const struct iommu_user_data *user_data);

/* AMD IOMMU GID */
int amd_iommu_vminfo_alloc(struct amd_iommu *iommu, struct amd_iommu_vminfo *vminfo);
void amd_iommu_vminfo_free(struct amd_iommu *iommu, struct amd_iommu_vminfo *vminfo);
struct amd_iommu_vminfo *amd_iommu_get_vminfo(int gid);

static inline struct amd_iommu *get_amd_iommu_from_devid(u16 devid)
{
	struct amd_iommu *iommu;

	for_each_iommu(iommu)
		if (iommu->devid == devid)
			return iommu;
	return NULL;
}

int amd_iommu_viommu_init(struct iommufd_viommu *viommu, struct iommu_domain *parent,
			  const struct iommu_user_data *user_data);

/* VIOMMU */
int amd_viommu_domain_id_update(struct amd_iommu *iommu, u16 gid,
				u16 hdom_id, u16 gdom_id,
				bool is_set);
#endif /* AMD_IOMMU_H */
