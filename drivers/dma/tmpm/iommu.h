/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD TMPM interface driver
 *
 * Copyright (C) 2017-2022 Advanced Micro Devices, Inc.
 */

#ifndef _TMPM_IOMMU_H_
#define _TMPM_IOMMU_H_

int tmpm_iommu_enable(void);
void tmpm_iommu_disable(void);
int tmpm_iommu_map(unsigned long iova, phys_addr_t paddr,
		size_t size, int prot, gfp_t gfp);
size_t tmpm_iommu_unmap(unsigned long iova, size_t size);

struct iommu_domain *tmpm_iommu_get_domain(struct device *dev);
void tmpm_iommu_put_all_domain(void);
int tmpm_iommu_domain_attach_device(struct device *dev);
void tmpm_iommu_detach_devices(void);

phys_addr_t tmpm_iova_to_phys(unsigned long iova);

int tmpm_iommu_get_domain_id(void);

#endif /* _TMPM_IOMMU_H_ */
