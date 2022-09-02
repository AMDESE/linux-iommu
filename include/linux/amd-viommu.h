/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 */

#ifndef _LINUX_AMD_VIOMMU_H
#define _LINUX_AMD_VIOMMU_H

#include <uapi/linux/amd_viommu.h>

extern long iommufd_amd_viommu_ioctl(struct file *filp,
				     unsigned int cmd,
				     unsigned long arg);

extern long iommufd_viommu_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg);

extern int amd_viommu_guest_mmio_write(struct amd_viommu_mmio_data *data);
extern int amd_viommu_guest_mmio_read(struct amd_viommu_mmio_data *data);

#endif /* _LINUX_AMD_VIOMMU_H */
