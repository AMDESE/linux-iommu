// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#ifndef __CDM_PCI_DRV_H
#define __CDM_PCI_DRV_H

#include "ksb_mcdi.h"

#define KSB_PCI_MAX_PF      0x4
#define KSB_PCI_MAX_VF      0x400
#define KSB_PCI_VF_APERTURE 0x100

#define KSB_PCI_GET_FUNC_ADDR(_pf, _vf) \
	(((_pf * KSB_PCI_VF_APERTURE) + _vf) + KSB_PCI_MAX_PF)

struct ksb_buffer {
	void *addr;
	dma_addr_t dma_addr;
	unsigned int len;
};

struct ksb_drv_data {
	bool is_pf;
	bool is_vf;
};

struct dpu_addr_space {
	uint64_t addr_spc_id;
	uint8_t dpu_dst_id;
	uint8_t pasid;
	uint8_t func_id;
	uint8_t pasid_en;
};

struct ksb_drv_ctx {
	struct pci_dev *pci_dev;
	struct ksb_drv_data *drv_data;
	struct ksb_mcdi mc_ctx;
	struct ksb_buffer mcdi_buf;
	resource_size_t membase_phys;
	u8 __iomem *membase;
	resource_size_t membase_len;
	int mem_bar;
	u32 pf_fw_index;
	u32 vf_fw_index;
	void *cdx_ctx;
	void *doe_ctx;
};

int ksb_pci_get_func_addr(struct pci_dev *pci_dev, u32 *fn_addr_off);
#endif
