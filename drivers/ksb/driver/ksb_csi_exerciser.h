// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */
#ifndef __KSB_CSI_EXERCISER_H
#define __KSB_CSI_EXERCISER_H


void csi_exerciser_mmio_wr(struct pci_dev *pci_dev, int devfn, uint64_t wr_data);
void csi_exerciser_mmio_rd(struct pci_dev *pci_dev, int devfn, uint64_t *rd_data);
void csi_exerciser_init(struct pci_dev *pci_dev);
#endif
