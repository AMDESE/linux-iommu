
// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#include <linux/kernel.h>
#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/random.h>

#include "ksb_csi_exerciser.h"
#include "ksb_pci_drv.h"
#include "ksb_csi_reg.h"
#include "ksb_pci_io.h"

#define KSB_CSI_UPORT_REG_ADDR(n) ((n) * sizeof(u64))

/*********************Functions definitions*******************/
static inline void
csi_exerciser_reg_wr(struct pci_dev *pci_dev, u32 offset, u32 data)
{
	u32 reg = CSI_EXERCISER_OFFSET + offset;

	ksb_io_write32(pci_dev, reg, data);
}

static inline uint32_t
csi_exerciser_reg_rd(struct pci_dev *pci_dev, u32 offset)
{
	u32 reg = CSI_EXERCISER_OFFSET + offset;

	return ksb_io_read32(pci_dev, reg);
}

static inline void
csi_uport_reg_wr(struct pci_dev *pci_dev, int devfn, u64 data)
{
	u32 reg = CSI_UPORT_OFFSET + KSB_CSI_UPORT_REG_ADDR(devfn);

	ksb_io_write64(pci_dev, reg, data);
}

static inline uint64_t
csi_uport_reg_rd(struct pci_dev *pci_dev, int devfn)
{
	u32 reg = CSI_UPORT_OFFSET + KSB_CSI_UPORT_REG_ADDR(devfn);

	return ksb_io_read64(pci_dev, reg);
}

void csi_exerciser_mmio_wr(struct pci_dev *pci_dev, int devfn, uint64_t wr_data)
{
	csi_uport_reg_wr(pci_dev, devfn, wr_data);
}

void csi_exerciser_mmio_rd(struct pci_dev *pci_dev, int devfn, uint64_t *rd_data)
{
	if (rd_data)
		*rd_data = csi_uport_reg_rd(pci_dev, devfn);
}

void csi_exerciser_init(struct pci_dev *pci_dev)
{
	int retry_count = 5;
	u32 status;

	/* Set NPR, CMPL, PR dest_id for returning the dest credit */
	csi_exerciser_reg_wr(pci_dev, CSI_NPR_DEST_ID, CSI_UPORT_DST_ID_BASE);
	csi_exerciser_reg_wr(pci_dev, CSI_CMPL_DEST_ID, CSI_UPORT_DST_ID_BASE + 1);
	csi_exerciser_reg_wr(pci_dev, CSI_PR_DEST_ID, CSI_UPORT_DST_ID_BASE + 2);

	/* Set CMPL init credits */
	csi_exerciser_reg_wr(pci_dev, CSI_CMPL_CREDIT, CSI_UPORT_CMPL_CREDITS);
	csi_exerciser_reg_wr(pci_dev, CSI_INIT_CREDITS_SOURCE2, CSI_UPORT_CMPL_CREDITS);

	/* Set destination FIFO ID */
	csi_exerciser_reg_wr(pci_dev, CSI_CMPL_DEST_FIFO_ID_SOURCE1, CSI_UPORT_CMPL_DEST_FIFO_ID);
	csi_exerciser_reg_wr(pci_dev, CSI_CMPL_DEST_FIFO_ID_SOURCE2, CSI_UPORT_CMPL_DEST_FIFO_ID);
	csi_exerciser_reg_wr(pci_dev, CSI_BUF_ID_SOURCE2, CSI_UPORT_CMPL_DEST_FIFO_ID);
	csi_exerciser_reg_wr(pci_dev, CSI_INPUT_SOURCE1, CSI_EXER_INPUT_SOURCE_PCIE0);
	csi_exerciser_reg_wr(pci_dev, CSI_INPUT_SOURCE2, CSI_EXER_INPUT_SOURCE_PSX);

	/* Reset counters, encode & req_gen logic */
	csi_exerciser_reg_wr(pci_dev, CSI_CTRL, CSI_CTRL_RESET_COUNTERS);

	/* Load Initial credit for all the flow */
	csi_exerciser_reg_wr(pci_dev, CSI_CTRL, CSI_CTRL_LOAD_CREDITS);

	while (retry_count > 0) {
		status = csi_exerciser_reg_rd(pci_dev, CSI_TXN_STATUS);
		if (!(status & 0x2))
			break;

		retry_count--;
		mdelay(5);
	}

	/* Enabling CMPL txn at user port if it receives NPR */
	csi_exerciser_reg_wr(pci_dev, CSI_CTRL, CSI_CTRL_INITIATE_CMPL);
	csi_exerciser_reg_wr(pci_dev, CSI_CTRL, CSI_CTRL_CLEAR);
}
