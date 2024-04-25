// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#ifndef __KSB_PCI_IO_H
#define __KSB_PCI_IO_H

static inline void ksb_io_write32(struct pci_dev *pdev, u32 offset, u32 val)
{
	struct ksb_drv_ctx *ksb_drv = pci_get_drvdata(pdev);
	u8 __iomem *reg_addr = ksb_drv->membase;

#ifdef DBG_TRACE
	printk("%s: [W] Reg Address 0x%llx, VAL[0x%x]\n", dev_name(&pdev->dev),
           (unsigned long long)(reg_addr + offset), val);
#endif

	writel(val, reg_addr + offset);
}

static inline u32 ksb_io_read32(struct pci_dev *pdev, uint32_t offset)
{
	struct ksb_drv_ctx *ksb_drv = pci_get_drvdata(pdev);
	u8 __iomem *reg_addr = ksb_drv->membase;
	uint32_t value;

	value = readl(reg_addr + offset);

#ifdef DBG_TRACE
	printk("%s: [R] Reg Address 0x%llx, VAL[0x%x]\n", dev_name(&pdev->dev),
           (unsigned long long)(reg_addr + offset), value);
#endif
	return value;
}

static inline void ksb_io_write64(struct pci_dev *pdev, u32 offset, u64 val)
{
	struct ksb_drv_ctx *ksb_drv = pci_get_drvdata(pdev);
	u8 __iomem *reg_addr = ksb_drv->membase;

#ifdef DBG_TRACE
	printk("%s: [W] Reg Address 0x%llx, VAL[0x%llx]\n", dev_name(&pdev->dev),
           (unsigned long long)(reg_addr + offset), val);
#endif

	writeq(val, reg_addr + offset);
}

static inline u64 ksb_io_read64(struct pci_dev *pdev, uint32_t offset)
{
	struct ksb_drv_ctx *ksb_drv = pci_get_drvdata(pdev);
	u8 __iomem *reg_addr = ksb_drv->membase;
	u64 value;

	value = readq(reg_addr + offset);

#ifdef DBG_TRACE
	printk("%s: [R] Reg Address 0x%llx, VAL[0x%llx]\n", dev_name(&pdev->dev),
           (unsigned long long)(reg_addr + offset), value);
#endif
	return value;
}
#endif
