// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI PCI device code
 *
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dev_printk.h>
#include <linux/dma-direction.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/iomap.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci-ats.h>
#include <linux/pci.h>
#include <linux/pm.h>

#include "mmio.h"
#include "sdxi.h"

/*
 * SDXI devices signal message 0 on error conditions, see "Error
 * Logging Control and Status Registers".
 */
#define ERROR_IRQ_MSG 0

/* MMIO BARs */
#define MMIO_CTL_REGS_BAR		0x0
#define MMIO_DOORBELL_BAR		0x2

static struct pci_dev *sdxi_to_pci_dev(const struct sdxi_dev *sdxi)
{
	return to_pci_dev(sdxi_to_dev(sdxi));
}

static int sdxi_pci_irq_init(struct sdxi_dev *sdxi)
{
	struct pci_dev *pdev = sdxi_to_pci_dev(sdxi);
	int msi_count;
	int ret;

	/* 1st irq for error + 1 for each context */
	msi_count = sdxi->max_cxts + 1;

	ret = pci_alloc_irq_vectors(pdev, 1, msi_count,
				    PCI_IRQ_MSI | PCI_IRQ_MSIX);
	if (ret < 0) {
		sdxi_err(sdxi, "alloc MSI/MSI-X vectors failed\n");
		return ret;
	}

	sdxi->error_irq = pci_irq_vector(pdev, ERROR_IRQ_MSG);

	sdxi_dbg(sdxi, "allocated %d irq vectors", ret);

	return 0;
}

static int sdxi_pci_irq_get(struct sdxi_dev *sdxi, unsigned int msg)
{
	return pci_irq_vector(sdxi_to_pci_dev(sdxi), msg);
}

static void sdxi_pci_irq_exit(struct sdxi_dev *sdxi)
{
	pci_free_irq_vectors(sdxi_to_pci_dev(sdxi));
}

static int sdxi_pci_map(struct sdxi_dev *sdxi)
{
	struct pci_dev *pdev = sdxi_to_pci_dev(sdxi);
	int bars, ret;

	bars = 1 << MMIO_CTL_REGS_BAR | 1 << MMIO_DOORBELL_BAR;
	ret = pcim_iomap_regions(pdev, bars, SDXI_DRV_NAME);
	if (ret) {
		sdxi_err(sdxi, "pcim_iomap_regions failed (%d)\n", ret);
		return ret;
	}

	sdxi->dbs_bar = pci_resource_start(pdev, MMIO_DOORBELL_BAR);

	/* FIXME: pcim_iomap_table may return NULL, and it's deprecated. */
	sdxi->ctrl_regs = pcim_iomap_table(pdev)[MMIO_CTL_REGS_BAR];
	sdxi->dbs = pcim_iomap_table(pdev)[MMIO_DOORBELL_BAR];
	if (!sdxi->ctrl_regs || !sdxi->dbs) {
		sdxi_err(sdxi, "pcim_iomap_table failed\n");
		return -EINVAL;
	}

	return 0;
}

static void sdxi_pci_unmap(struct sdxi_dev *sdxi)
{
	struct pci_dev *pdev = sdxi_to_pci_dev(sdxi);

	pcim_iounmap(pdev, sdxi->ctrl_regs);
	pcim_iounmap(pdev, sdxi->dbs);
}

static int sdxi_pci_init(struct sdxi_dev *sdxi)
{
	struct pci_dev *pdev = sdxi_to_pci_dev(sdxi);
	struct device *dev = &pdev->dev;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret) {
		sdxi_err(sdxi, "pcim_enable_device failed\n");
		return ret;
	}

	pci_set_master(pdev);
	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret) {
		sdxi_err(sdxi, "failed to set DMA mask & coherent bits\n");
		return ret;
	}

	ret = sdxi_pci_map(sdxi);
	if (ret) {
		sdxi_err(sdxi, "failed to map device IO resources\n");
		return ret;
	}

	return 0;
}

static void sdxi_pci_exit(struct sdxi_dev *sdxi)
{
	sdxi_pci_unmap(sdxi);
}

static struct sdxi_dev *sdxi_device_alloc(struct device *dev)
{
	struct sdxi_dev *sdxi;

	sdxi = kzalloc(sizeof(*sdxi), GFP_KERNEL);
	if (!sdxi)
		return NULL;

	sdxi->dev = dev;
	sdxi->pci_is_virtfn = to_pci_dev(dev)->is_virtfn;

	sdxi->minor = -1;
	sdxi->pf_id = -1;
	sdxi->vf_id = -1;
	mutex_init(&sdxi->cxt_lock);
	mutex_init(&sdxi->pm_lock);

	return sdxi;
}

static void sdxi_device_free(struct sdxi_dev *sdxi)
{
	kfree(sdxi);
}

static const struct sdxi_dev_ops sdxi_pci_dev_ops = {
	.irq_init = sdxi_pci_irq_init,
	.irq_exit = sdxi_pci_irq_exit,
	.irq_get = sdxi_pci_irq_get,
};

static int sdxi_vf_ids_init(struct sdxi_dev *sdxi)
{
	struct pci_dev *pdev = sdxi_to_pci_dev(sdxi);
	struct sdxi_dev *pf_sdxi;
	int vf_id;

	if (!pdev->is_virtfn)
		return 0;

	if (!sdxi_fn_reports_vf(sdxi)) {
		sdxi_err(sdxi, "VF mismatch: cap0.vf=%d pci.is_virtfn=%d\n",
			 sdxi_fn_reports_vf(sdxi), pdev->is_virtfn);
		return -EINVAL;
	}

	if (!pdev->physfn)
		return -EINVAL;

	/* retrieve owner PF */
	pf_sdxi = pci_get_drvdata(pdev->physfn);
	if (!pf_sdxi || pf_sdxi->pf_id < 0)
		return -EPROBE_DEFER;

	if (sdxi_fn_reports_vf(pf_sdxi))
		return -EINVAL;

	vf_id = pci_iov_vf_id(pdev);
	if (vf_id < 0)
		return vf_id;

	sdxi->pf_id = pf_sdxi->pf_id;
	sdxi->vf_id = vf_id;

	return 0;
}

static int sdxi_pci_probe(struct pci_dev *pdev,
			  const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct sdxi_dev *sdxi;
	int err;

	sdxi = sdxi_device_alloc(dev);
	if (!sdxi)
		return -ENOMEM;

	pci_set_drvdata(pdev, sdxi);

	err = sdxi_pci_init(sdxi);
	if (err)
		goto free_sdxi;

	err = sdxi_device_init(sdxi, &sdxi_pci_dev_ops);
	if (err)
		goto pci_exit;

	err = sdxi_vf_ids_init(sdxi);
	if (err)
		goto dev_exit;

	err = sdxi_chardev_register(sdxi);
	if (err)
		goto dev_exit;

	return 0;

dev_exit:
	sdxi_device_exit(sdxi);
pci_exit:
	sdxi_pci_exit(sdxi);
free_sdxi:
	sdxi_device_free(sdxi);

	return err;
}

static void sdxi_pci_remove(struct pci_dev *pdev)
{
	struct sdxi_dev *sdxi = pci_get_drvdata(pdev);

	sdxi_chardev_unregister(sdxi);
	sdxi_device_exit(sdxi);
	sdxi_pci_exit(sdxi);
	sdxi_device_free(sdxi);
}

static const struct pci_device_id sdxi_id_table[] = {
	{ PCI_DEVICE_CLASS(PCI_CLASS_ACCELERATOR_SDXI, 0xffffff) },
	{ }
};
MODULE_DEVICE_TABLE(pci, sdxi_id_table);

static int sdxi_pm_suspend(struct device *dev)
{
	struct sdxi_dev *sdxi = pci_get_drvdata(to_pci_dev(dev));

	return sdxi_device_suspend(sdxi);
}

static int sdxi_pm_resume(struct device *dev)
{
	struct sdxi_dev *sdxi = pci_get_drvdata(to_pci_dev(dev));

	return sdxi_device_resume(sdxi);
}

static const struct dev_pm_ops sdxi_pm_ops = {
	.suspend = sdxi_pm_suspend,
	.resume = sdxi_pm_resume,
	.freeze = sdxi_pm_suspend,
	.thaw = sdxi_pm_resume,
	.poweroff = sdxi_pm_suspend,
	.restore = sdxi_pm_resume,
};

static struct pci_driver sdxi_driver = {
	.name = "sdxi",
	.id_table = sdxi_id_table,
	.probe = sdxi_pci_probe,
	.remove = sdxi_pci_remove,
	.sriov_configure = pci_sriov_configure_simple,
	.driver.pm = &sdxi_pm_ops,
};

static int __init sdxi_module_init(void)
{
	int rc;

	rc = sdxi_chardev_init();
	if (rc)
		return rc;

	rc = pci_register_driver(&sdxi_driver);
	if (rc)
		sdxi_chardev_exit();

	return rc;
}

static void __exit sdxi_module_exit(void)
{
	pci_unregister_driver(&sdxi_driver);
	sdxi_chardev_exit();
}

MODULE_AUTHOR("Nathan Lynch");
MODULE_AUTHOR("Wei Huang <wei.huang2@amd.com>");
MODULE_DESCRIPTION(SDXI_DRV_DESC);
MODULE_LICENSE("GPL");
module_init(sdxi_module_init);
module_exit(sdxi_module_exit);
