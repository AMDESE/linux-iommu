// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/workqueue.h>

#include <linux/cdev.h>
#include <linux/net.h>
#include <uapi/linux/in.h>

#include "ksb_pci_drv.h"
#include "ksb_cdx_dev.h"
#include "ksb_mcdi_cmd.h"
#include "ksb_dpu_exerciser.h"

#define KSB_PCI_DRV				"ksb_pci"
#define PCI_EXT_CAP_ID_DOE			0x2E	/* Data Object Exchange */

/* KSB PCI CSR */
/* KSB_MC_DB_REG: MC doorbell register */
#define	KSB_MC_DB_LWRG 0x00000020
#define	KSB_MC_DB_HWRG 0x00000024

static const struct ksb_drv_data pf_drv_data = {
		.is_pf = true,
		.is_vf = false,
};

static const struct ksb_drv_data vf_drv_data = {
		.is_pf = false,
		.is_vf = true,
};

extern void *pcim_doe_create_mb_kmod(struct pci_dev *pdev, u16 cap_offset);
extern void pcim_doe_destroy_mb_kmod(struct pci_dev *pdev, void *doe_mb);
void *(*__pcim_doe_create_mb)(struct pci_dev *pdev, u16 cap_offset);
void (*__pcim_doe_destroy_mb)(struct pci_dev *pdev, void *);

static void setup_pci_doe(struct ksb_drv_ctx *ksb_drv)
{
	struct pci_dev *pci_dev = ksb_drv->pci_dev;
	void *doe_mb = NULL;
	int pos;

	pos = pci_find_ext_capability(pci_dev, PCI_EXT_CAP_ID_DOE);
	if (pos == 0) {
		printk("No extended capability for DOE found\n");
	} else {
		__pcim_doe_create_mb = symbol_get(pcim_doe_create_mb_kmod);
		if (__pcim_doe_create_mb) {
			doe_mb = __pcim_doe_create_mb(pci_dev, pos);
			if (!doe_mb)
				printk("pcim_doe_create_mb failed\n");
			else
				printk("pcim_doe_create_mb successful\n");
			ksb_drv->doe_ctx = doe_mb;
			symbol_put(pcim_doe_create_mb_kmod);
		}
	}
}

/* MCDI operations handler */
static bool ksb_mcdi_rpc_timeout(struct ksb_mcdi *mc_ctx, unsigned int cmd)
{
	struct ksb_drv_ctx *ksb_drv = container_of(mc_ctx,
                                                   struct ksb_drv_ctx, mc_ctx);
	const struct ksb_dword hdr = *(const struct ksb_dword *)ksb_drv->mcdi_buf.addr;

	rmb();
	return KSB_DWORD_FIELD(hdr, MCDI_HEADER_RESPONSE);
}

static void ksb_mcdi_request(struct ksb_mcdi *mc_ctx,
			     const struct ksb_dword *hdr, size_t hdr_len,
			     const struct ksb_dword *sdu, size_t sdu_len)
{
	struct ksb_drv_ctx *ksb_drv = container_of(mc_ctx,
                                                   struct ksb_drv_ctx, mc_ctx);
	u8 __iomem *reg_addr = ksb_drv->membase;
	dma_addr_t dma_addr = ksb_drv->mcdi_buf.dma_addr;
	u8 *pdu = ksb_drv->mcdi_buf.addr;
	u64 swapped_addr;

	memcpy(pdu, hdr, hdr_len);
	memcpy(pdu + hdr_len, sdu, sdu_len);
	wmb();

	swapped_addr = (dma_addr >> 32) | ((dma_addr & 0xffffffff) << 32);
	writeq(swapped_addr, reg_addr + KSB_MC_DB_LWRG);
}

static void ksb_mcdi_response(struct ksb_mcdi *mc_ctx, struct ksb_dword *outbuf,
			      size_t offset, size_t outlen)
{
	struct ksb_drv_ctx *ksb_drv = container_of(mc_ctx,
                                                   struct ksb_drv_ctx, mc_ctx);
	u8 *pdu = ksb_drv->mcdi_buf.addr;
	memcpy(outbuf, pdu + offset, outlen);
}
static const struct ksb_mcdi_ops mcdi_ops = {
	.mcdi_rpc_timeout = ksb_mcdi_rpc_timeout,
	.mcdi_request = ksb_mcdi_request,
	.mcdi_response = ksb_mcdi_response,
};

int ksb_pci_get_func_addr(struct pci_dev *pci_dev, u32 *fn_addr_off)
{
	struct ksb_drv_ctx *ksb_drv;
	int ret;

	ksb_drv = pci_get_drvdata(pci_dev);
	if (!ksb_drv) {
		pci_err(pci_dev, "failed to get PCI driver data\n");
		return -EINVAL;
	}

        ret = ksb_mcdi_cmd_get_func_id(ksb_drv, &ksb_drv->pf_fw_index,
				       &ksb_drv->vf_fw_index);
        if (ret != 0) {
                printk("Failed to fetch the function index\n");
		return ret;
        }

	printk("XILINX PCI PF %u: VF %u\n", ksb_drv->pf_fw_index, ksb_drv->vf_fw_index);

	if (ksb_drv->drv_data->is_vf)
		*fn_addr_off = KSB_PCI_GET_FUNC_ADDR(ksb_drv->pf_fw_index,
						 ksb_drv->vf_fw_index);
	else
		*fn_addr_off = ksb_drv->pf_fw_index;

	return 0;
}

static int ksb_pci_probe(struct pci_dev *pci_dev,
			   const struct pci_device_id *entry)
{
	struct ksb_drv_ctx *ksb_drv;
	struct ksb_buffer *mcdi_buf;
	int bar, ret;
	bool is_vf;

	ksb_drv = kzalloc(sizeof(*ksb_drv), GFP_KERNEL);
	if (!ksb_drv)
		return -ENOMEM;

	ksb_drv->drv_data = (struct ksb_drv_data *)entry->driver_data;
	is_vf = ksb_drv->drv_data->is_vf;

	ret = pci_enable_device(pci_dev);
	if (ret) {
		pci_err(pci_dev, "failed to enable PCI device\n");
		goto fail1;
	}

	if (dma_set_mask(&pci_dev->dev, DMA_BIT_MASK(64))) {
		dev_warn(&pci_dev->dev, "No suitable DMA available\n");
		ret = -EIO;
		goto fail1;
	}

	bar = 0;

	ret = pci_request_region(pci_dev, bar, KSB_PCI_DRV);
	if(ret) {
		pci_err(pci_dev, "request for memory BAR[%d] failed\n", bar);
		ret = -EIO;
		goto fail2;
	}

	ksb_drv->membase_phys = pci_resource_start(pci_dev, bar);
	if (!ksb_drv->membase_phys) {
		pci_err(pci_dev,
			"ERROR: No BAR%d mapping from the BIOS."
			 "Try pci=realloc on the kernel command line\n", bar);
		ret = -ENODEV;
		goto fail2;
	}

	pci_set_master(pci_dev);
	pci_save_state(pci_dev);

	ksb_drv->membase_len = pci_resource_len(pci_dev, bar);
	if (ksb_drv->membase_len == 0) {
		pci_err(pci_dev, "Invalid membase length for BAR[%d]\n", bar);
		ret = -EIO;
		goto fail2;
	}

	ksb_drv->mem_bar = bar;

	ksb_drv->membase = ioremap(ksb_drv->membase_phys, ksb_drv->membase_len);
	if (!ksb_drv->membase) {
		pci_err(pci_dev, "could not map memory BAR[%d] at %llx+%llx\n",
			bar, (unsigned long long)ksb_drv->membase_phys,
			ksb_drv->membase_len);
		ret = -ENOMEM;
		goto fail3;
	}

	mcdi_buf = &ksb_drv->mcdi_buf;
	mcdi_buf->addr = dma_alloc_coherent(&pci_dev->dev, MCDI_BUF_LEN,
					   &mcdi_buf->dma_addr, GFP_KERNEL);
	if (!mcdi_buf->addr) {
		pci_err(pci_dev, "MCDI MCDI buffer alloc failed\n");
		goto fail4;
		return -ENOMEM;
	}

	mcdi_buf->len = MCDI_BUF_LEN;

	ksb_drv->mc_ctx.mcdi_ops = &mcdi_ops;

	/* MCDI FW: Initialize the FW path */
	ret = ksb_mcdi_init(&ksb_drv->mc_ctx);
	if (ret) {
		pci_err(pci_dev, "MCDI Initialization failed: %d\n", ret);
		goto fail5;
	}

	printk("memory BAR[%d] at %llx+%llx (virtual 0x%llx)\n", bar,
		(unsigned long long)ksb_drv->membase_phys, ksb_drv->membase_len,
		(unsigned long long)ksb_drv->membase);

	pci_set_drvdata(pci_dev, ksb_drv);
	ksb_drv->pci_dev = pci_dev;

	ksb_drv->cdx_ctx = cdx_device_init(pci_dev, is_vf);
	/* If CDM init failed, just print an err and continue */
	if (ksb_drv->cdx_ctx == NULL)
		pci_err(pci_dev, "CDM context init fialed\n");

	/* Initialize DPU exerciser */
	ret = dpu_exerciser_init(ksb_drv);
	if (ret) {
		pci_err(pci_dev, "Failed to initialize DPU exerciser %d\n", ret);
	}

	if (!is_vf && pci_dev->devfn == 0)
		setup_pci_doe(ksb_drv);

	return 0;

fail5:
	dma_free_coherent(&pci_dev->dev, mcdi_buf->len,
			  mcdi_buf->addr, mcdi_buf->dma_addr);
fail4:
	iounmap(ksb_drv->membase);
fail3:
	pci_release_region(pci_dev, bar);
fail2:
	pci_disable_device(pci_dev);
fail1:
	kfree(ksb_drv);

   return ret;
}

static void ksb_pci_remove(struct pci_dev *pci_dev)
{
	struct ksb_drv_ctx *ksb_drv;
	void *doe_mb;

	ksb_drv = pci_get_drvdata(pci_dev);
	if (!ksb_drv) {
		pci_err(pci_dev, "failed to get PCI driver data\n");
		return;
	}

	doe_mb = ksb_drv->doe_ctx;
	if (doe_mb) {
		__pcim_doe_destroy_mb = symbol_get(pcim_doe_destroy_mb_kmod);
		if (__pcim_doe_destroy_mb) {
			__pcim_doe_destroy_mb(pci_dev, doe_mb);
			symbol_put(pcim_doe_destroy_mb_kmod);
		}
	}

	dpu_exerciser_fini(ksb_drv);
	cdx_device_fini(ksb_drv->cdx_ctx);
	dma_free_coherent(&pci_dev->dev, ksb_drv->mcdi_buf.len,
			  ksb_drv->mcdi_buf.addr, ksb_drv->mcdi_buf.dma_addr);
	ksb_mcdi_finish(&ksb_drv->mc_ctx);
	iounmap(ksb_drv->membase);
	pci_release_region(pci_dev, ksb_drv->mem_bar);
	pci_disable_device(pci_dev);
	kfree(ksb_drv);
	printk("Xilinx KSB device %s removed\n", dev_name(&pci_dev->dev));
}

static int ksb_pci_vf_configure(struct pci_dev *pci_dev, int num_vfs)
{
	int prev_vfs = pci_num_vf(pci_dev);
	int ret;

	if (!num_vfs) {
		if (pci_vfs_assigned(pci_dev)) {
			pci_err(pci_dev, "Unable to remove driver, VFs are assigned\n");
			return -EPERM;
		}

		pci_disable_sriov(pci_dev);
		return 0;
	}

	if (prev_vfs)
		return -EEXIST;

	ret = pci_enable_sriov(pci_dev, num_vfs);
	if (ret != 0) {
		pci_err(pci_dev, "Failed to enable SRIOV, err: %d\n", ret);
		return ret;
	}

	return num_vfs;
}

static void ksb_pci_reset_prepare(struct pci_dev *dev)
{
	struct ksb_drv_ctx *ksb_drv = pci_get_drvdata(dev);

	/* Disable stats */
	dpu_exerciser_set_stats(ksb_drv->cdx_ctx, false);
}

static void ksb_pci_reset_done(struct pci_dev *dev)
{
	struct ksb_drv_ctx *ksb_drv = pci_get_drvdata(dev);

	/* Enable stats */
	dpu_exerciser_set_stats(ksb_drv->cdx_ctx, true);
}

static const struct pci_error_handlers ksb_pci_err_handler = {
	.reset_prepare = ksb_pci_reset_prepare,
	.reset_done = ksb_pci_reset_done,
};

/* PCI device ID table.
 * On changes make sure to update sfc_pci_table in efx.c
 */
static const struct pci_device_id ksb_pci_table[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_XILINX, 0x50a4),
	 .driver_data = (unsigned long) &pf_drv_data},
#if (defined(CONFIG_WITH_VF_PROBE))
	{PCI_DEVICE(PCI_VENDOR_ID_XILINX, 0x50a5),
	 .driver_data = (unsigned long) &vf_drv_data},
#endif
	{0}			/* end of list */
};

struct pci_driver ksb_pci_driver = {
	.name		= KSB_PCI_DRV,
	.id_table	= ksb_pci_table,
	.probe		= ksb_pci_probe,
	.remove		= ksb_pci_remove,
	.sriov_configure = ksb_pci_vf_configure,
	.err_handler = &ksb_pci_err_handler,
};

static int __init ksb_pci_drv_init(void)
{
	int rc;

	printk(KERN_INFO "Loading PCI KSB Driver module...\n");

	rc = pci_register_driver(&ksb_pci_driver);
	if (rc < 0) {
		printk(KERN_ERR "pci_register_driver failed, rc=%d\n", rc);
	}

	return 0;
}

static void __exit ksb_pci_drv_end(void)
{
	pci_unregister_driver(&ksb_pci_driver);
	printk(KERN_INFO "Unloaded PCI KSB Driver module...successfully\n");
}

module_init(ksb_pci_drv_init);
module_exit(ksb_pci_drv_end);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xilinx KSB Driver");