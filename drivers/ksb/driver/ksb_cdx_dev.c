// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bitfield.h>
#include <linux/pci.h>
#include <linux/cdev.h>
#include <uapi/linux/in.h>

#include "../user/include/ksb_user.h"
#include "ksb_cdx_dev.h"
#include "ksb_cdm_exerciser.h"
#include "ksb_csi_exerciser.h"
#include "ksb_pci_drv.h"
#include "ksb_dpu_exerciser.h"

/****************** Functions definition *************************/
static ksb_dpu_op_t to_dpu_op(int cmd)
{
	switch (cmd) {
		case KSB_DMA_RD_USER:	return KSB_DPU_OP_RD;
		case KSB_DMA_WR_USER:	return KSB_DPU_OP_WR;
		case KSB_DMA_RD_WR_USER:	return KSB_DPU_OP_RD_WR;
		case KSB_DMA_PERF_WR_USER:	return KSB_DPU_OP_PERF_WR;
		case KSB_DMA_PERF_RD_USER:	return KSB_DPU_OP_PERF_RD;
	}
	return KSB_DPU_OP_INVALID;
}

static int cdx_dev_dma_alloc(cdx_device_t *cdx_dev, cdx_dev_dma_ctx_t *dma_ctx)
{
	struct pci_dev *pci_dev = cdx_dev->pci_dev;
	dma_addr_t dma_addr;
	uint8_t *mem;
	uint32_t len = CDM_DEVICE_DMA_SIZE;

	mem = dma_alloc_coherent(&pci_dev->dev, len, &dma_addr, GFP_KERNEL);
	if (!mem)
		return -ENOMEM;

	dma_ctx->dma_size = len;
	dma_ctx->dma_addr = dma_addr;
	dma_ctx->dma_end_addr = (dma_addr_t)(dma_addr + len);
	dma_ctx->mem = mem;

	return 0;
}

static void cdx_dev_dma_free(cdx_device_t *cdx_dev, cdx_dev_dma_ctx_t *dma_ctx)
{
	struct pci_dev *pci_dev = cdx_dev->pci_dev;

	dma_free_coherent(&pci_dev->dev, dma_ctx->dma_size,
			  dma_ctx->mem, dma_ctx->dma_addr);
	memset(dma_ctx, 0, sizeof(*dma_ctx));
}

static int cdx_dev_dma_ctx_alloc_all(cdx_device_t *cdx_dev)
{
	if(cdx_dev_dma_alloc(cdx_dev, &cdx_dev->dma_msg_ctx[CDM_DMA_MSGST])) {
		printk("%s: Failed to allocate MSGST DMA memory\n", __func__);
		return -ENOMEM;
	}

	if(cdx_dev_dma_alloc(cdx_dev, &cdx_dev->dma_msg_ctx[CDM_DMA_MSGLD])) {
		printk("%s: Failed to allocate MSGLD DMA memory\n", __func__);
		cdx_dev_dma_free(cdx_dev, &cdx_dev->dma_msg_ctx[CDM_DMA_MSGST]);
		return -ENOMEM;
	}

	return 0;
}

static void cdx_dev_dma_ctx_free_all(cdx_device_t *cdx_dev)
{
	cdx_dev_dma_free(cdx_dev, &cdx_dev->dma_msg_ctx[CDM_DMA_MSGST]);
	cdx_dev_dma_free(cdx_dev, &cdx_dev->dma_msg_ctx[CDM_DMA_MSGLD]);
}

static int cdx_dev_usr_err(int err_no)
{
	int rc;

	switch(err_no) {
	case 0:
		rc = 0;
		break;

	case EIO:
		rc = KSB_CDX_ERR_IO;
		break;

	case EINVAL:
		rc = KSB_CDX_ERR_PATTERN_MISMATCH;
		break;

	default:
		rc = KSB_CDX_ERR_UNKNOWN;
	}

	return rc;
}

static long cdx_dev_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	cdx_device_t *cdx_dev = file->private_data;
	ksb_user_cmd_t usr_cmd;
	int ret = 0;

	if (copy_from_user(&usr_cmd, (u8 __user *)arg, sizeof(usr_cmd))) {
		printk("%s: Failed to copy user data\n", __func__);
		return -EFAULT;
	}

	usr_cmd.err_code = 0;

	if ((cmd == KSB_CDM_MSGST || cmd == KSB_CDM_MSGLD) && usr_cmd.req_size > CDM_EXERCISER_DATA_CHUNK_SIZE) {
		usr_cmd.err_code = KSB_CDX_ERR_INVAL_REQUEST_SIZE;
		goto end;
	}

	switch (cmd) {
	case KSB_CDM_MSGST:
		ret = cdm_exerciser_execute_cmd(cdx_dev, CDM_DMA_MSGST,
						usr_cmd.seed, usr_cmd.req_size,
						usr_cmd.req_count);
		break;
	case KSB_CDM_MSGLD:
		ret = cdm_exerciser_execute_cmd(cdx_dev, CDM_DMA_MSGLD,
						usr_cmd.seed, usr_cmd.req_size,
						usr_cmd.req_count);
		break;
	case KSB_MMIO_WR:
		csi_exerciser_mmio_wr(cdx_dev->pci_dev, cdx_dev->func_addr_off, usr_cmd.wr_data);
		break;
	case KSB_MMIO_RD:
		csi_exerciser_mmio_rd(cdx_dev->pci_dev, cdx_dev->func_addr_off, &usr_cmd.rd_data);
		break;
	case KSB_MMIO_WR_RD:
		csi_exerciser_mmio_wr(cdx_dev->pci_dev, cdx_dev->func_addr_off, usr_cmd.wr_data);
		csi_exerciser_mmio_rd(cdx_dev->pci_dev, cdx_dev->func_addr_off, &usr_cmd.rd_data);
		break;
	case KSB_DMA_PERF_WR_USER:
	case KSB_DMA_PERF_RD_USER:
	{
		ksb_dpu_cmd_t dpu_cmd = { 0 };
		ksb_dpu_perf_t perf;

		/* Maximum DMA size is limited to MTU size which is 10K set for DPU */
		if (usr_cmd.req_size > MAX_DMA_SIZE) {
			usr_cmd.err_code = KSB_CDX_ERR_INVAL_REQUEST_SIZE;
			goto end;
		}

		if (cmd == KSB_DMA_PERF_RD_USER && !usr_cmd.dma_rd_fabric)
			/* For DMA read into dpu buffer, we need two dpu exe */
			dpu_cmd.dpu_exe = reserve_dpu_cmd_exe(usr_cmd.dpu_exe_instance, true);
		else
			dpu_cmd.dpu_exe = reserve_dpu_cmd_exe(usr_cmd.dpu_exe_instance, false);
		if (dpu_cmd.dpu_exe < 0) {
			printk("Failed to reserve dpu cmd exe\n");
			return -EAGAIN;
		}

		dpu_cmd.cmd = to_dpu_op(cmd);
		dpu_cmd.src = usr_cmd.src;
		dpu_cmd.dst = usr_cmd.dst;
		dpu_cmd.dma_len = usr_cmd.req_size;
		dpu_cmd.loops = usr_cmd.in_pkts;
		dpu_cmd.addr_mapped = usr_cmd.addr_mapped ? true : false;
		dpu_cmd.dma_rd_fabric = usr_cmd.dma_rd_fabric;

		ret = dpu_exerciser_execute_user_perf_cmd(cdx_dev, &dpu_cmd, &perf);

		if (cmd == KSB_DMA_PERF_RD_USER && !usr_cmd.dma_rd_fabric)
			release_dpu_cmd_exe(dpu_cmd.dpu_exe, true);
		else
			release_dpu_cmd_exe(dpu_cmd.dpu_exe, false);

		usr_cmd.out_loops = perf.loops;
		usr_cmd.out_duration_ns = perf.duration_ns;
		break;
	}
	case KSB_DMA_RD_USER:
	case KSB_DMA_WR_USER:
	case KSB_DMA_RD_WR_USER:
	{
		ksb_dpu_cmd_t dpu_cmd = { 0 };

		/* Maximum DMA size is limited to MTU size which is 10K set for DPU */
		if (usr_cmd.req_size > MAX_DMA_SIZE) {
			usr_cmd.err_code = KSB_CDX_ERR_INVAL_REQUEST_SIZE;
			goto end;
		}

		dpu_cmd.dpu_exe = reserve_dpu_cmd_exe(usr_cmd.dpu_exe_instance, false);
		if (dpu_cmd.dpu_exe < 0) {
			printk("Failed to reserve dpu cmd exe\n");
			return -EAGAIN;
		}

		dpu_cmd.cmd = to_dpu_op(cmd);
		dpu_cmd.src = usr_cmd.src;
		dpu_cmd.dst = usr_cmd.dst;
		dpu_cmd.dma_len = usr_cmd.req_size;
		dpu_cmd.addr_mapped = usr_cmd.addr_mapped ? true : false;

		ret = dpu_exerciser_execute_user_cmd(cdx_dev, &dpu_cmd);

		release_dpu_cmd_exe(dpu_cmd.dpu_exe, false);
		break;
	}
	case KSB_DMA_STATS_ENABLE:
	{
		ksb_stats_en_cmd_t stats_cmd;

		if (cdx_dev->addr_space.func_id != 0) {
			return -EINVAL;
		}
		if (copy_from_user(&stats_cmd, (u8 __user *)arg, sizeof(stats_cmd))) {
			printk("%s: Failed to copy user data\n", __func__);
			return -EFAULT;
		}

		cdx_dev->user_stats_en = stats_cmd.enable ? true : false;

		dpu_exerciser_set_stats(cdx_dev, cdx_dev->user_stats_en);
		break;
	}
	default:
		break;
	}

	usr_cmd.err_code = cdx_dev_usr_err(ret);
end:
	if (copy_to_user((u8 __user *)arg, &usr_cmd, sizeof(usr_cmd)))
		return -EFAULT;

	return 0;
}

static int cdx_dev_fs_open(struct inode *inode, struct file *file)
{
	cdx_device_t *cdx_dev = container_of(inode->i_cdev, struct cdx_device_s, cdev);

	get_device(&cdx_dev->dev);

	file->private_data = cdx_dev;

	/* Do not allocate DMA context if the file handle was not
	 * released during last file open() */
	if (cdx_dev->dma_msg_ctx[CDM_DMA_MSGST].mem &&
	    cdx_dev->dma_msg_ctx[CDM_DMA_MSGST].dma_addr != 0 &&
	    cdx_dev->dma_msg_ctx[CDM_DMA_MSGLD].mem &&
	    cdx_dev->dma_msg_ctx[CDM_DMA_MSGLD].dma_addr != 0)
		return 0;

	if (cdx_dev_dma_ctx_alloc_all(cdx_dev))
		return -ENOMEM;

	return 0;
}

static int cdx_dev_fs_release(struct inode *inode, struct file *file)
{
	cdx_device_t *cdx_dev = container_of(inode->i_cdev, struct cdx_device_s, cdev);

	put_device(&cdx_dev->dev);
	cdx_dev_dma_ctx_free_all(cdx_dev);

	return 0;
}

static const struct file_operations cdx_device_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl	= cdx_dev_fs_ioctl,
	.open           = cdx_dev_fs_open,
	.release        = cdx_dev_fs_release,
};

static char *pci_cdx_devnode(const struct device *dev, umode_t *mode, kuid_t *uid, kgid_t *gid)
{
	return kasprintf(GFP_KERNEL, "pcicdx/%s", dev_name(dev));
}

static const struct device_type pci_cdm_type = {
	.name = "pci_ksb_cdx",
	.devnode = pci_cdx_devnode,
};

static void cdx_device_create_release(struct device *dev)
{
	printk("device: '%s': %s\n", dev_name(dev), __func__);
}

cdx_device_t *cdx_device_init(struct pci_dev *pci_dev, bool is_vf)
{
	cdx_device_t *cdx_dev;
	int cdm_major;
	int rc;

	cdx_dev = kzalloc(sizeof(*cdx_dev), GFP_KERNEL);
	if (!cdx_dev)
		return NULL;

	rc = alloc_chrdev_region(&cdx_dev->devt, 0, 1, "cdx-device");
	if (rc)
		goto fail1;

	cdm_major = MAJOR(cdx_dev->devt);

	cdev_init(&cdx_dev->cdev, &cdx_device_fops);

	device_initialize(&cdx_dev->dev);
	cdx_dev->dev.parent = &pci_dev->dev;
	cdx_dev->dev.devt = cdx_dev->devt;
	cdx_dev->dev.type = &pci_cdm_type;
	cdx_dev->dev.class = pci_dev->dev.class;
	cdx_dev->dev.release = cdx_device_create_release;
	cdx_dev->pci_dev = pci_dev;
	device_set_pm_not_required(&cdx_dev->dev);
	rc = dev_set_name(&cdx_dev->dev, "ksb_cdx_dev%x%x", pci_dev->bus->number, pci_dev->devfn);
	if (rc)
		goto fail2;

	rc = cdev_device_add(&cdx_dev->cdev, &cdx_dev->dev);
	if (rc)
		goto fail3;

	/* Get the PCIe function address offset used by firmware.
	 * This will be used as an offset into CSI exerciser address
	 * space. */
	rc = ksb_pci_get_func_addr(pci_dev, &cdx_dev->func_addr_off);
	if (rc)
		pci_err(pci_dev, "Failed to get function address: %d\n", rc);

	printk("%s Function address offset %u\n", dev_name(&cdx_dev->dev),
		cdx_dev->func_addr_off);

	/* Call csi_exerciser_init() only once for PF 0 */
	if (!is_vf && pci_dev->devfn == 0)
		csi_exerciser_init(pci_dev);

	printk("%s [%p] init done...\n", dev_name(&cdx_dev->dev), cdx_dev);
	return cdx_dev;

fail3:
	put_device(&cdx_dev->dev);
fail2:
	unregister_chrdev_region(cdx_dev->devt, 1);
fail1:
	kfree(cdx_dev);

	return NULL;
}

void cdx_device_fini(cdx_device_t *cdm_ctx)
{
	cdx_device_t *cdx_dev = cdm_ctx;

	/* Cleanup the DMA contexts if the file handle was not released */
	if (cdx_dev->dma_msg_ctx[CDM_DMA_MSGST].mem &&
	    cdx_dev->dma_msg_ctx[CDM_DMA_MSGST].dma_addr != 0 &&
	    cdx_dev->dma_msg_ctx[CDM_DMA_MSGLD].mem &&
	    cdx_dev->dma_msg_ctx[CDM_DMA_MSGLD].dma_addr != 0)
		cdx_dev_dma_ctx_free_all(cdx_dev);

	cdev_device_del(&cdx_dev->cdev, &cdx_dev->dev);
	put_device(&cdx_dev->dev);
	unregister_chrdev_region(cdx_dev->devt, 1);
	kfree(cdx_dev);
}
