// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#ifndef __KSB_CDM_DEV_H
#define __KSB_CDM_DEV_H

#include "ksb_pci_drv.h"
#define SIZE_IN_DWORD(a) (sizeof(a) / sizeof(u32))

#define MAX_DMA_SIZE 10240
#define CDM_DEVICE_DMA_SIZE 4096
#define CDM_EXERCISER_DATA_CHUNK_SIZE 256

/* CDM exerciser operation type */
typedef enum cdx_dev_dma_op_e {
	CDM_DMA_MSGST,
	CDM_DMA_MSGLD,
	CDM_DMA_MSGMAX,
} cdx_dev_dma_op_t;

/* CDM exerciser operation status */
typedef enum cdx_dev_exerciser_e {
	CMD_EXERCISER_FAIL = -1,
	CMD_EXERCISER_PASS,
} cdx_dev_exerciser_t;

typedef struct cdx_dev_dma_ctx_s {
	size_t dma_size;
	uint8_t *mem;
	dma_addr_t dma_addr;
	dma_addr_t dma_end_addr;
} cdx_dev_dma_ctx_t;

typedef struct cdx_device_s {
	dev_t devt;
	struct device dev;
	struct cdev cdev;
	struct pci_dev *pci_dev;
	cdx_dev_dma_ctx_t dma_msg_ctx[CDM_DMA_MSGMAX];
	u32 func_addr_off;
	int cdm_major;

	/* Address space for DPU exe */
	struct dpu_addr_space addr_space;
	/* Statistics work */
	struct delayed_work stats_work;
	/* Stats workqueue */
	struct workqueue_struct *stats_wq;
	/* stats flag */
	bool stats_enabled;
	/* User stats flag */
	bool user_stats_en;
	/* stats mutex */
	struct mutex stats_lock;
} cdx_device_t;

cdx_device_t *cdx_device_init(struct pci_dev *pci_dev, bool is_vf);
void cdx_device_fini(cdx_device_t *cdm_ctx);
#endif
