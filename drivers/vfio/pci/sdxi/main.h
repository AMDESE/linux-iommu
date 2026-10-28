/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef SDXI_VFIO_H
#define SDXI_VFIO_H

#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/sdxi.h>
#include <linux/types.h>
#include <linux/vfio.h>
#include <linux/vfio_pci_core.h>

#define SDXI_MIG_MAGIC		0x49584453	/* "SDXI" */
#define SDXI_MIG_VERSION	1

struct sdxi_mig_blob {
	__le32 magic;
	__le32 version;
	__le64 cap0;
	__le64 cap1;
	__le64 ctl0;
	__le64 ctl2;
	__le64 cxt_l2;
	__le64 rkey;
	__le64 err_cfg;
	__le64 err_ctl;
	__le64 err_wrt;
	__le64 err_rd;
} __packed;

struct sdxi_mig_file {
	struct file		*filp;
	struct mutex		 lock;
	loff_t			 pos;
	struct sdxi_mig_blob	 blob;
	bool			 valid;
};

struct sdxi_vfio_pci_device {
	struct vfio_pci_core_device	core_dev;
	void __iomem			*bar0;

	struct mutex			 state_mutex;
	enum vfio_device_mig_state	 state;
	struct sdxi_mig_file		*save_file;
	struct sdxi_mig_file		*restore_file;
};

#endif /* SDXI_VFIO_H */
