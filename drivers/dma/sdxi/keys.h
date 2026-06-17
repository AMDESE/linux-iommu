/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Key table management (AKey/RKey) and key-related IOCTLs.
 *
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#ifndef __DMA_SDXI_KEYS_H
#define __DMA_SDXI_KEYS_H

#include <linux/types.h>

struct file;
struct sdxi_dev;
struct sdxi_file;

int sdxi_keys_init(struct sdxi_dev *sdxi, u64 cap1);
void sdxi_keys_exit(struct sdxi_dev *sdxi);

int sdxi_ioctl_get_rkey_list(struct file *filep, struct sdxi_file *sf,
			     void *data);
int sdxi_ioctl_get_rkeys(struct file *filep, struct sdxi_file *sf,
			 void *data);
int sdxi_ioctl_set_rkeys(struct file *filep, struct sdxi_file *sf,
			 void *data);
int sdxi_ioctl_get_akey_list(struct file *filep, struct sdxi_file *sf,
			     void *data);
int sdxi_ioctl_get_akeys(struct file *filep, struct sdxi_file *sf,
			 void *data);
int sdxi_ioctl_set_akeys(struct file *filep, struct sdxi_file *sf,
			 void *data);

#endif /* __DMA_SDXI_KEYS_H */
