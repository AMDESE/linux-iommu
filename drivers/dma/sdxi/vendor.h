/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI vendor-command handler registry.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef __DMA_SDXI_VENDOR_H
#define __DMA_SDXI_VENDOR_H

#include <linux/list.h>
#include <linux/module.h>
#include <linux/types.h>

struct sdxi_admin_vendor_args;
struct sdxi_dev;

struct sdxi_vendor_handler_ops {
	int (*authorize)(struct sdxi_dev *sdxi,
			 const struct sdxi_admin_vendor_args *args);
	int (*exec)(struct sdxi_dev *sdxi, u16 opcode_type,
		    struct sdxi_admin_vendor_args *args,
		    unsigned int timeout_ms);
};

struct sdxi_vendor_handler {
	struct list_head entry;
	const char *name;
	const u8 *guid;
	struct module *owner;
	const struct sdxi_vendor_handler_ops *ops;
};

int sdxi_vendor_register(struct sdxi_vendor_handler *handler);
void sdxi_vendor_unregister(struct sdxi_vendor_handler *handler);
int sdxi_vendor_get(const u8 guid[16],
		    const struct sdxi_vendor_handler **handler_out);
void sdxi_vendor_put(const struct sdxi_vendor_handler *handler);
int sdxi_vendor_find_opcode_type(struct sdxi_dev *sdxi, const u8 guid[16],
				 unsigned int timeout_ms, u16 *opcode_type);

#endif /* __DMA_SDXI_VENDOR_H */
