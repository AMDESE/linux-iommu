// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI vendor-command handler registry.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/string.h>

#include "admin.h"
#include "sdxi.h"
#include "vendor.h"

static LIST_HEAD(sdxi_vendor_handlers);
static DEFINE_MUTEX(sdxi_vendor_lock);

int sdxi_vendor_register(struct sdxi_vendor_handler *handler)
{
	struct sdxi_vendor_handler *iter;

	if (!handler || !handler->name || !handler->guid || !handler->ops ||
	    !handler->ops->authorize || !handler->ops->exec)
		return -EINVAL;

	if (!handler->entry.next)
		INIT_LIST_HEAD(&handler->entry);

	mutex_lock(&sdxi_vendor_lock);

	if (!list_empty(&handler->entry)) {
		mutex_unlock(&sdxi_vendor_lock);
		return -EBUSY;
	}

	list_for_each_entry(iter, &sdxi_vendor_handlers, entry) {
		if (!memcmp(iter->guid, handler->guid, 16)) {
			mutex_unlock(&sdxi_vendor_lock);
			return -EEXIST;
		}
	}

	list_add_tail(&handler->entry, &sdxi_vendor_handlers);
	mutex_unlock(&sdxi_vendor_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(sdxi_vendor_register);

void sdxi_vendor_unregister(struct sdxi_vendor_handler *handler)
{
	if (!handler)
		return;

	if (!handler->entry.next)
		INIT_LIST_HEAD(&handler->entry);

	mutex_lock(&sdxi_vendor_lock);
	if (!list_empty(&handler->entry))
		list_del_init(&handler->entry);
	mutex_unlock(&sdxi_vendor_lock);
}
EXPORT_SYMBOL_GPL(sdxi_vendor_unregister);

int sdxi_vendor_get(const u8 guid[16],
		    const struct sdxi_vendor_handler **handler_out)
{
	const struct sdxi_vendor_handler *handler;
	int err = -EOPNOTSUPP;

	if (!guid || !handler_out)
		return -EINVAL;

	mutex_lock(&sdxi_vendor_lock);
	list_for_each_entry(handler, &sdxi_vendor_handlers, entry) {
		if (memcmp(handler->guid, guid, 16))
			continue;

		if (!try_module_get(handler->owner))
			break;

		*handler_out = handler;
		err = 0;
		break;
	}
	mutex_unlock(&sdxi_vendor_lock);

	return err;
}

void sdxi_vendor_put(const struct sdxi_vendor_handler *handler)
{
	if (!handler)
		return;

	module_put(handler->owner);
}

int sdxi_vendor_find_opcode_type(struct sdxi_dev *sdxi, const u8 guid[16],
				 unsigned int timeout_ms, u16 *opcode_type)
{
	static const u16 disc_first = 1;
	static const u16 disc_last = 2047;
	size_t required = (size_t)(disc_last - disc_first + 1) * 16;
	dma_addr_t dma;
	u8 *buf;
	u16 index;
	int err;

	if (!sdxi || !guid || !opcode_type)
		return -EINVAL;

	if (!sdxi_dev_compatible(sdxi, SDXI_VERSION_1_1))
		return -EOPNOTSUPP;

	buf = dma_alloc_coherent(sdxi_to_dev(sdxi), required, &dma, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memset(buf, 0, required);

	err = sdxi_adm_disc(sdxi, disc_first, disc_last, dma, timeout_ms, NULL);
	if (err)
		goto out_free;

	dma_rmb();
	for (index = disc_first; index <= disc_last; index++) {
		const u8 *record = buf + (size_t)(index - disc_first) * 16;

		if (memcmp(record, guid, 16))
			continue;

		*opcode_type = index;
		err = 0;
		goto out_free;
	}

	err = -EOPNOTSUPP;

out_free:
	dma_free_coherent(sdxi_to_dev(sdxi), required, buf, dma);
	return err;
}
