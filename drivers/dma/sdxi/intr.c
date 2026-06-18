// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI context interrupt routing to userspace.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <linux/eventfd.h>
#include <linux/interrupt.h>
#include <linux/string.h>

#include "context.h"
#include "hw.h"
#include "intr.h"
#include "sdxi.h"

/*
 * Slot 0 is owned by context-table programming. Slot 1 is the default
 * userspace local-memory AKey installed at context creation. Context eventfd
 * routing dynamically allocates another free slot and reports it through
 * SDXI_CXT_EVENTFD.
 */
#define SDXI_UCXT_DEFAULT_AKEY	1

static int sdxi_cxt_alloc_intr_akey(struct sdxi_cxt *cxt, u16 *akey)
{
	struct sdxi_akey_table *tbl;
	u32 i;
	u16 intr;

	if (!cxt || !cxt->akey_table || !akey)
		return -EINVAL;

	tbl = cxt->akey_table;

	for (i = SDXI_UCXT_DEFAULT_AKEY + 1; i < ARRAY_SIZE(tbl->entry); i++) {
		intr = le16_to_cpu(tbl->entry[i].intr_num);
		if (intr & SDXI_AKEY_ENT_VL)
			continue;

		*akey = i;
		return 0;
	}

	return -ENOSPC;
}

static void sdxi_cxt_clear_intr_akey(struct sdxi_cxt *cxt, u16 akey)
{
	struct sdxi_akey_ent *ent;

	if (!cxt || !cxt->akey_table || !akey)
		return;
	if (akey >= ARRAY_SIZE(cxt->akey_table->entry))
		return;

	ent = &cxt->akey_table->entry[akey];
	WRITE_ONCE(ent->intr_num, 0);
	dma_wmb();
	memset(ent, 0, sizeof(*ent));
	dma_wmb();
}

static void sdxi_cxt_arm_intr_akey(struct sdxi_cxt *cxt, u16 akey)
{
	struct sdxi_akey_ent *ent;
	u32 pasid = 0;
	u16 intr;

	if (!cxt || !cxt->akey_table || !akey)
		return;
	if (akey >= ARRAY_SIZE(cxt->akey_table->entry))
		return;

	ent = &cxt->akey_table->entry[akey];

	if (cxt->pasid_valid)
		pasid = FIELD_PREP(SDXI_AKEY_ENT_PASID, cxt->pasid);

	intr = (FIELD_PREP(SDXI_AKEY_ENT_VL, 1) |
		FIELD_PREP(SDXI_AKEY_ENT_IV, 1) |
		FIELD_PREP(SDXI_AKEY_ENT_PV, cxt->pasid_valid) |
		FIELD_PREP(SDXI_AKEY_ENT_INTR_NUM, cxt->intr_msg));

	memset(ent, 0, sizeof(*ent));
	ent->pasid = cpu_to_le32(pasid);
	dma_wmb();
	WRITE_ONCE(ent->intr_num, cpu_to_le16(intr));
}

static irqreturn_t sdxi_cxt_irq_handler(int irq, void *data)
{
	struct sdxi_cxt *cxt = data;
	struct eventfd_ctx *ev_ctx;
	bool armed;
	unsigned long flags;

	spin_lock_irqsave(&cxt->intr_lock, flags);
	ev_ctx = cxt->intr_eventfd;
	armed = cxt->intr_armed;
	if (ev_ctx) {
		eventfd_signal(ev_ctx);
		spin_unlock_irqrestore(&cxt->intr_lock, flags);
		return IRQ_HANDLED;
	}
	spin_unlock_irqrestore(&cxt->intr_lock, flags);

	if (armed) {
		sdxi_err(cxt->sdxi,
			 "context %u interrupt without eventfd, destroying context\n",
			 cxt->id);
		sdxi_cxt_kill(cxt);
	}

	return IRQ_HANDLED;
}

bool sdxi_cxt_has_intr_fd(const struct sdxi_cxt *cxt)
{
	if (!cxt)
		return false;

	return READ_ONCE(cxt->intr_eventfd);
}

int sdxi_cxt_init_intr(struct sdxi_cxt *cxt)
{
	struct sdxi_dev *sdxi;
	unsigned int msg;
	int irq;
	int err;

	if (!cxt || !cxt->sdxi || !cxt->akey_table)
		return -ENODEV;

	/* Disallow binding interrupts to the administrative context. */
	if (cxt->id == SDXI_ADMIN_CXT_ID)
		return -EINVAL;

	if (cxt->intr_irq > 0)
		return 0;

	sdxi = cxt->sdxi;
	msg = cxt->id + 1;
	if (!FIELD_FIT(SDXI_AKEY_ENT_INTR_NUM, msg))
		return -ENOSPC;

	irq = sdxi_irq_get(sdxi, msg);
	if (irq < 0)
		return irq;

	err = request_irq(irq, sdxi_cxt_irq_handler, IRQF_TRIGGER_NONE,
			  "sdxi-cxt", cxt);
	if (err)
		return err;

	cxt->intr_irq = irq;
	cxt->intr_msg = msg;
	cxt->intr_akey = 0;
	cxt->intr_armed = false;

	return 0;
}

static int sdxi_cxt_clear_intr_fd(struct sdxi_cxt *cxt)
{
	struct eventfd_ctx *ev_ctx;
	unsigned long flags;
	u16 akey;

	if (!cxt)
		return 0;

	mutex_lock(&cxt->akey_lock);

	spin_lock_irqsave(&cxt->intr_lock, flags);
	akey = cxt->intr_akey;
	cxt->intr_armed = false;
	spin_unlock_irqrestore(&cxt->intr_lock, flags);

	sdxi_cxt_clear_intr_akey(cxt, akey);

	spin_lock_irqsave(&cxt->intr_lock, flags);
	ev_ctx = cxt->intr_eventfd;
	cxt->intr_akey = 0;
	cxt->intr_eventfd = NULL;
	spin_unlock_irqrestore(&cxt->intr_lock, flags);

	mutex_unlock(&cxt->akey_lock);

	if (ev_ctx)
		eventfd_ctx_put(ev_ctx);

	return 0;
}

void sdxi_cxt_exit_intr(struct sdxi_cxt *cxt)
{
	struct eventfd_ctx *ev_ctx;
	unsigned long flags;
	u16 akey;

	if (!cxt)
		return;

	mutex_lock(&cxt->akey_lock);

	spin_lock_irqsave(&cxt->intr_lock, flags);
	akey = cxt->intr_akey;
	cxt->intr_armed = false;
	spin_unlock_irqrestore(&cxt->intr_lock, flags);

	sdxi_cxt_clear_intr_akey(cxt, akey);

	spin_lock_irqsave(&cxt->intr_lock, flags);
	ev_ctx = cxt->intr_eventfd;
	cxt->intr_akey = 0;
	cxt->intr_eventfd = NULL;
	spin_unlock_irqrestore(&cxt->intr_lock, flags);

	mutex_unlock(&cxt->akey_lock);

	if (cxt->intr_irq > 0)
		free_irq(cxt->intr_irq, cxt);

	cxt->intr_irq = 0;
	cxt->intr_msg = 0;

	if (ev_ctx)
		eventfd_ctx_put(ev_ctx);
}

int sdxi_cxt_set_intr_fd(struct sdxi_cxt *cxt, int eventfd_fd,
			 u16 *akey, u32 *intr_num)
{
	struct eventfd_ctx *ev_ctx;
	struct eventfd_ctx *old_ev_ctx;
	unsigned long flags;
	u16 intr_akey;
	int err;

	if (!cxt || !cxt->sdxi || !cxt->akey_table)
		return -ENODEV;

	if (sdxi_cxt_is_fatal(cxt))
		return -ENODEV;

	/* Disallow binding interrupts to the administrative context. */
	if (cxt->id == SDXI_ADMIN_CXT_ID)
		return -EINVAL;

	if (cxt->intr_irq <= 0 || !cxt->intr_msg)
		return -EOPNOTSUPP;

	/* Unbind request. */
	if (eventfd_fd < 0) {
		err = sdxi_cxt_clear_intr_fd(cxt);
		if (err)
			return err;
		if (akey)
			*akey = 0;
		if (intr_num)
			*intr_num = 0;
		return 0;
	}

	ev_ctx = eventfd_ctx_fdget(eventfd_fd);
	if (IS_ERR(ev_ctx))
		return PTR_ERR(ev_ctx);

	mutex_lock(&cxt->akey_lock);

	spin_lock_irqsave(&cxt->intr_lock, flags);
	intr_akey = cxt->intr_akey;
	spin_unlock_irqrestore(&cxt->intr_lock, flags);

	if (!intr_akey) {
		err = sdxi_cxt_alloc_intr_akey(cxt, &intr_akey);
		if (err)
			goto err_unlock;
	}

	spin_lock_irqsave(&cxt->intr_lock, flags);
	old_ev_ctx = cxt->intr_eventfd;
	cxt->intr_eventfd = ev_ctx;
	cxt->intr_akey = intr_akey;
	cxt->intr_armed = false;
	spin_unlock_irqrestore(&cxt->intr_lock, flags);

	sdxi_cxt_arm_intr_akey(cxt, intr_akey);

	spin_lock_irqsave(&cxt->intr_lock, flags);
	cxt->intr_armed = true;
	spin_unlock_irqrestore(&cxt->intr_lock, flags);

	mutex_unlock(&cxt->akey_lock);

	if (akey)
		*akey = intr_akey;
	if (intr_num)
		*intr_num = cxt->intr_msg;

	if (old_ev_ctx)
		eventfd_ctx_put(old_ev_ctx);

	return 0;

err_unlock:
	mutex_unlock(&cxt->akey_lock);
	eventfd_ctx_put(ev_ctx);
	return err;
}
