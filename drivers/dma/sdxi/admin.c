// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI admin command descriptor helpers.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <linux/cleanup.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/processor.h>
#include <asm/rwonce.h>

#include "admin.h"
#include "completion.h"
#include "context.h"
#include "descriptor.h"
#include "ring.h"
#include "sdxi.h"

#define SDXI_ADMIN_WAIT_TIMEOUT_MS	5000U

int sdxi_adm_start_cxt_sync(struct sdxi_cxt *cxt, unsigned int timeout_ms,
			   u32 *cst_flags, bool interruptible)
{
	struct sdxi_cxt *adm = to_admin_cxt(cxt);
	struct sdxi_desc *start, *sync;
	struct sdxi_ring_resv resv;
	u32 flags;
	int err;

	might_sleep();

	sdxi_dbg(cxt->sdxi, "adm start NM cxt=%u timeout_ms=%u\n",
		 cxt->id, timeout_ms);

	struct sdxi_completion *sc __free(sdxi_completion) =
		sdxi_completion_alloc(cxt->sdxi);

	/* This is not how to start the admin context. */
	if (WARN_ON(adm == cxt))
		return -EINVAL;
	if (!sc)
		return -ENOMEM;

	err = sdxi_ring_reserve(adm->ring_state, 2, &resv);
	if (err)
		return err;

	start = sdxi_ring_resv_next(&resv);
	sync = sdxi_ring_resv_next(&resv);

	err = sdxi_encode_cxt_start(start, &(const struct sdxi_cxt_start) {
			.range = sdxi_cxt_range(cxt->id),
		});
	if (err)
		return err;

	err = sdxi_encode_sync(sync, &(const struct sdxi_sync) {
			.filter = SDXI_SYNC_FLT_CXT,
			.cxt = sdxi_cxt_range(cxt->id),
		});
	if (err)
		return err;
	sdxi_completion_attach(sync, sc);
	sdxi_desc_make_valid(start);
	sdxi_desc_make_valid(sync);
	sdxi_cxt_push_doorbell(adm, sdxi_ring_resv_dbval(&resv));
	if (interruptible)
		err = sdxi_completion_wait_timeout(sc, timeout_ms);
	else
		err = sdxi_completion_wait_timeout_nosignal(sc, timeout_ms);
	if (err)
		return err;

	sdxi_ring_wake_up(adm->ring_state);
	if (cst_flags)
		*cst_flags = flags;
	if (sdxi_completion_errored(sc))
		return -EIO;

	WRITE_ONCE(cxt->started, true);

	return 0;
}

int sdxi_adm_stop_cxt_sync(struct sdxi_cxt *cxt, unsigned int timeout_ms,
			   u32 *cst_flags, bool interruptible)
{
	struct sdxi_cxt *adm = to_admin_cxt(cxt);
	struct sdxi_desc *stop, *sync;
	struct sdxi_ring_resv resv;
	u32 flags;
	int err;

	might_sleep();

	struct sdxi_completion *sc __free(sdxi_completion) =
		sdxi_completion_alloc(cxt->sdxi);

	/* This is not how to stop the admin context. */
	if (WARN_ON(adm == cxt))
		return -EINVAL;
	if (!sc)
		return -ENOMEM;

	err = sdxi_ring_reserve(adm->ring_state, 2, &resv);
	if (WARN_ON_ONCE(err))
		return err;

	stop = sdxi_ring_resv_next(&resv);
	sync = sdxi_ring_resv_next(&resv);

	sdxi_encode_cxt_stop(stop, &(const struct sdxi_cxt_stop) {
			.range = sdxi_cxt_range(cxt->id),
		});
	sdxi_encode_sync(sync, &(const struct sdxi_sync) {
			.filter = SDXI_SYNC_FLT_STOP,
			.cxt = sdxi_cxt_range(cxt->id),
		});
	sdxi_completion_attach(sync, sc);
	sdxi_desc_make_valid(stop);
	sdxi_desc_make_valid(sync);
	sdxi_cxt_push_doorbell(adm, sdxi_ring_resv_dbval(&resv));
	if (interruptible)
		err = sdxi_completion_wait_timeout(sc, timeout_ms);
	else
		err = sdxi_completion_wait_timeout_nosignal(sc, timeout_ms);
	if (err)
		return err;

	sdxi_ring_wake_up(adm->ring_state);
	flags = sdxi_completion_flags(sc);
	if (cst_flags)
		*cst_flags = flags;
	if (sdxi_completion_errored(sc))
		return -EIO;

	WRITE_ONCE(cxt->started, false);

	return 0;
}

int sdxi_adm_rkey_update_sync(struct sdxi_dev *sdxi, u16 rkey_start, u16 rkey_end,
			      unsigned int timeout_ms, u32 *cst_flags)
{
	struct sdxi_cxt *adm;
	struct sdxi_ring_resv resv;
	struct sdxi_desc *upd, *sync;
	u32 flags;
	int err;

	might_sleep();

	struct sdxi_completion *sc __free(sdxi_completion) =
		sdxi_completion_alloc(sdxi);

	if (!sdxi)
		return -ENODEV;

	adm = sdxi->admin_cxt;
	if (!adm || !adm->ring_state)
		return -ENODEV;
	if (adm->id != SDXI_ADMIN_CXT_ID)
		return -ENODEV;

	if (!sc)
		return -ENOMEM;

	err = sdxi_ring_reserve(adm->ring_state, 2, &resv);
	if (err)
		return err;

	upd = sdxi_ring_resv_next(&resv);
	sync = sdxi_ring_resv_next(&resv);

	err = sdxi_encode_rkey_upd(upd, &(const struct sdxi_rkey_upd) {
			.rkey_start = rkey_start,
			.rkey_end = rkey_end,
		});
	if (err)
		return err;

	err = sdxi_encode_sync(sync, &(const struct sdxi_sync) {
			.filter = SDXI_SYNC_FLT_RKEY,
			.key_start = rkey_start,
			.key_end = rkey_end,
		});
	if (err)
		return err;

	sdxi_completion_attach(sync, sc);
	sdxi_desc_make_valid(upd);
	sdxi_desc_make_valid(sync);
	sdxi_cxt_push_doorbell(adm, sdxi_ring_resv_dbval(&resv));

	err = sdxi_completion_wait_timeout(sc, timeout_ms);
	if (err)
		return err;

	flags = sdxi_completion_flags(sc);
	if (cst_flags)
		*cst_flags = flags;

	sdxi_ring_wake_up(adm->ring_state);

	if (sdxi_completion_errored(sc))
		return -EIO;

	return 0;
}

int sdxi_adm_akey_update_sync(struct sdxi_dev *sdxi, u16 cxt_start, u16 cxt_end,
			      u16 akey_start, u16 akey_end,
			      unsigned int timeout_ms, u32 *cst_flags)
{
	struct sdxi_cxt *adm;
	struct sdxi_ring_resv resv;
	struct sdxi_desc *upd, *sync;
	u32 flags;
	int err;

	might_sleep();

	struct sdxi_completion *sc __free(sdxi_completion) =
		sdxi_completion_alloc(sdxi);

	if (!sdxi)
		return -ENODEV;

	adm = sdxi->admin_cxt;
	if (!adm || !adm->ring_state)
		return -ENODEV;
	if (adm->id != SDXI_ADMIN_CXT_ID)
		return -ENODEV;

	if (!sc)
		return -ENOMEM;

	err = sdxi_ring_reserve(adm->ring_state, 2, &resv);
	if (err)
		return err;

	upd = sdxi_ring_resv_next(&resv);
	sync = sdxi_ring_resv_next(&resv);

	err = sdxi_encode_akey_upd(upd, &(const struct sdxi_akey_upd) {
			.cxt = {
				.cxt_start = cxt_start,
				.cxt_end = cxt_end,
			},
			.akey_start = akey_start,
			.akey_end = akey_end,
		});
	if (err)
		return err;

	err = sdxi_encode_sync(sync, &(const struct sdxi_sync) {
			.filter = SDXI_SYNC_FLT_AKEY,
			.cxt = {
				.cxt_start = cxt_start,
				.cxt_end = cxt_end,
			},
			.key_start = akey_start,
			.key_end = akey_end,
		});
	if (err)
		return err;

	sdxi_completion_attach(sync, sc);
	sdxi_desc_make_valid(upd);
	sdxi_desc_make_valid(sync);
	sdxi_cxt_push_doorbell(adm, sdxi_ring_resv_dbval(&resv));

	err = sdxi_completion_wait_timeout(sc, timeout_ms);
	if (err)
		return err;

	flags = sdxi_completion_flags(sc);
	if (cst_flags)
		*cst_flags = flags;

	sdxi_ring_wake_up(adm->ring_state);

	if (sdxi_completion_errored(sc))
		return -EIO;

	return 0;
}

int sdxi_adm_disc(struct sdxi_dev *sdxi, u16 index_start, u16 index_end,
		  dma_addr_t addr, unsigned int timeout_ms, u32 *cst_flags)
{
	struct sdxi_cxt *adm;
	struct sdxi_ring_resv resv;
	struct sdxi_desc *desc;
	u32 flags;
	int err;

	might_sleep();

	struct sdxi_completion *sc __free(sdxi_completion) =
		sdxi_completion_alloc(sdxi);

	if (!sdxi)
		return -ENODEV;

	adm = sdxi->admin_cxt;
	if (!adm || !adm->ring_state)
		return -ENODEV;
	if (adm->id != SDXI_ADMIN_CXT_ID)
		return -ENODEV;

	if (!sc)
		return -ENOMEM;

	err = sdxi_ring_reserve(adm->ring_state, 1, &resv);
	if (err)
		return err;

	desc = sdxi_ring_resv_next(&resv);
	err = sdxi_encode_disc(desc, &(const struct sdxi_disc) {
			.index_start = index_start,
			.index_end = index_end,
			.addr = addr,
		});
	if (err)
		return err;

	sdxi_completion_attach(desc, sc);
	sdxi_desc_make_valid(desc);
	sdxi_cxt_push_doorbell(adm, sdxi_ring_resv_dbval(&resv));

	err = sdxi_completion_wait_timeout(sc, timeout_ms);
	if (err)
		return err;

	flags = sdxi_completion_flags(sc);
	if (cst_flags)
		*cst_flags = flags;

	sdxi_ring_wake_up(adm->ring_state);

	if (sdxi_completion_errored(sc))
		return -EIO;

	return 0;
}

int sdxi_adm_submit_desc(struct sdxi_cxt *adm, struct sdxi_desc *desc,
			 unsigned int timeout_ms, u32 *cst_flags)
{
	struct sdxi_ring_resv resv;
	struct sdxi_desc *dst;
	struct sdxi_completion *sc __free(sdxi_completion) =
		sdxi_completion_alloc(adm->sdxi);
	int err;

	if (!sc)
		return -ENOMEM;

	err = sdxi_ring_reserve(adm->ring_state, 1, &resv);
	if (err)
		return err;

	dst = sdxi_ring_resv_next(&resv);
	*dst = *desc;

	sdxi_completion_attach(dst, sc);
	sdxi_desc_make_valid(dst);
	sdxi_cxt_push_doorbell(adm, sdxi_ring_resv_dbval(&resv));

	err = sdxi_completion_wait_timeout(sc, timeout_ms);
	if (err)
		return err;

	if (cst_flags)
		*cst_flags = sdxi_completion_flags(sc);

	sdxi_ring_wake_up(adm->ring_state);

	if (sdxi_completion_errored(sc))
		return -EIO;

	return 0;
}
EXPORT_SYMBOL_GPL(sdxi_adm_submit_desc);

int sdxi_adm_start_cxt(struct sdxi_cxt *cxt)
{
	return sdxi_adm_start_cxt_sync(cxt, SDXI_ADMIN_WAIT_TIMEOUT_MS, NULL,
				       false);
}

int sdxi_adm_stop_cxt(struct sdxi_cxt *cxt)
{
	return sdxi_adm_stop_cxt_sync(cxt, SDXI_ADMIN_WAIT_TIMEOUT_MS, NULL,
				      false);
}
