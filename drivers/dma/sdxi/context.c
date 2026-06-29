// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI submission queue (sq) and descriptor management
 *
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt)     "SDXI: " fmt

#include <linux/delay.h>
#include <linux/cleanup.h>
#include <linux/dma-direction.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/wordpart.h>

#include "admin.h"
#include "completion.h"
#include "descriptor.h"
#include "context.h"
#include "hw.h"
#include "intr.h"
#include "process.h"
#include "ring.h"
#include "sdxi.h"
#include "trace.h"

#define SDXI_CXT_QUIESCE_TIMEOUT_MS	5000U
#define SDXI_CXT_CLEANUP_RETRY_MS	100U


static struct sdxi_sq *sdxi_sq_alloc_default(struct sdxi_cxt *cxt);
static void sdxi_sq_free(struct sdxi_sq *sq);
static int config_cxt_tables(struct sdxi_dev *sdxi, struct sdxi_cxt *cxt);
static void cleanup_cxt_tables(struct sdxi_dev *sdxi, struct sdxi_cxt *cxt);

static struct sdxi_cxt *sdxi_alloc_cxt(struct sdxi_dev *sdxi)
{
	struct sdxi_cxt *cxt;
	struct device *dev = sdxi_to_dev(sdxi);

	cxt = kzalloc(sizeof(*cxt), GFP_KERNEL);
	if (!cxt)
		return NULL;

	cxt->sdxi = sdxi;
	mutex_init(&cxt->cleanup_lock);

	cxt->ring_state = kzalloc(sizeof(*cxt->ring_state), GFP_KERNEL);
	if (!cxt->ring_state)
		goto free_cxt;

	cxt->akey_table = dma_alloc_coherent(dev, sizeof(*cxt->akey_table),
					 &cxt->akey_table_dma, GFP_KERNEL);
	if (!cxt->akey_table)
		goto free_ring_state;

	cxt->cxt_ctl = dma_pool_zalloc(sdxi->cxt_ctl_pool, GFP_KERNEL,
				       &cxt->cxt_ctl_dma);
	if (!cxt->cxt_ctl)
		goto free_akey_table;

	cxt->sq = sdxi_sq_alloc_default(cxt);
	if (!cxt->sq)
		goto free_cxt_ctl;

	return cxt;

free_cxt_ctl:
	dma_pool_free(sdxi->cxt_ctl_pool, cxt->cxt_ctl, cxt->cxt_ctl_dma);
	cxt->cxt_ctl = NULL;
free_akey_table:
	dma_free_coherent(dev, sizeof(*cxt->akey_table), cxt->akey_table,
			  cxt->akey_table_dma);
	cxt->akey_table = NULL;
free_ring_state:
	kfree(cxt->ring_state);
free_cxt:
	mutex_destroy(&cxt->cleanup_lock);
	kfree(cxt);
	return NULL;
}

static void sdxi_free_cxt(struct sdxi_cxt *cxt)
{
	struct sdxi_dev *sdxi;

	if (!cxt)
		return;

	sdxi = cxt->sdxi;
	if (cxt->id)
		WARN_ON(xa_erase(&sdxi->client_cxts, cxt->id) != cxt);

	sdxi_sq_free(cxt->sq);
	if (cxt->cxt_ctl)
		dma_pool_free(sdxi->cxt_ctl_pool, cxt->cxt_ctl, cxt->cxt_ctl_dma);
	if (cxt->akey_table)
		dma_free_coherent(sdxi_to_dev(sdxi), sizeof(*cxt->akey_table),
				  cxt->akey_table, cxt->akey_table_dma);

	ida_destroy(&cxt->akey_ida);
	kfree(cxt->ring_state);
	mutex_destroy(&cxt->cleanup_lock);
	kfree(cxt);
}

DEFINE_FREE(sdxi_cxt, struct sdxi_cxt *, if (_T) sdxi_free_cxt(_T))

static int sdxi_publish_cxt(const struct sdxi_cxt *cxt)
{
	return config_cxt_tables(cxt->sdxi, (struct sdxi_cxt *)cxt);
}

static void sdxi_rescind_cxt(struct sdxi_cxt *cxt)
{
	cleanup_cxt_tables(cxt->sdxi, cxt);
}

/* Alloc sdxi_sq in kernel space */
static struct sdxi_sq *sdxi_sq_alloc(struct sdxi_cxt *cxt, u32 ring_entries)
{
	struct sdxi_dev *sdxi = cxt->sdxi;
	struct device *dev = sdxi_to_dev(sdxi);
	u64 write_index_ptr;
	struct sdxi_sq *sq;
	u64 ds_ring_ptr;
	u64 cxt_sts_ptr;
	u32 ds_ring_sz;

	if (ring_entries > sdxi->max_ring_entries) {
		sdxi_err(sdxi, "%d ring entries requested, max is %llu\n",
			ring_entries, sdxi->max_ring_entries);
		return NULL;
	}

	sq = kzalloc(sizeof(*sq), GFP_KERNEL);
	if (!sq)
		return NULL;

	sq->ring_entries = ring_entries;
	sq->ring_size = PAGE_ALIGN((size_t)sq->ring_entries *
				   sizeof(sq->desc_ring[0]));
	sq->desc_ring = dma_alloc_coherent(dev, sq->ring_size, &sq->ring_dma,
					   GFP_KERNEL);
	if (!sq->desc_ring)
		goto free_sq;

	sq->cxt_sts = dma_pool_zalloc(sdxi->cxt_sts_pool, GFP_KERNEL, &sq->cxt_sts_dma);
	if (!sq->cxt_sts)
		goto free_desc_ring;

	sq->write_index = dma_pool_zalloc(sdxi->write_index_pool, GFP_KERNEL,
					  &sq->write_index_dma);
	if (!sq->write_index)
		goto free_cxt_sts;

	/* final setup */
	if (cxt->id == SDXI_ADMIN_CXT_ID)
		sq->cxt_sts->state = FIELD_PREP(SDXI_CXT_STS_STATE, CXTV_RUN);

	write_index_ptr = FIELD_PREP(SDXI_CXT_CTL_WRITE_INDEX_PTR,
				     sq->write_index_dma >> 3);
	cxt_sts_ptr = FIELD_PREP(SDXI_CXT_CTL_CXT_STS_PTR,
				 sq->cxt_sts_dma >> 4);
	ds_ring_sz = sq->ring_entries;

	cxt->cxt_ctl->write_index_ptr = cpu_to_le64(write_index_ptr);
	cxt->cxt_ctl->cxt_sts_ptr     = cpu_to_le64(cxt_sts_ptr);
	cxt->cxt_ctl->ds_ring_sz      = cpu_to_le32(ds_ring_sz);

	/* turn it on now */
	sq->cxt = cxt;
	cxt->sq = sq;
	ds_ring_ptr = (FIELD_PREP(SDXI_CXT_CTL_DS_RING_PTR, sq->ring_dma >> 6) |
		       FIELD_PREP(SDXI_CXT_CTL_VL, 1));
	dma_wmb();
	WRITE_ONCE(cxt->cxt_ctl->ds_ring_ptr, cpu_to_le64(ds_ring_ptr));

	sdxi_dbg(sdxi, "sq created, id=%d, cxt_ctl=%p\n"
		 "  desc ring addr:   v=0x%p:d=%pad\n"
		 "  write index addr: v=0x%p:d=%pad\n"
		 "  cxt status addr: v=0x%p:d=%pad\n",
		 cxt->id, cxt->cxt_ctl,
		 sq->desc_ring, &sq->ring_dma,
		 sq->write_index, &sq->write_index_dma,
		 sq->cxt_sts, &sq->cxt_sts_dma);

	/* dump SQ info */
	trace_sdxi_create_sq(cxt, sq);

	return sq;

free_cxt_sts:
	dma_pool_free(sdxi->cxt_sts_pool, sq->cxt_sts, sq->cxt_sts_dma);
free_desc_ring:
	dma_free_coherent(dev, sq->ring_size, sq->desc_ring, sq->ring_dma);
free_sq:
	kfree(sq);
	return NULL;
}

static void sdxi_sq_free(struct sdxi_sq *sq)
{
	struct sdxi_cxt *cxt;
	struct sdxi_dev *sdxi;
	struct device *dev;

	if (!sq)
		return;

	cxt = sq->cxt;
	if (!cxt)
		return;

	sdxi = cxt->sdxi;
	dev = sdxi_to_dev(sdxi);

	trace_sdxi_free_sq(cxt, sq);

	dma_pool_free(sdxi->write_index_pool, sq->write_index, sq->write_index_dma);
	dma_pool_free(sdxi->cxt_sts_pool, sq->cxt_sts, sq->cxt_sts_dma);
	dma_free_coherent(dev, sq->ring_size, sq->desc_ring, sq->ring_dma);

	cxt->sq = NULL;
	kfree(sq);
}

/* Default size 1024 ==> 64KB descriptor ring, guaranteed */
#define DEFAULT_DESC_RING_ENTRIES	1024
static struct sdxi_sq *sdxi_sq_alloc_default(struct sdxi_cxt *cxt)
{
	return sdxi_sq_alloc(cxt, DEFAULT_DESC_RING_ENTRIES);
}

static bool sdxi_cxt_l2_ent_vl(const struct sdxi_cxt_l2_ent *ent)
{
	return FIELD_GET(SDXI_CXT_L2_ENT_VL, le64_to_cpu(ent->lv01_ptr));
}

static dma_addr_t sdxi_cxt_l2_ent_lv01_ptr(const struct sdxi_cxt_l2_ent *ent)
{
	return FIELD_GET(SDXI_CXT_L2_ENT_LV01_PTR, le64_to_cpu(ent->lv01_ptr)) << ilog2(SZ_4K);
}

static void set_cxt_l2_entry(struct sdxi_cxt_l2_ent *l2_entry,
			     dma_addr_t l1_table_dma)
{
	u64 lv01_ptr;

	/* We shouldn't be updating a live entry. */
	if (WARN_ON_ONCE(sdxi_cxt_l2_ent_vl(l2_entry)))
		return;
	/* L1 tables must be 4K-aligned. */
	if (WARN_ON_ONCE(!IS_ALIGNED(l1_table_dma, SZ_4K)))
		return;

	lv01_ptr = (FIELD_PREP(SDXI_CXT_L2_ENT_LV01_PTR,
				   l1_table_dma >> ilog2(SZ_4K)) |
		    FIELD_PREP(SDXI_CXT_L2_ENT_VL, 1));

	/*
	 * Ensure the valid bit update follows prior updates to other
	 * control structures.
	 */
	dma_wmb();
	WRITE_ONCE(l2_entry->lv01_ptr, cpu_to_le64(lv01_ptr));
}

static void set_cxt_l1_entry(struct sdxi_dev *sdxi,
			     struct sdxi_cxt_l1_ent *l1_entry,
			     struct sdxi_cxt *cxt)
{
	u64 ctl2;
	u8 max_buffer;
	u64 cxt_ctl_ptr;
	u64 akey_ptr;
	u16 intr_num;
	u32 misc0;
	bool pv;

	if (!cxt) {
		memset(l1_entry, 0, sizeof(*l1_entry));
		return;
	}

	pv = cxt->pasid_valid;

	ctl2 = sdxi_read64(sdxi, SDXI_MMIO_CTL2);
	max_buffer = FIELD_GET(SDXI_MMIO_CTL2_MAX_BUFFER, ctl2);

	cxt_ctl_ptr = (FIELD_PREP(SDXI_CXT_L1_ENT_VL, 1) |
		       FIELD_PREP(SDXI_CXT_L1_ENT_KA, 1) |
		       FIELD_PREP(SDXI_CXT_L1_ENT_PV, pv) |
		       FIELD_PREP(SDXI_CXT_L1_ENT_CXT_CTL_PTR,
				  cxt->cxt_ctl_dma >> L1_CXT_CTRL_PTR_SHIFT));
	akey_ptr = (FIELD_PREP(SDXI_CXT_L1_ENT_AKEY_SZ,
			       akey_table_order(cxt->akey_table)) |
		    FIELD_PREP(SDXI_CXT_L1_ENT_AKEY_PTR,
			       cxt->akey_table_dma >> L1_CXT_AKEY_PTR_SHIFT));
	misc0 = FIELD_PREP(SDXI_CXT_L1_ENT_MAX_BUFFER, max_buffer);
	if (pv)
		misc0 |= FIELD_PREP(SDXI_CXT_L1_ENT_PASID, cxt->pasid);

	*l1_entry = (struct sdxi_cxt_l1_ent) {
		.cxt_ctl_ptr = cpu_to_le64(cxt_ctl_ptr),
		.akey_ptr = cpu_to_le64(akey_ptr),
		.misc0 = cpu_to_le32(misc0),
		.opb_000_enb = cpu_to_le32(cxt->opb_000_enb),
	};

	intr_num = le16_to_cpu(cxt->akey_table->entry[0].intr_num);
	FIELD_MODIFY(SDXI_AKEY_ENT_VL, &intr_num, 1);
	cxt->akey_table->entry[0].intr_num = cpu_to_le16(intr_num);
}

static int config_cxt_tables(struct sdxi_dev *sdxi,
			     struct sdxi_cxt *cxt)
{
	struct sdxi_cxt_l1_table *l1_table;
	struct sdxi_cxt_l1_ent *l1_entry;
	u16 l2_idx;
	u8 l1_idx;

	l2_idx = ID_TO_L2_INDEX(cxt->id);
	l1_idx = ID_TO_L1_INDEX(cxt->id);

	/* Allocate L1 table if not present. */
	l1_table = sdxi->l1_table_array[l2_idx];
	if (!l1_table) {
		struct sdxi_cxt_l2_ent *l2_entry;
		dma_addr_t l1_table_dma;

		l1_table = dma_alloc_coherent(sdxi_to_dev(sdxi),
					      sizeof(*l1_table),
					      &l1_table_dma, GFP_KERNEL);
		if (!l1_table)
			return -ENOMEM;

		/* Track the L1 table vaddr. */
		sdxi->l1_table_array[l2_idx] = l1_table;

		/* Install the new entry in the L2 table. */
		l2_entry = &sdxi->l2_table->entry[l2_idx];
		set_cxt_l2_entry(l2_entry, l1_table_dma);
	}

	/* Populate the L1 entry. */
	l1_entry = &l1_table->entry[l1_idx];
	set_cxt_l1_entry(cxt->sdxi, l1_entry, cxt);

	return 0;
}

static void clear_cxt_table_entries(struct sdxi_cxt_l2_table *l2_table,
				    struct sdxi_cxt_l1_table *l1_table,
				    struct sdxi_cxt *cxt)
{
	struct sdxi_cxt_l2_ent *l2_entry;
	struct sdxi_cxt_l1_ent *l1_entry;
	struct sdxi_dev *sdxi = cxt->sdxi;
	dma_addr_t l1_dma;

	l2_entry = &l2_table->entry[ID_TO_L2_INDEX(cxt->id)];
	l1_entry = &l1_table->entry[ID_TO_L1_INDEX(cxt->id)];

	memset(l1_entry, 0, sizeof(*l1_entry));

	/* If this L1 table has been completely zeroed then free it. */
	if (memchr_inv(l1_table, 0, L1_TABLE_SIZE))
		return;

	l1_dma = sdxi_cxt_l2_ent_lv01_ptr(l2_entry);

	memset(l2_entry, 0, sizeof(*l2_entry));

	dma_free_coherent(sdxi_to_dev(sdxi), sizeof(*l1_table),
			  l1_table, l1_dma);
}

static void cleanup_cxt_tables(struct sdxi_dev *sdxi,
			       struct sdxi_cxt *cxt)
{
	u16 l2_idx;
	struct sdxi_cxt_l1_table *l1_table;

	if (!cxt)
		return;

	l2_idx = ID_TO_L2_INDEX(cxt->id);

	l1_table = sdxi->l1_table_array[l2_idx];
	/* clear l1 entry */
	clear_cxt_table_entries(sdxi->l2_table, l1_table, cxt);
}


static void free_admin_cxt(void *ptr)
{
	struct sdxi_dev *sdxi = ptr;

	sdxi_free_cxt(sdxi->admin_cxt);
}

int sdxi_admin_cxt_init(struct sdxi_dev *sdxi)
{
	int err;
	struct sdxi_sq *sq;

	struct sdxi_cxt *cxt __free(sdxi_cxt) = sdxi_alloc_cxt(sdxi);
	if (!cxt)
		return -ENOMEM;

	sq = cxt->sq;
	/* SDXI 1.0 4.1.8.4.b: Set CXT_STS.state to CXTV_RUN. */
	sq->cxt_sts->state = FIELD_PREP(SDXI_CXT_STS_STATE, CXTV_RUN);
	cxt->id = SDXI_ADMIN_CXT_ID;
	cxt->db = sdxi->dbs + cxt->id * sdxi->db_stride;
	sdxi_ring_state_init(cxt->ring_state, &sq->cxt_sts->read_index,
			     sq->write_index, sq->ring_entries, sq->desc_ring);
	ida_init(&cxt->akey_ida);

	err = sdxi_publish_cxt(cxt);
	if (err)
		return err;

	sdxi->admin_cxt = no_free_ptr(cxt);

	return devm_add_action_or_reset(sdxi->dev, free_admin_cxt, sdxi);
}

int sdxi_start_cxt(struct sdxi_cxt *cxt)
{
	struct sdxi_cxt *adm = to_admin_cxt(cxt);
	struct sdxi_desc *desc;
	struct sdxi_ring_resv resv;
	int err;

	might_sleep();

	struct sdxi_completion *sc __free(sdxi_completion) =
		sdxi_completion_alloc(cxt->sdxi);

	if (!sc)
		return -ENOMEM;

	/* This is not how to start the admin context. */
	if (WARN_ON(adm == cxt))
		return -EINVAL;

	err = sdxi_ring_reserve(adm->ring_state, 1, &resv);
	if (err)
		return err;

	desc = sdxi_ring_resv_next(&resv);
	sdxi_encode_cxt_start(desc, &(const struct sdxi_cxt_start) {
			.range = sdxi_cxt_range_single(cxt->id),
		});
	sdxi_completion_attach(desc, sc);
	sdxi_desc_make_valid(desc);
	sdxi_cxt_push_doorbell(adm, sdxi_ring_resv_dbval(&resv));

	return sdxi_completion_poll(sc);
}

void sdxi_stop_cxt(struct sdxi_cxt *cxt)
{
	struct sdxi_cxt *adm = to_admin_cxt(cxt);
	struct sdxi_desc *stop, *sync;
	struct sdxi_ring_resv resv;
	int err;

	might_sleep();

	struct sdxi_completion *sc __free(sdxi_completion) =
		sdxi_completion_alloc(cxt->sdxi);

	if (!sc)
		return;

	/* This is not how to stop the admin context. */
	if (WARN_ON(adm == cxt))
		return;

	err = sdxi_ring_reserve(adm->ring_state, 2, &resv);
	if (WARN_ON_ONCE(err))
		return;

	stop = sdxi_ring_resv_next(&resv);
	sync = sdxi_ring_resv_next(&resv);

	sdxi_encode_cxt_stop(stop, &(const struct sdxi_cxt_stop) {
			.range = sdxi_cxt_range_single(cxt->id),
		});
	sdxi_encode_sync(sync, &(const struct sdxi_sync) {
			.filter = SDXI_SYNC_FLT_STOP,
			.range = sdxi_cxt_range_single(cxt->id),
		});
	sdxi_completion_attach(sync, sc);
	sdxi_desc_make_valid(stop);
	sdxi_desc_make_valid(sync);
	sdxi_cxt_push_doorbell(adm, sdxi_ring_resv_dbval(&resv));

	WARN_ON(sdxi_completion_poll(sc));
}

/*
 * Temporary owner for context id until it can be assigned to a
 * context object; enables scope-based cleanup.
 */
struct sdxi_cxt_id {
	struct sdxi_dev *sdxi;
	u16 index;
};

static void sdxi_cxt_id_dtor(const struct sdxi_cxt_id *cxt_id)
{
	if (cxt_id->index == 0)
		return;
	WARN_ON(xa_erase(&cxt_id->sdxi->client_cxts, cxt_id->index) != NULL);
}

static struct sdxi_cxt_id sdxi_cxt_id_ctor(struct sdxi_dev *sdxi)
{
	struct xa_limit limit = XA_LIMIT(1, sdxi->max_cxtid);
	u32 index;

	return (struct sdxi_cxt_id) {
		.sdxi = sdxi,
		.index = xa_alloc(&sdxi->client_cxts, &index, NULL,
				  limit, GFP_KERNEL) ? 0 : (u16)index,
	};
}

DEFINE_CLASS(sdxi_cxt_id, struct sdxi_cxt_id, sdxi_cxt_id_dtor(&_T),
	     sdxi_cxt_id_ctor(sdxi), struct sdxi_dev *sdxi)

static bool sdxi_cxt_id_valid(const struct sdxi_cxt_id *cxt_id)
{
	return cxt_id->index > 0;
}

/*
 * Transfer ownership of the id to the context object, recording the
 * context pointer in the device's client_cxt xarray. sdxi_cxt_free()
 * is responsible for releasing the id from now on.
 */
static void sdxi_cxt_id_assign(struct sdxi_cxt *cxt, struct sdxi_cxt_id *cxt_id)
{
	/* We reserved the space in the constructor so this should not fail. */
	WARN_ON(xa_store(&cxt_id->sdxi->client_cxts,
			 cxt_id->index, cxt, GFP_KERNEL));
	cxt->id = cxt_id->index;
	cxt_id->index = 0;
}

/*
 * Allocate a context for in-kernel use. Starting the context is the
 * caller's responsibility.
 */
struct sdxi_cxt *sdxi_cxt_new(struct sdxi_dev *sdxi)
{
	struct sdxi_sq *sq;

	/*
	 * Ensure an ID is available before allocating memory for the
	 * context and its control structures.
	 */
	CLASS(sdxi_cxt_id, id)(sdxi);
	if (!sdxi_cxt_id_valid(&id))
		return NULL;

	struct sdxi_cxt *cxt __free(sdxi_cxt) = sdxi_alloc_cxt(sdxi);
	if (!cxt)
		return NULL;

	sdxi_cxt_id_assign(cxt, &id);

	cxt->db = sdxi->dbs + cxt->id * sdxi->db_stride;

	sq = cxt->sq;
	sdxi_ring_state_init(cxt->ring_state, &sq->cxt_sts->read_index,
			     sq->write_index, sq->ring_entries, sq->desc_ring);
	ida_init(&cxt->akey_ida);

	if (sdxi_publish_cxt(cxt))
		return NULL;

	return_ptr(cxt);
}

void sdxi_cxt_exit(struct sdxi_cxt *cxt)
{
	if (WARN_ON(sdxi_cxt_is_admin(cxt)))
		return;

	sdxi_rescind_cxt(cxt);
	sdxi_free_cxt(cxt);
}
