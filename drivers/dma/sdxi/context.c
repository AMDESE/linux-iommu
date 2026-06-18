// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI submission queue (sq) and descriptor management
 *
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt)     "SDXI: " fmt

#include <linux/delay.h>
#include <linux/dma-direction.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/types.h>
#include <linux/wordpart.h>

#include "admin.h"
#include "context.h"
#include "hw.h"
#include "intr.h"
#include "process.h"
#include "ring.h"
#include "sdxi.h"
#include "trace.h"

#define SDXI_CXT_QUIESCE_TIMEOUT_MS	5000U
#define SDXI_CXT_CLEANUP_RETRY_MS	100U

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

	sq = kzalloc_obj(*sq, GFP_KERNEL);
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

	if (!pv) {
		intr_num = le16_to_cpu(cxt->akey_table->entry[0].intr_num);
		FIELD_MODIFY(SDXI_AKEY_ENT_VL, &intr_num, 1);
		cxt->akey_table->entry[0].intr_num = cpu_to_le16(intr_num);
	}
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

static void clear_cxt_table_entries(struct sdxi_dev *sdxi,
				    struct sdxi_cxt_l1_table *l1_table,
				    struct sdxi_cxt *cxt)
{
	struct sdxi_cxt_l2_ent *l2_entry;
	struct sdxi_cxt_l1_ent *l1_entry;
	dma_addr_t l1_dma;
	u16 l2_idx;

	l2_idx = ID_TO_L2_INDEX(cxt->id);
	l2_entry = &sdxi->l2_table->entry[l2_idx];
	l1_entry = &l1_table->entry[ID_TO_L1_INDEX(cxt->id)];

	memset(l1_entry, 0, sizeof(*l1_entry));

	/* If this L1 table has been completely zeroed then free it. */
	if (memchr_inv(l1_table, 0, L1_TABLE_SIZE))
		return;

	l1_dma = sdxi_cxt_l2_ent_lv01_ptr(l2_entry);

	memset(l2_entry, 0, sizeof(*l2_entry));
	sdxi->l1_table_array[l2_idx] = NULL;

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
	if (!l1_table)
		return;

	clear_cxt_table_entries(sdxi, l1_table, cxt);
}

static bool sdxi_cxt_cleanup_requested(const struct sdxi_cxt *cxt)
{
	return cxt->handle_closed || cxt->mm_dead || READ_ONCE(cxt->fatal);
}

static void sdxi_cxt_release_memory(struct sdxi_cxt *cxt)
{
	WARN_ON_ONCE(!cxt->resources_released);
	mutex_destroy(&cxt->cleanup_lock);
	kfree(cxt);
}

void sdxi_cxt_get(struct sdxi_cxt *cxt)
{
	refcount_inc(&cxt->refs);
}

void sdxi_cxt_put(struct sdxi_cxt *cxt)
{
	if (!cxt)
		return;

	if (refcount_dec_and_test(&cxt->refs))
		sdxi_cxt_release_memory(cxt);
}

struct sdxi_cxt *sdxi_cxt_get_by_id(struct sdxi_dev *sdxi, u16 cxt_id)
{
	struct sdxi_cxt **row;
	struct sdxi_cxt *cxt = NULL;
	u16 l2_idx;
	u8 l1_idx;

	if (!sdxi)
		return NULL;

	l2_idx = ID_TO_L2_INDEX(cxt_id);
	l1_idx = ID_TO_L1_INDEX(cxt_id);

	mutex_lock(&sdxi->cxt_lock);
	row = sdxi->cxt_array[l2_idx];
	if (row) {
		cxt = row[l1_idx];
		if (cxt && cxt->id == cxt_id)
			sdxi_cxt_get(cxt);
		else
			cxt = NULL;
	}
	mutex_unlock(&sdxi->cxt_lock);

	return cxt;
}

static void sdxi_cxt_destroy_table_slot(struct sdxi_cxt *cxt)
{
	struct sdxi_dev *sdxi = cxt->sdxi;
	u16 l2_idx = ID_TO_L2_INDEX(cxt->id);
	u8 l1_idx = ID_TO_L1_INDEX(cxt->id);

	sdxi->cxt_count--;
	dma_free_coherent(sdxi_to_dev(sdxi), sizeof(*cxt->akey_table),
			  cxt->akey_table, cxt->akey_table_dma);
	cxt->akey_table = NULL;
	cxt->akey_table_dma = 0;
	kfree(cxt->ring_state);
	cxt->ring_state = NULL;

	(sdxi->cxt_array)[l2_idx][l1_idx] = NULL;
}

static void sdxi_cxt_release_resources(struct sdxi_cxt *cxt)
{
	struct sdxi_dev *sdxi = cxt->sdxi;

	trace_sdxi_free_cxt(sdxi, cxt);

	mutex_lock(&sdxi->cxt_lock);
	cleanup_cxt_tables(sdxi, cxt);
	if (cxt->cxt_ctl) {
		dma_pool_free(sdxi->cxt_ctl_pool, cxt->cxt_ctl, cxt->cxt_ctl_dma);
		cxt->cxt_ctl = NULL;
		cxt->cxt_ctl_dma = 0;
	}
	sdxi_cxt_destroy_table_slot(cxt);
	mutex_unlock(&sdxi->cxt_lock);
}

static int sdxi_cxt_quiesce_locked(struct sdxi_cxt *cxt,
				   unsigned int timeout_ms, u32 *cst_flags,
				   bool interruptible)
{
	u32 flags = 0;
	int err = 0;

	if (cxt->resources_released)
		return -ENODEV;

	if (cxt->quiesced) {
		if (cst_flags)
			*cst_flags = 0;
		return 0;
	}

	if (!timeout_ms)
		timeout_ms = SDXI_CXT_QUIESCE_TIMEOUT_MS;

	if (!sdxi_cxt_is_admin(cxt))
		err = sdxi_adm_stop_cxt_sync(cxt, timeout_ms, &flags,
					     interruptible);

	if (err)
		return err;

	cxt->quiesced = true;
	cxt->quiesce_cst_flags = flags;
	if (cst_flags)
		*cst_flags = flags;

	return 0;
}

static void sdxi_cxt_cleanup_workfn(struct work_struct *work)
{
	struct sdxi_cxt *cxt = container_of(to_delayed_work(work),
					     struct sdxi_cxt, cleanup_work);
	struct sdxi_process *process = NULL;
	struct iommu_sva *sva = NULL;
	u32 pasid = 0;
	bool destroy = false;
	bool retry = false;

	mutex_lock(&cxt->cleanup_lock);

	if (cxt->resources_released || !sdxi_cxt_cleanup_requested(cxt))
		goto out_unlock;

	if (!cxt->quiesced) {
		if (sdxi_cxt_quiesce_locked(cxt, 0, NULL, false)) {
			retry = true;
			goto out_unlock;
		}
	}

	if (cxt->vma_refs)
		goto out_unlock;

	WRITE_ONCE(cxt->resources_released, true);
	process = cxt->process;
	cxt->process = NULL;
	destroy = true;

out_unlock:
	mutex_unlock(&cxt->cleanup_lock);

	if (retry) {
		mod_delayed_work(system_wq, &cxt->cleanup_work,
				 msecs_to_jiffies(SDXI_CXT_CLEANUP_RETRY_MS));
		return;
	}

	if (!destroy)
		return;

	wake_up_poll(&cxt->poll_wq, EPOLLHUP);

	sdxi_cxt_exit_intr(cxt);
	sdxi_sq_free(cxt->sq);

	if (process) {
		mutex_lock(&process->mutex);
		if (process->cxt == cxt)
			process->cxt = NULL;
		sva = sdxi_process_detach_sva_locked(process, &pasid);
		mutex_unlock(&process->mutex);

		sdxi_process_unbind_sva(process, sva, pasid);
		sdxi_put_process(process);
	}

	sdxi_cxt_release_resources(cxt);
	sdxi_cxt_put(cxt);
}

static struct sdxi_cxt *alloc_cxt(struct sdxi_dev *sdxi, bool admin)
{
	struct sdxi_cxt *cxt;
	u16 id, start_id, l2_idx, l1_idx;
	u32 max_cxts;

	max_cxts = 1 + FIELD_GET(SDXI_MMIO_CTL2_MAX_CXT,
				 sdxi_read64(sdxi, SDXI_MMIO_CTL2));

	if (sdxi->cxt_count >= max_cxts)
		return NULL;

	/*
	 * Context id 0 is the kernel-only admin context. Reserve it so that
	 * only callers that explicitly ask for the admin context (admin == true)
	 * can ever land in slot 0. All other in-kernel and user-visible
	 * contexts must allocate from id 1 onwards.
	 */
	start_id = admin ? SDXI_ADMIN_CXT_ID : SDXI_ADMIN_CXT_ID + 1;
	if (start_id >= max_cxts)
		return NULL;

	/* search for an empty context slot */
	for (id = start_id; id < max_cxts; id++) {
		l2_idx = ID_TO_L2_INDEX(id);
		l1_idx = ID_TO_L1_INDEX(id);

		if (sdxi->cxt_array[l2_idx] == NULL) {
			struct sdxi_cxt **ptr;

			ptr = kcalloc(L1_TABLE_ENTRIES, sizeof(ptr[0]),
				      GFP_KERNEL);
			if (!ptr)
				return NULL;
			sdxi->cxt_array[l2_idx] = ptr;
		}

		cxt = (sdxi->cxt_array)[l2_idx][l1_idx];
		/* found one empty slot */
		if (!cxt)
			break;
	}

	/* nothing found, bail... */
	if (id == max_cxts)
		return NULL;

	/*
	 * Defensive: never hand out id 0 unless the caller is the admin
	 * bring-up path. The loop above already enforces this via start_id,
	 * but the check guards against future regressions.
	 */
	if (WARN_ON_ONCE(id == SDXI_ADMIN_CXT_ID && !admin))
		return NULL;

	cxt = kzalloc_obj(*cxt, GFP_KERNEL);
	if (!cxt)
		return NULL;

	cxt->akey_table = dma_alloc_coherent(sdxi_to_dev(sdxi),
					     sizeof(*cxt->akey_table),
					     &cxt->akey_table_dma, GFP_KERNEL);
	if (!cxt->akey_table) {
		kfree(cxt);
		return NULL;
	}

	cxt->sdxi = sdxi;
	refcount_set(&cxt->refs, 1);
	mutex_init(&cxt->cleanup_lock);
	init_waitqueue_head(&cxt->poll_wq);
	mutex_init(&cxt->akey_lock);
	spin_lock_init(&cxt->intr_lock);
	INIT_DELAYED_WORK(&cxt->cleanup_work, sdxi_cxt_cleanup_workfn);
	cxt->id = id;
	cxt->mmap_gen = ++sdxi->mmap_gen_ctr;
	if (unlikely(!cxt->mmap_gen))
		cxt->mmap_gen = ++sdxi->mmap_gen_ctr;
	cxt->db_base = sdxi->dbs_bar + id * sdxi->db_stride;
	cxt->db = sdxi->dbs + id * sdxi->db_stride;

	sdxi->cxt_array[l2_idx][l1_idx] = cxt;
	sdxi->cxt_count++;

	return cxt;
}

static void free_cxt(struct sdxi_cxt *cxt)
{
	struct sdxi_dev *sdxi = cxt->sdxi;
	u16 l2_idx, l1_idx;

	l2_idx = ID_TO_L2_INDEX(cxt->id);
	l1_idx = ID_TO_L1_INDEX(cxt->id);

	sdxi->cxt_count--;
	dma_free_coherent(sdxi_to_dev(sdxi), sizeof(*cxt->akey_table),
			  cxt->akey_table, cxt->akey_table_dma);
	kfree(cxt->ring_state);
	cancel_delayed_work_sync(&cxt->cleanup_work);
	mutex_destroy(&cxt->akey_lock);
	mutex_destroy(&cxt->cleanup_lock);
	kfree(cxt);

	(sdxi->cxt_array)[l2_idx][l1_idx] = NULL;
}

/* alloc context resources and populate context table */
static struct sdxi_cxt *sdxi_cxt_alloc(struct sdxi_dev *sdxi, bool admin,
				       bool pasid_valid, u32 pasid,
				       u32 opb_000_enb)
{
	struct sdxi_cxt *cxt;
	u64 ctl2;
	u32 opb_000_avl;
	u8 max_akey_sz;

	mutex_lock(&sdxi->cxt_lock);

	cxt = alloc_cxt(sdxi, admin);
	if (!cxt)
		goto drop_cxt_lock;

	cxt->cxt_ctl = dma_pool_zalloc(sdxi->cxt_ctl_pool, GFP_KERNEL,
				       &cxt->cxt_ctl_dma);
	if (!cxt->cxt_ctl)
		goto release_cxt;

	cxt->ring_state = kzalloc_obj(*cxt->ring_state, GFP_KERNEL);
	if (!cxt->ring_state)
		goto release_cxt_ctl;

	cxt->pasid_valid = pasid_valid;
	cxt->pasid = pasid;
	cxt->opb_000_enb = opb_000_enb & sdxi->op_grp_cap;

	ctl2 = sdxi_read64(sdxi, SDXI_MMIO_CTL2);
	opb_000_avl = FIELD_GET(SDXI_MMIO_CTL2_OPB_000_AVL, ctl2);
	max_akey_sz = FIELD_GET(SDXI_MMIO_CTL2_MAX_AKEY_SZ, ctl2);
	if (cxt->opb_000_enb & ~opb_000_avl)
		goto release_ring_state;
	if (akey_table_order(cxt->akey_table) > max_akey_sz)
		goto release_ring_state;

	if (config_cxt_tables(sdxi, cxt))
		goto release_ring_state;

	trace_sdxi_create_cxt(sdxi, cxt);
	mutex_unlock(&sdxi->cxt_lock);
	return cxt;

release_ring_state:
	kfree(cxt->ring_state);
release_cxt_ctl:
	dma_pool_free(sdxi->cxt_ctl_pool, cxt->cxt_ctl, cxt->cxt_ctl_dma);
release_cxt:
	free_cxt(cxt);
drop_cxt_lock:
	mutex_unlock(&sdxi->cxt_lock);
	return NULL;
}

struct sdxi_cxt *sdxi_working_cxt_init(struct sdxi_dev *sdxi,
				       enum sdxi_cxt_id id)
{
	struct sdxi_cxt *cxt;
	struct sdxi_sq *sq;
	bool admin;

	switch (id) {
	case SDXI_ANY_CXT_ID:  /* User context */
		admin = false;
		break;
	default:  /* kernel context */
		admin = (id == SDXI_ADMIN_CXT_ID);
		break;
	}

	cxt = sdxi_cxt_alloc(sdxi, admin, false, 0, sdxi->op_grp_cap);
	if (!cxt) {
		sdxi_err(sdxi, "failed to alloc a new context\n");
		return NULL;
	}

	/* check if context ID matches */
	if (id < SDXI_ANY_CXT_ID && cxt->id != id) {
		sdxi_err(sdxi, "failed to alloc a context with id=%d\n", id);
		goto err_cxt_id;
	}

	sq = sdxi_sq_alloc_default(cxt);
	if (!sq) {
		sdxi_err(sdxi, "failed to alloc a submission queue (sq)\n");
		goto err_sq_alloc;
	}

	sdxi_ring_state_init(cxt->ring_state, &sq->cxt_sts->read_index,
			     sq->write_index, sq->ring_entries, sq->desc_ring);

	if (id == SDXI_ADMIN_CXT_ID)
		cxt->started = true;

	return cxt;

err_sq_alloc:
err_cxt_id:
	sdxi_working_cxt_exit(cxt);

	return NULL;
}

/*
 * Allocate a context for in-kernel use. Starting the context is the
 * caller's responsibility.
 */
struct sdxi_cxt *sdxi_kcxt_new(struct sdxi_dev *sdxi)
{
	struct sdxi_cxt *cxt = sdxi_cxt_alloc(sdxi, false, false, 0,
					      sdxi->op_grp_cap);
	struct sdxi_sq *sq;

	if (!cxt)
		return NULL;

	sq = sdxi_sq_alloc_default(cxt);
	if (!sq) {
		sdxi_working_cxt_exit(cxt);
		return NULL;
	}

	sdxi_ring_state_init(cxt->ring_state, &sq->cxt_sts->read_index,
			     sq->write_index, sq->ring_entries, sq->desc_ring);

	return cxt;
}

struct sdxi_cxt *sdxi_ucxt_new(struct sdxi_dev *sdxi, u32 ring_entries,
			       u64 ds_ring, u64 write_index, u64 cxt_sts,
			       u32 pasid, u32 opb_000_enb)
{
	struct sdxi_cxt *cxt;
	u64 write_index_ptr;
	u64 cxt_sts_ptr;
	u64 ds_ring_ptr;

	cxt = sdxi_cxt_alloc(sdxi, false, true, pasid, opb_000_enb);
	if (!cxt)
		return NULL;

	write_index_ptr = FIELD_PREP(SDXI_CXT_CTL_WRITE_INDEX_PTR,
				     write_index >> WRT_INDEX_PTR_SHIFT);
	cxt_sts_ptr = FIELD_PREP(SDXI_CXT_CTL_CXT_STS_PTR,
				 cxt_sts >> CXT_STATUS_PTR_SHIFT);
	cxt->cxt_ctl->write_index_ptr = cpu_to_le64(write_index_ptr);
	cxt->cxt_ctl->cxt_sts_ptr     = cpu_to_le64(cxt_sts_ptr);
	cxt->cxt_ctl->ds_ring_sz      = cpu_to_le32(ring_entries);

	/*
	 * Set ds_ring_ptr and its valid bit last, after all prior
	 * updates to the control hierarchy are visible to the device.
	 */
	ds_ring_ptr = (FIELD_PREP(SDXI_CXT_CTL_DS_RING_PTR,
				  ds_ring >> DESC_RING_BASE_PTR_SHIFT) |
		       FIELD_PREP(SDXI_CXT_CTL_VL, 1));
	dma_wmb();
	WRITE_ONCE(cxt->cxt_ctl->ds_ring_ptr, cpu_to_le64(ds_ring_ptr));

	return cxt;
}

static const char *cxt_sts_state_str(enum cxt_sts_state state)
{
	static const char *const context_states[] = {
		[CXTV_STOP_SW]  = "stopped (software)",
		[CXTV_RUN]      = "running",
		[CXTV_STOPG_SW] = "stopping (software)",
		[CXTV_STOP_FN]  = "stopped (function)",
		[CXTV_STOPG_FN] = "stopping (function)",
		[CXTV_ERR_FN]   = "error",
	};
	const char *str = "unknown";

	switch (state) {
	case CXTV_STOP_SW:
	case CXTV_RUN:
	case CXTV_STOPG_SW:
	case CXTV_STOP_FN:
	case CXTV_STOPG_FN:
	case CXTV_ERR_FN:
		str = context_states[state];
	}

	return str;
}

void sdxi_working_cxt_exit(struct sdxi_cxt *cxt)
{
	struct sdxi_process *process = NULL;
	struct iommu_sva *sva = NULL;
	u32 pasid = 0;

	if (!cxt)
		return;

	cancel_delayed_work_sync(&cxt->cleanup_work);

	mutex_lock(&cxt->cleanup_lock);
	if (cxt->resources_released) {
		mutex_unlock(&cxt->cleanup_lock);
		return;
	}

	if (!cxt->quiesced)
		(void)sdxi_cxt_quiesce_locked(cxt, 0, NULL, false);

	WRITE_ONCE(cxt->resources_released, true);
	process = cxt->process;
	cxt->process = NULL;
	mutex_unlock(&cxt->cleanup_lock);

	wake_up_poll(&cxt->poll_wq, EPOLLHUP);

	sdxi_cxt_exit_intr(cxt);
	sdxi_sq_free(cxt->sq);

	if (process) {
		mutex_lock(&process->mutex);
		if (process->cxt == cxt)
			process->cxt = NULL;
		sva = sdxi_process_detach_sva_locked(process, &pasid);
		mutex_unlock(&process->mutex);

		sdxi_process_unbind_sva(process, sva, pasid);
		sdxi_put_process(process);
	}

	sdxi_cxt_release_resources(cxt);
	sdxi_cxt_put(cxt);
}

int sdxi_cxt_quiesce(struct sdxi_cxt *cxt, unsigned int timeout_ms,
		     u32 *cst_flags)
{
	int err;
	bool schedule = false;

	if (!cxt)
		return -EINVAL;

	mutex_lock(&cxt->cleanup_lock);
	err = sdxi_cxt_quiesce_locked(cxt, timeout_ms, cst_flags, true);
	if (!err && !cxt->resources_released && sdxi_cxt_cleanup_requested(cxt))
		schedule = true;
	mutex_unlock(&cxt->cleanup_lock);

	if (schedule)
		mod_delayed_work(system_wq, &cxt->cleanup_work, 0);

	return err;
}

bool sdxi_cxt_is_user(const struct sdxi_cxt *cxt)
{
	if (!cxt)
		return false;

	return cxt->id != SDXI_ADMIN_CXT_ID &&
	       READ_ONCE(cxt->pasid_valid) &&
	       READ_ONCE(cxt->process);
}

bool sdxi_cxt_is_fatal(const struct sdxi_cxt *cxt)
{
	if (!cxt)
		return true;

	return READ_ONCE(cxt->fatal);
}

void sdxi_cxt_kill(struct sdxi_cxt *cxt)
{
	if (!cxt)
		return;

	if (READ_ONCE(cxt->fatal))
		return;

	WRITE_ONCE(cxt->fatal, true);
	wake_up_poll(&cxt->poll_wq, EPOLLERR);
	mod_delayed_work(system_wq, &cxt->cleanup_work, 0);
}

void sdxi_cxt_release_user_handle(struct sdxi_cxt *cxt)
{
	bool schedule = false;

	if (!cxt)
		return;

	mutex_lock(&cxt->cleanup_lock);
	cxt->handle_closed = true;
	if (!cxt->resources_released)
		schedule = true;
	mutex_unlock(&cxt->cleanup_lock);

	if (schedule)
		mod_delayed_work(system_wq, &cxt->cleanup_work, 0);
}

int sdxi_cxt_notify_mm_release(struct sdxi_cxt *cxt)
{
	bool schedule = false;
	int err = 0;

	if (!cxt)
		return -EINVAL;

	mutex_lock(&cxt->cleanup_lock);
	cxt->mm_dead = true;
	/*
	 * mmu_notifier->release must freeze the device's secondary MMU view
	 * before returning, otherwise the hardware can keep walking user VA
	 * while exit_mmap tears the address space down underneath it.
	 */
	if (!cxt->resources_released) {
		err = sdxi_cxt_quiesce_locked(cxt, 0, NULL, false);
		schedule = true;
	}
	mutex_unlock(&cxt->cleanup_lock);

	if (schedule)
		mod_delayed_work(system_wq, &cxt->cleanup_work, 0);

	return err;
}

void sdxi_cxt_vma_open(struct sdxi_cxt *cxt)
{
	if (!cxt)
		return;

	sdxi_cxt_get(cxt);
	mutex_lock(&cxt->cleanup_lock);
	cxt->vma_refs++;
	mutex_unlock(&cxt->cleanup_lock);
}

void sdxi_cxt_vma_close(struct sdxi_cxt *cxt)
{
	bool schedule = false;

	if (!cxt)
		return;

	mutex_lock(&cxt->cleanup_lock);
	if (WARN_ON_ONCE(!cxt->vma_refs))
		goto out_unlock;

	cxt->vma_refs--;
	if (!cxt->resources_released && sdxi_cxt_cleanup_requested(cxt))
		schedule = true;

out_unlock:
	mutex_unlock(&cxt->cleanup_lock);

	if (schedule)
		mod_delayed_work(system_wq, &cxt->cleanup_work, 0);

	sdxi_cxt_put(cxt);
}

void sdxi_cxt_push_doorbell(struct sdxi_cxt *cxt, u64 index)
{
	enum cxt_sts_state state = sdxi_cxt_sts_state(cxt->sq->cxt_sts);

	/*
	 * To do: cache doorbell values as they're written to
	 * eliminate redundant doorbell writes.
	 */

	/* Ensure write index is visible. */
	dma_wmb();
	sdxi_dbg(cxt->sdxi, "Ringing context %u (state = %s) doorbell: %llu\n",
		 cxt->id, cxt_sts_state_str(state), index);
	iowrite64(index, cxt->db);
}
