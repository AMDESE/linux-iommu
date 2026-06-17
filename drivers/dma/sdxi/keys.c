// SPDX-License-Identifier: GPL-2.0-only
/*
 * Key table management (AKey/RKey) and key-related IOCTLs.
 *
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#include <linux/bitops.h>
#include <linux/bitfield.h>
#include <linux/capability.h>
#include <linux/dma-mapping.h>
#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include <uapi/linux/sdxi.h>

#include "admin.h"
#include "context.h"
#include "intr.h"
#include "ioctl.h"
#include "keys.h"
#include "process.h"
#include "sdxi.h"

static u32 sdxi_key_bitmap_bytes(u32 nentries)
{
	return DIV_ROUND_UP(nentries, 8);
}

static bool sdxi_key_entry_vl(const void *entry)
{
	__le16 intr_num;

	memcpy(&intr_num, entry, sizeof(intr_num));

	return le16_to_cpu(intr_num) & BIT(0);
}

static u32 sdxi_key_table_count_valid(const void *table, u32 nentries,
				      size_t stride)
{
	u32 count = 0;
	u32 i;

	for (i = 0; i < nentries; i++) {
		const u8 *entry = (const u8 *)table + i * stride;

		if (sdxi_key_entry_vl(entry))
			count++;
	}

	return count;
}

static u32 sdxi_key_table_build_bitmap(__u8 *bitmap, u32 nentries,
				       const void *table, size_t stride)
{
	u32 count = 0;
	u32 bytes = sdxi_key_bitmap_bytes(nentries);
	u32 i;

	memset(bitmap, 0, bytes);

	for (i = 0; i < nentries; i++) {
		const u8 *entry = (const u8 *)table + i * stride;

		if (!sdxi_key_entry_vl(entry))
			continue;

		count++;
		bitmap[i / 8] |= BIT(i % 8);
	}

	return count;
}

static int sdxi_rkey_ent_validate(const struct sdxi_rkey_ent *ent)
{
	u16 intr = le16_to_cpu(ent->intr_num);
	u32 pasid = le32_to_cpu(ent->pasid);

	if (intr & BIT(15))
		return -EINVAL;

	if (pasid & ~(SDXI_RKEY_ENT_PASID | SDXI_RKEY_ENT_PR | SDXI_RKEY_ENT_PH))
		return -EINVAL;

	if (memchr_inv(ent->rsvd_0, 0, sizeof(ent->rsvd_0)))
		return -EINVAL;

	return 0;
}

static void sdxi_rkey_ent_store(struct sdxi_rkey_ent *dst,
				const struct sdxi_rkey_ent *src)
{
	u16 intr = le16_to_cpu(src->intr_num);
	struct sdxi_rkey_ent tmp = *src;

	/*
	 * Keep the entry invalid while updating fields; set the valid bit last.
	 */
	tmp.intr_num = cpu_to_le16(intr & ~SDXI_RKEY_ENT_VL);
	memcpy(dst, &tmp, sizeof(tmp));
	dma_wmb();
	WRITE_ONCE(dst->intr_num, src->intr_num);
}

static int sdxi_akey_ent_validate(const struct sdxi_akey_ent *ent)
{
	u16 intr = le16_to_cpu(ent->intr_num);
	u32 pasid = le32_to_cpu(ent->pasid);

	if (intr & BIT(15))
		return -EINVAL;

	if (pasid & ~(SDXI_AKEY_ENT_PASID | SDXI_AKEY_ENT_PR | SDXI_AKEY_ENT_PH))
		return -EINVAL;

	if (memchr_inv(ent->rsvd_0, 0, sizeof(ent->rsvd_0)))
		return -EINVAL;
	if (memchr_inv(ent->rsvd_1, 0, sizeof(ent->rsvd_1)))
		return -EINVAL;

	return 0;
}

static int sdxi_akey_ent_validate_user(const struct sdxi_cxt *cxt,
				       const struct sdxi_akey_ent *ent)
{
	u16 intr = le16_to_cpu(ent->intr_num);
	u32 pasid = le32_to_cpu(ent->pasid);

	if (!(intr & SDXI_AKEY_ENT_VL)) {
		if (intr || ent->tgt_sfunc || pasid || ent->stag || ent->rkey)
			return -EINVAL;
		return 0;
	}

	if (ent->tgt_sfunc)
		return -EPERM;
	if (!(intr & SDXI_AKEY_ENT_PV))
		return -EPERM;
	if (intr & SDXI_AKEY_ENT_STE)
		return -EPERM;
	if (FIELD_GET(SDXI_AKEY_ENT_PASID, pasid) != cxt->pasid)
		return -EPERM;
	if (pasid & SDXI_AKEY_ENT_PR)
		return -EPERM;
	if (pasid & SDXI_AKEY_ENT_PH)
		return -EPERM;
	if (le16_to_cpu(ent->stag))
		return -EPERM;
	if (ent->rkey)
		return -EPERM;
	if (!(intr & SDXI_AKEY_ENT_IV) &&
	    FIELD_GET(SDXI_AKEY_ENT_INTR_NUM, intr))
		return -EINVAL;

	return 0;
}

static bool sdxi_akey_ent_iv(const struct sdxi_akey_ent *ent)
{
	return le16_to_cpu(ent->intr_num) & SDXI_AKEY_ENT_IV;
}

static u32 sdxi_akey_ent_intr_num(const struct sdxi_akey_ent *ent)
{
	return FIELD_GET(SDXI_AKEY_ENT_INTR_NUM, le16_to_cpu(ent->intr_num));
}

static bool sdxi_akey_index_driver_owned(const struct sdxi_cxt *cxt,
					 u32 index)
{
	u16 intr_akey;

	if (index == 0 || index == 1)
		return true;

	intr_akey = READ_ONCE(cxt->intr_akey);
	return intr_akey && index == intr_akey;
}

static void sdxi_akey_ent_store(struct sdxi_akey_ent *dst,
				const struct sdxi_akey_ent *src)
{
	u16 intr = le16_to_cpu(src->intr_num);
	struct sdxi_akey_ent tmp = *src;

	/*
	 * Keep the entry invalid while updating fields; set the valid bit last.
	 */
	tmp.intr_num = cpu_to_le16(intr & ~SDXI_AKEY_ENT_VL);
	memcpy(dst, &tmp, sizeof(tmp));
	dma_wmb();
	WRITE_ONCE(dst->intr_num, src->intr_num);
}

int sdxi_keys_init(struct sdxi_dev *sdxi, u64 cap1)
{
	u64 reg;

	if (!sdxi)
		return -ENODEV;

	sdxi->rkey_cap = FIELD_GET(SDXI_MMIO_CAP1_RKEY_CAP, cap1);
	if (!sdxi->rkey_cap)
		return 0;

	sdxi->rkey_order = 0;
	sdxi->rkey_entries = (SZ_4K << sdxi->rkey_order) /
			     sizeof(*sdxi->rkey_table);

	sdxi->rkey_table = dmam_alloc_coherent(sdxi_to_dev(sdxi),
					       SZ_4K << sdxi->rkey_order,
					       &sdxi->rkey_table_dma,
					       GFP_KERNEL);
	if (!sdxi->rkey_table)
		return -ENOMEM;

	memset(sdxi->rkey_table, 0, SZ_4K << sdxi->rkey_order);

	reg = FIELD_PREP(SDXI_MMIO_RKEY_PTR,
			 sdxi->rkey_table_dma >> ilog2(SZ_4K)) |
	      FIELD_PREP(SDXI_MMIO_RKEY_SZ, sdxi->rkey_order) |
	      FIELD_PREP(SDXI_MMIO_RKEY_EN, 1);
	sdxi_write64(sdxi, SDXI_MMIO_RKEY, reg);

	return 0;
}

void sdxi_keys_exit(struct sdxi_dev *sdxi)
{
	if (!sdxi)
		return;

	if (sdxi->rkey_cap)
		sdxi_write64(sdxi, SDXI_MMIO_RKEY, 0);

	sdxi->rkey_table = NULL;
	sdxi->rkey_table_dma = 0;
	sdxi->rkey_entries = 0;
	sdxi->rkey_order = 0;
	sdxi->rkey_cap = 0;
}

/* Default per-call timeout for SET_*KEYS admin DSC_KEY_UPD + SYNC. */
#define SDXI_KEY_DEFAULT_TIMEOUT_MS	5000U

/*
 * Shared helpers used by both the RKey (per-device) and AKey (per-context)
 * ioctls. The two paths now exchange identical wire structs
 * (struct sdxi_key_{list,get_keys,set_keys}_args, struct sdxi_key_entry);
 * the table being addressed is identified by the ioctl number alone.
 */

/* Header validation common to GET_LIST / GET_KEYS / SET_KEYS. */
static int sdxi_key_args_check_hdr(u32 argsz, size_t min_argsz,
				   u32 flags, const u32 *rsvd,
				   size_t rsvd_words)
{
	size_t i;

	if (argsz < min_argsz)
		return -EINVAL;

	if (flags)
		return -EINVAL;

	for (i = 0; i < rsvd_words; i++)
		if (rsvd[i])
			return -EINVAL;

	return 0;
}

/*
 * Fill the validity bitmap for a key table. Returns 0 on success, -ENOSPC
 * if the user buffer is too small (in which case @buf_size, @nentries and
 * @nvalid still get updated so the caller can resize and retry).
 */
static int sdxi_key_list_fill(struct sdxi_key_list_args *args,
			      const void *table, size_t stride, u32 nentries)
{
	u32 available = args->buf_size;
	u32 required = sdxi_key_bitmap_bytes(nentries);

	args->argsz = sizeof(*args);
	args->nentries = nentries;
	args->buf_size = required;
	args->nvalid = sdxi_key_table_count_valid(table, nentries, stride);

	if (available < required)
		return -ENOSPC;

	args->nvalid = sdxi_key_table_build_bitmap(args->data, nentries,
						   table, stride);
	return 0;
}

/*
 * Validate per-entry index/reserved fields and (optionally) compute the
 * min/max touched index for the post-write admin SYNC range.
 */
static int sdxi_key_check_indices(const struct sdxi_key_entry *entries,
				  u32 nkeys, u32 nentries,
				  u16 *out_min, u16 *out_max)
{
	u16 key_min = U16_MAX;
	u16 key_max = 0;
	u32 i;

	for (i = 0; i < nkeys; i++) {
		const struct sdxi_key_entry *entry = &entries[i];

		if (entry->rsvd0)
			return -EINVAL;
		if (entry->index >= nentries)
			return -EINVAL;

		if (entry->index < key_min)
			key_min = entry->index;
		if (entry->index > key_max)
			key_max = entry->index;
	}

	if (out_min)
		*out_min = key_min;
	if (out_max)
		*out_max = key_max;

	return 0;
}

/*
 * Initialize the kernel-output bookkeeping in struct sdxi_set_keys_args.
 * The dispatcher already zeroes @data, but be defensive since handlers
 * may bail out at any point.
 */
static void sdxi_set_keys_init_status(struct sdxi_set_keys_args *args)
{
	args->cst_flags = 0;
	args->commit_state = SDXI_KEY_COMMIT_NONE;
	args->first_failed_index = 0;
}

static unsigned int sdxi_set_keys_timeout(const struct sdxi_set_keys_args *args)
{
	if (args->timeout_ms == SDXI_KEY_TIMEOUT_DEFAULT)
		return SDXI_KEY_DEFAULT_TIMEOUT_MS;
	return args->timeout_ms;
}

int sdxi_ioctl_get_rkey_list(struct file *filep, struct sdxi_file *sf,
			     void *data)
{
	struct sdxi_key_list_args *args = data;
	struct sdxi_process *p;
	struct sdxi_dev *sdxi;
	int err;

	if (!sf || !sf->process)
		return -EINVAL;

	p = sf->process;

	err = sdxi_key_args_check_hdr(args->argsz, sizeof(*args), args->flags,
				      &args->rsvd0, 1);
	if (err)
		return err;

	sdxi = p->sdxi;
	if (!sdxi)
		return -ENODEV;

	if (!sdxi->rkey_cap)
		return -EOPNOTSUPP;

	if (!sdxi->rkey_table || !sdxi->rkey_entries)
		return -ENODEV;

	mutex_lock(&sdxi->rkey_lock);
	err = sdxi_key_list_fill(args, sdxi->rkey_table,
				 sizeof(*sdxi->rkey_table),
				 sdxi->rkey_entries);
	mutex_unlock(&sdxi->rkey_lock);

	return err;
}

int sdxi_ioctl_get_rkeys(struct file *filep, struct sdxi_file *sf,
			 void *data)
{
	struct sdxi_get_keys_args *args = data;
	struct sdxi_process *p;
	struct sdxi_dev *sdxi;
	u32 nkeys;
	u32 i;
	int err;

	if (!sf || !sf->process)
		return -EINVAL;

	p = sf->process;

	err = sdxi_key_args_check_hdr(args->argsz, sizeof(*args), args->flags,
				      &args->rsvd0, 1);
	if (err)
		return err;

	sdxi = p->sdxi;
	if (!sdxi)
		return -ENODEV;

	if (!sdxi->rkey_cap)
		return -EOPNOTSUPP;

	if (!sdxi->rkey_table || !sdxi->rkey_entries)
		return -ENODEV;

	nkeys = args->nkeys;
	if (nkeys > sdxi->rkey_entries)
		return -EINVAL;

	args->argsz = sizeof(*args);

	err = sdxi_key_check_indices(args->entries, nkeys, sdxi->rkey_entries,
				     NULL, NULL);
	if (err)
		return err;

	mutex_lock(&sdxi->rkey_lock);
	for (i = 0; i < nkeys; i++) {
		struct sdxi_key_entry *entry = &args->entries[i];

		memcpy(entry->data, &sdxi->rkey_table[entry->index],
		       sizeof(entry->data));
	}
	mutex_unlock(&sdxi->rkey_lock);

	/* Every requested entry was populated; @nkeys is unchanged. */
	return 0;
}

int sdxi_ioctl_set_rkeys(struct file *filep, struct sdxi_file *sf,
			 void *data)
{
	struct sdxi_set_keys_args *args = data;
	struct sdxi_process *p;
	struct sdxi_dev *sdxi;
	u32 nkeys;
	u32 i;
	u16 key_min;
	u16 key_max;
	int err;

	if (!sf || !sf->process)
		return -EINVAL;

	p = sf->process;

	err = sdxi_key_args_check_hdr(args->argsz, sizeof(*args), args->flags,
				      args->rsvd0,
				      ARRAY_SIZE(args->rsvd0));
	if (err)
		return err;

	args->argsz = sizeof(*args);
	sdxi_set_keys_init_status(args);

	sdxi = p->sdxi;
	if (!sdxi)
		return -ENODEV;

	if (!sdxi->rkey_cap)
		return -EOPNOTSUPP;

	if (!sdxi->rkey_table || !sdxi->rkey_entries)
		return -ENODEV;

	nkeys = args->nkeys;
	if (!nkeys) {
		args->commit_state = SDXI_KEY_COMMIT_ALL;
		return 0;
	}

	if (nkeys > sdxi->rkey_entries)
		return -EINVAL;

	err = sdxi_key_check_indices(args->entries, nkeys, sdxi->rkey_entries,
				     &key_min, &key_max);
	if (err)
		return err;

	mutex_lock(&sdxi->rkey_lock);
	for (i = 0; i < nkeys; i++) {
		const struct sdxi_key_entry *entry = &args->entries[i];
		struct sdxi_rkey_ent ent;

		memcpy(&ent, entry->data, sizeof(ent));
		err = sdxi_rkey_ent_validate(&ent);
		if (err)
			goto out_unlock;
	}

	for (i = 0; i < nkeys; i++) {
		const struct sdxi_key_entry *entry = &args->entries[i];
		struct sdxi_rkey_ent ent;

		memcpy(&ent, entry->data, sizeof(ent));
		sdxi_rkey_ent_store(&sdxi->rkey_table[entry->index], &ent);
	}

	dma_wmb();

	err = sdxi_adm_rkey_update_sync(sdxi, key_min, key_max,
					sdxi_set_keys_timeout(args), NULL);
	if (err) {
		/*
		 * In-memory entries were written but hardware adoption could
		 * not be confirmed; report PARTIAL with first_failed_index = 0
		 * (no per-entry boundary is recoverable from a single SYNC).
		 */
		args->commit_state = SDXI_KEY_COMMIT_PARTIAL;
		args->first_failed_index = 0;
		goto out_unlock;
	}

	args->commit_state = SDXI_KEY_COMMIT_ALL;
out_unlock:
	mutex_unlock(&sdxi->rkey_lock);
	return err;
}

int sdxi_ioctl_get_akey_list(struct file *filep, struct sdxi_file *sf,
			     void *data)
{
	struct sdxi_key_list_args *args = data;
	struct sdxi_cxt *cxt;
	int err;

	if (!sf)
		return -EINVAL;

	cxt = sf->cxt;
	if (!cxt)
		return -EINVAL;
	if (sdxi_cxt_is_fatal(cxt))
		return -ENODEV;

	err = sdxi_key_args_check_hdr(args->argsz, sizeof(*args), args->flags,
				      &args->rsvd0, 1);
	if (err)
		return err;

	mutex_lock(&cxt->akey_lock);
	err = sdxi_key_list_fill(args, cxt->akey_table,
				 sizeof(cxt->akey_table->entry[0]),
				 ARRAY_SIZE(cxt->akey_table->entry));
	mutex_unlock(&cxt->akey_lock);

	return err;
}

int sdxi_ioctl_get_akeys(struct file *filep, struct sdxi_file *sf,
			 void *data)
{
	struct sdxi_get_keys_args *args = data;
	struct sdxi_cxt *cxt;
	u32 nentries;
	u32 nkeys;
	u32 i;
	int err;

	if (!sf)
		return -EINVAL;

	cxt = sf->cxt;
	if (!cxt)
		return -EINVAL;
	if (sdxi_cxt_is_fatal(cxt))
		return -ENODEV;

	err = sdxi_key_args_check_hdr(args->argsz, sizeof(*args), args->flags,
				      &args->rsvd0, 1);
	if (err)
		return err;

	nentries = ARRAY_SIZE(cxt->akey_table->entry);
	nkeys = args->nkeys;

	if (nkeys > nentries)
		return -EINVAL;

	args->argsz = sizeof(*args);

	err = sdxi_key_check_indices(args->entries, nkeys, nentries, NULL, NULL);
	if (err)
		return err;

	mutex_lock(&cxt->akey_lock);
	for (i = 0; i < nkeys; i++) {
		struct sdxi_key_entry *entry = &args->entries[i];
		u32 index = entry->index;

		memcpy(entry->data, &cxt->akey_table->entry[index],
		       sizeof(entry->data));
	}
	mutex_unlock(&cxt->akey_lock);

	return 0;
}

int sdxi_ioctl_set_akeys(struct file *filep, struct sdxi_file *sf,
			 void *data)
{
	struct sdxi_set_keys_args *args = data;
	struct sdxi_cxt *cxt;
	u32 nentries;
	u32 nkeys;
	u32 i;
	u16 key_min;
	u16 key_max;
	int err;

	if (!sf)
		return -EINVAL;

	cxt = sf->cxt;
	if (!cxt)
		return -EINVAL;
	if (sdxi_cxt_is_fatal(cxt))
		return -ENODEV;

	err = sdxi_key_args_check_hdr(args->argsz, sizeof(*args), args->flags,
				      args->rsvd0, ARRAY_SIZE(args->rsvd0));
	if (err)
		return err;

	nentries = ARRAY_SIZE(cxt->akey_table->entry);
	nkeys = args->nkeys;

	args->argsz = sizeof(*args);
	sdxi_set_keys_init_status(args);

	if (!nkeys) {
		args->commit_state = SDXI_KEY_COMMIT_ALL;
		return 0;
	}

	if (nkeys > nentries)
		return -EINVAL;

	err = sdxi_key_check_indices(args->entries, nkeys, nentries,
				     &key_min, &key_max);
	if (err)
		return err;

	mutex_lock(&cxt->akey_lock);
	for (i = 0; i < nkeys; i++) {
		const struct sdxi_key_entry *entry = &args->entries[i];
		struct sdxi_akey_ent ent;

		/*
		 * AKey entry 0 is controlled by the driver as part of context
		 * table programming. AKey entry 1 is the default local PASID
		 * AKey. The current context interrupt AKey, if bound, is also
		 * driver-owned until SDXI_CXT_EVENTFD unbinds it.
		 */
		if (sdxi_akey_index_driver_owned(cxt, entry->index)) {
			err = -EPERM;
			goto out_unlock;
		}

		memcpy(&ent, entry->data, sizeof(ent));
		err = sdxi_akey_ent_validate(&ent);
		if (err)
			goto out_unlock;
		if (!capable(CAP_SYS_ADMIN)) {
			err = sdxi_akey_ent_validate_user(cxt, &ent);
			if (err)
				goto out_unlock;
		}

		if (!sdxi_akey_ent_iv(&ent))
			continue;

		if (!cxt->intr_msg) {
			err = -EOPNOTSUPP;
			goto out_unlock;
		}
		if (!sdxi_cxt_has_intr_fd(cxt)) {
			err = -ENOTCONN;
			goto out_unlock;
		}
		if (sdxi_akey_ent_intr_num(&ent) != cxt->intr_msg) {
			err = -EINVAL;
			goto out_unlock;
		}
	}

	for (i = 0; i < nkeys; i++) {
		const struct sdxi_key_entry *entry = &args->entries[i];
		struct sdxi_akey_ent ent;

		memcpy(&ent, entry->data, sizeof(ent));
		sdxi_akey_ent_store(&cxt->akey_table->entry[entry->index], &ent);
	}

	dma_wmb();

	err = sdxi_adm_akey_update_sync(cxt->sdxi, cxt->id, cxt->id,
					key_min, key_max,
					sdxi_set_keys_timeout(args), NULL);
	if (err) {
		args->commit_state = SDXI_KEY_COMMIT_PARTIAL;
		args->first_failed_index = 0;
		goto out_unlock;
	}

	args->commit_state = SDXI_KEY_COMMIT_ALL;
out_unlock:
	mutex_unlock(&cxt->akey_lock);
	return err;
}
