// SPDX-License-Identifier: GPL-2.0-only
/*
 * Key table management (AKey/RKey) and key-related IOCTLs.
 *
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#include <linux/bitops.h>
#include <linux/bitfield.h>
#include <linux/dma-mapping.h>
#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/sizes.h>
#include <linux/string.h>

#include "keys.h"
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

static u32 sdxi_key_table_build_bitmap(u8 *bitmap, u32 nentries,
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

	if (pasid & ~(SDXI_RKEY_ENT_PASID | SDXI_RKEY_ENT_PH))
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

	if (pasid & ~(SDXI_AKEY_ENT_PASID | SDXI_AKEY_ENT_PR))
		return -EINVAL;

	if (memchr_inv(ent->rsvd_0, 0, sizeof(ent->rsvd_0)))
		return -EINVAL;
	if (memchr_inv(ent->rsvd_1, 0, sizeof(ent->rsvd_1)))
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
