// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD vIOMMU migration payload format.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <linux/align.h>
#include <linux/bug.h>
#include <linux/overflow.h>
#include <linux/string.h>

#include "viommu_mig.h"

/**
 * amd_viommu_mig_section - Reserve a payload section and locate its data
 * @w: Writer to append to
 * @type: One bit of enum iommu_viommu_mig_section
 * @length: Bytes of section data the caller intends to write
 *
 * Return: where the section data belongs, or NULL when the writer is
 * measuring rather than writing, and on error.
 *
 * The two NULL cases are deliberately not distinguished. A caller fills a
 * section only when it is handed a pointer, which is what keeps a measuring
 * pass from touching hardware, and inspects @w->err once at the end instead
 * of after every section.
 */
void *amd_viommu_mig_section(struct amd_viommu_mig_writer *w, u32 type,
			     size_t length)
{
	struct amd_viommu_mig_tlv tlv = { .type = type, .length = length };
	size_t data_offset, end;

	if (w->err)
		return NULL;

	if (WARN_ON_ONCE(length > U32_MAX)) {
		w->err = -EINVAL;
		return NULL;
	}

	data_offset = size_add(w->offset, sizeof(tlv));
	end = size_add(data_offset, ALIGN(length, AMD_VIOMMU_MIG_SECTION_ALIGN));
	if (end == SIZE_MAX) {
		w->err = -EOVERFLOW;
		return NULL;
	}

	w->section_mask |= type;

	if (!w->buf) {
		w->offset = end;
		return NULL;
	}

	if (end > w->capacity) {
		w->err = -ENOSPC;
		return NULL;
	}

	memcpy(w->buf + w->offset, &tlv, sizeof(tlv));

	/*
	 * Zero the data and its trailing padding rather than relying on the
	 * caller having been handed a zeroed buffer, so that a section which
	 * writes only some of its fields cannot leak stack or heap contents.
	 */
	memset(w->buf + data_offset, 0, end - data_offset);
	w->offset = end;

	return w->buf + data_offset;
}

/**
 * amd_viommu_mig_put - Append a section copied from a caller buffer
 * @w: Writer to append to
 * @type: One bit of enum iommu_viommu_mig_section
 * @data: Section contents
 * @length: Bytes at @data
 *
 * Return: 0, or the writer's sticky error.
 */
int amd_viommu_mig_put(struct amd_viommu_mig_writer *w, u32 type,
		       const void *data, size_t length)
{
	void *dst = amd_viommu_mig_section(w, type, length);

	if (dst)
		memcpy(dst, data, length);

	return w->err;
}
