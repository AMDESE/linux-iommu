/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef AMD_VIOMMU_MIG_H
#define AMD_VIOMMU_MIG_H

#include <linux/types.h>

/*
 * Layout of the opaque payload that accompanies struct
 * iommu_viommu_mig_header on IOMMU_VIOMMU_MIG_STATE. The header is UAPI and
 * fixed at 64 bytes; everything described here is owned by this driver and
 * versioned by AMD_VIOMMU_MIG_FORMAT_VERSION.
 *
 * The payload is a sequence of type-length-value sections. A reader walks
 * them in order and skips any type it does not recognise, so adding a section
 * needs no format version bump; changing what an existing section means does.
 *
 * Values are little-endian because the AMD IOMMU is x86-only, so a payload
 * never crosses an endianness boundary.
 */
#define AMD_VIOMMU_MIG_FORMAT_VERSION		1

/*
 * Lowest format version able to consume what this kernel writes, reported as
 * iommu_viommu_mig_header.min_reader_version. Raise it only for a change that
 * would make an older reader misinterpret a payload rather than skip it.
 */
#define AMD_VIOMMU_MIG_MIN_READER_VERSION	1

/* Every section header is aligned, so a reader can walk them in place. */
#define AMD_VIOMMU_MIG_SECTION_ALIGN		8

/**
 * struct amd_viommu_mig_tlv - Header of one payload section
 * @type: One bit of enum iommu_viommu_mig_section
 * @length: Bytes of section data, excluding the padding that follows it
 *
 * Section data starts immediately after this header and is followed by zero
 * to seven zero bytes, so that the next section header stays aligned.
 */
struct amd_viommu_mig_tlv {
	__u32 type;
	__u32 length;
};

static_assert(sizeof(struct amd_viommu_mig_tlv) == AMD_VIOMMU_MIG_SECTION_ALIGN);

/**
 * struct amd_viommu_mig_writer - Payload builder
 * @buf: Destination buffer, or NULL to measure a payload without writing one
 * @capacity: Bytes available at @buf, ignored while measuring
 * @offset: Bytes consumed so far, and the payload length once done
 * @section_mask: Sections emitted so far, for iommu_viommu_mig_header
 * @err: First error encountered, sticky
 *
 * A NULL @buf turns every section into a size calculation, so that
 * mig_get_size and mig_save can run the same sequence of calls and cannot
 * disagree about how large a payload is. A disagreement would show up as a
 * caller looping on -EMSGSIZE forever.
 */
struct amd_viommu_mig_writer {
	u8 *buf;
	size_t capacity;
	size_t offset;
	u64 section_mask;
	int err;
};

static inline void amd_viommu_mig_writer_init(struct amd_viommu_mig_writer *w,
					      void *buf, size_t capacity)
{
	*w = (struct amd_viommu_mig_writer){ .buf = buf, .capacity = capacity };
}

void *amd_viommu_mig_section(struct amd_viommu_mig_writer *w, u32 type,
			     size_t length);
int amd_viommu_mig_put(struct amd_viommu_mig_writer *w, u32 type,
		       const void *data, size_t length);

#endif /* AMD_VIOMMU_MIG_H */
