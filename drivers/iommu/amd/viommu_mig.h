/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef AMD_VIOMMU_MIG_H
#define AMD_VIOMMU_MIG_H

#include <linux/bits.h>
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

/*
 * IOMMU_VIOMMU_MIG_SECTION_HW_QUEUE: one record per guest ring, for the
 * command ring, the event log and the PPR log.
 *
 * Every ring gets a record whether or not the guest has programmed it, so that
 * the section's size follows from this header alone and needs no register read.
 * That keeps GET_SIZE exact in any state, and stops it from under-reporting if
 * the guest programs a ring between the size query and the save.
 */
#define AMD_VIOMMU_MIG_HW_QUEUES		3

/* struct amd_viommu_mig_hw_queue.record_flags */
#define AMD_VIOMMU_MIG_HW_QUEUE_PROGRAMMED	BIT(0)

/**
 * struct amd_viommu_mig_hw_queue - State of one guest ring
 * @type: Which ring this is, an enum iommu_hw_queue_type value
 * @index: Ring index within its type, always zero today
 * @base_gpa: Ring base, in the address space the guest posts addresses in
 * @length_bytes: Ring size in bytes, decoded from @size_encoded
 * @size_encoded: Ring size as the guest programmed it, meaning 16 << n bytes
 * @queue_flags: Enable bits, a mask of enum iommu_hw_queue_flags_amd
 * @head: Ring head, a byte offset into the ring
 * @tail: Ring tail, a byte offset into the ring
 * @record_flags: AMD_VIOMMU_MIG_HW_QUEUE_*, describing the record itself
 *
 * @head and @tail are the fields a destination has to program; a ring restored
 * with the wrong pointers replays or loses entries. The rest echoes what the
 * source had, for a destination to check against what its own VMM asks it to
 * allocate, and is not otherwise authoritative.
 *
 * Both spellings of the size travel because they answer different questions:
 * @length_bytes is what the restore side reasons about, while @size_encoded is
 * the exact nibble to put back in the register.
 */
struct amd_viommu_mig_hw_queue {
	__u32 type;
	__u32 index;
	__aligned_u64 base_gpa;
	__u32 length_bytes;
	__u32 size_encoded;
	__u32 queue_flags;
	__u32 head;
	__u32 tail;
	__u32 record_flags;
};

/**
 * struct amd_viommu_mig_hw_queue_section - Start of the hardware queue section
 * @record_size: Bytes per record, so that a reader can stride over records
 *		 longer than the ones it knows how to parse
 * @nr_records: Number of records in @recs
 * @recs: One record per ring
 */
struct amd_viommu_mig_hw_queue_section {
	__u32 record_size;
	__u32 nr_records;
	struct amd_viommu_mig_hw_queue recs[];
};

/* Records follow one another directly, so their size has to keep the alignment */
static_assert(sizeof(struct amd_viommu_mig_hw_queue) %
	      AMD_VIOMMU_MIG_SECTION_ALIGN == 0);
static_assert(sizeof(struct amd_viommu_mig_hw_queue_section) %
	      AMD_VIOMMU_MIG_SECTION_ALIGN == 0);

/**
 * struct amd_viommu_mig_status - IOMMU_VIOMMU_MIG_SECTION_STATUS
 * @sticky: The write-one-to-clear bits that were pending at the source. The
 *	    guest clears these itself as it services them, so an overflow bit
 *	    here is the only surviving record that the guest lost log entries
 * @raw: The whole register as it read at the quiesce point. The run bits in it
 *	 belong to hardware, which asserts them from whether its own rings are
 *	 enabled, so they describe the source and not the destination
 *
 * Read after log generation stops, so it describes a vIOMMU that has stopped
 * changing rather than one still taking events.
 *
 * Neither field can be programmed back. These bits are write-one-to-clear, and
 * measurement on Genoa confirms it in both directions on the same bit: hardware
 * set ComWaitInt, writing that bit while set cleared it at both 32 and 64 bits,
 * and no write could set any sticky bit from clear. So a destination cannot
 * reinstate what the source had pending, and restore must not try.
 *
 * They travel anyway because dropping them would lose the information outright.
 * An overflow bit is the only evidence the guest ever gets that entries went
 * missing, and a VMM that wants the destination guest to learn of it has to be
 * told first.
 */
struct amd_viommu_mig_status {
	__aligned_u64 sticky;
	__aligned_u64 raw;
};

/*
 * IOMMU_VIOMMU_MIG_SECTION_EVTLOG and IOMMU_VIOMMU_MIG_SECTION_PPRLOG: contents
 * of a log ring, as runs of bytes tagged with where in the ring they belong.
 *
 * These two rings travel in the payload even though they live in guest memory.
 * The IOMMU writes them, not the guest and not the assigned device, and nothing
 * on the VMM's side is guaranteed to notice. A VMM that tracks dirty pages in
 * the device rather than in the IOMMU sees nothing of these writes, however
 * good that device's tracker is, so the rings would arrive holding whatever
 * they held when the guest last touched them.
 *
 * Their contents also have to agree with the head and tail captured alongside
 * them. Those pointers are read from registers at the quiesce point, while
 * guest RAM is swept on the VMM's own schedule, so a ring arriving by RAM
 * migration can disagree with the pointers describing it even where the writes
 * are tracked. Capturing both once log generation has stopped makes the pair
 * consistent by construction.
 *
 * The command ring is left out: the guest writes it, so guest RAM migration
 * covers it.
 *
 * Segments rather than one flat copy because only the entries between head and
 * tail mean anything to a resumed guest; the rest are consumed or never
 * written. The whole ring travels for now, as a single segment, because that is
 * what can be tested without a guest to generate real entries. Narrowing it to
 * the occupied range is then a change here rather than to the format, since a
 * reader is already following segment offsets either way.
 */

/**
 * struct amd_viommu_mig_log_segment - One run of log ring bytes
 * @offset: Where these bytes belong, as a byte offset into the ring
 * @length: How many bytes
 */
struct amd_viommu_mig_log_segment {
	__u32 offset;
	__u32 length;
};

/**
 * struct amd_viommu_mig_log_section - Start of a log contents section
 * @ring_bytes: Size of the ring these segments came out of, so that a
 *		destination can reject segments that do not fit the ring it has
 * @nr_segments: Segments described by @segs
 * @segs: Segment descriptors. The bytes themselves follow the last descriptor,
 *	  concatenated in the same order
 */
struct amd_viommu_mig_log_section {
	__u32 ring_bytes;
	__u32 nr_segments;
	struct amd_viommu_mig_log_segment segs[];
};

static_assert(sizeof(struct amd_viommu_mig_log_segment) %
	      AMD_VIOMMU_MIG_SECTION_ALIGN == 0);
static_assert(sizeof(struct amd_viommu_mig_log_section) %
	      AMD_VIOMMU_MIG_SECTION_ALIGN == 0);

struct amd_iommu_viommu;
struct iommufd_viommu;
struct iommufd_viommu_mig_ctx;
struct iommu_viommu_mig_header;

int amd_viommu_mig_quiesce_cmdbuf(struct amd_iommu_viommu *aviommu,
				  const struct iommufd_viommu_mig_ctx *ctx,
				  unsigned int timeout_ms);

/* struct iommufd_viommu_ops migration entry points */
int amd_viommu_mig_get_size(struct iommufd_viommu *viommu, size_t *out_size);
int amd_viommu_mig_prepare_save(struct iommufd_viommu *viommu,
				const struct iommufd_viommu_mig_ctx *ctx,
				u32 timeout_ms, u32 *out_status);
int amd_viommu_mig_save(struct iommufd_viommu *viommu,
			const struct iommufd_viommu_mig_ctx *ctx,
			struct iommu_viommu_mig_header *hdr, void *payload,
			size_t payload_len);
int amd_viommu_mig_restore(struct iommufd_viommu *viommu,
			   const struct iommufd_viommu_mig_ctx *ctx,
			   const struct iommu_viommu_mig_header *hdr,
			   const void *payload, size_t payload_len);
int amd_viommu_mig_commit_restore(struct iommufd_viommu *viommu,
				  const struct iommufd_viommu_mig_ctx *ctx);
void amd_viommu_mig_abort(struct iommufd_viommu *viommu);

#endif /* AMD_VIOMMU_MIG_H */
