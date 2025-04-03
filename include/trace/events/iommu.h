/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iommu trace points
 *
 * Copyright (C) 2013 Shuah Khan <shuah.kh@samsung.com>
 *
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM iommu

#if !defined(_TRACE_IOMMU_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_IOMMU_H

#include <linux/tracepoint.h>

struct device;
struct iopt_pages;

DECLARE_EVENT_CLASS(iommu_group_event,

	TP_PROTO(int group_id, struct device *dev),

	TP_ARGS(group_id, dev),

	TP_STRUCT__entry(
		__field(int, gid)
		__string(device, dev_name(dev))
	),

	TP_fast_assign(
		__entry->gid = group_id;
		__assign_str(device);
	),

	TP_printk("IOMMU: groupID=%d device=%s",
			__entry->gid, __get_str(device)
	)
);

DEFINE_EVENT(iommu_group_event, add_device_to_group,

	TP_PROTO(int group_id, struct device *dev),

	TP_ARGS(group_id, dev)

);

DEFINE_EVENT(iommu_group_event, remove_device_from_group,

	TP_PROTO(int group_id, struct device *dev),

	TP_ARGS(group_id, dev)
);

DECLARE_EVENT_CLASS(iommu_device_event,

	TP_PROTO(struct device *dev),

	TP_ARGS(dev),

	TP_STRUCT__entry(
		__string(device, dev_name(dev))
	),

	TP_fast_assign(
		__assign_str(device);
	),

	TP_printk("IOMMU: device=%s", __get_str(device)
	)
);

DEFINE_EVENT(iommu_device_event, attach_device_to_domain,

	TP_PROTO(struct device *dev),

	TP_ARGS(dev)
);

TRACE_EVENT(map,

	TP_PROTO(unsigned long iova, phys_addr_t paddr, size_t size),

	TP_ARGS(iova, paddr, size),

	TP_STRUCT__entry(
		__field(u64, iova)
		__field(u64, paddr)
		__field(size_t, size)
	),

	TP_fast_assign(
		__entry->iova = iova;
		__entry->paddr = paddr;
		__entry->size = size;
	),

	TP_printk("IOMMU: iova=0x%016llx - 0x%016llx paddr=0x%016llx size=%zu",
		  __entry->iova, __entry->iova + __entry->size, __entry->paddr,
		  __entry->size
	)
);

TRACE_EVENT(memfdtr,

	TP_PROTO(int i, phys_addr_t paddr, size_t size, unsigned long ua, int r, int max_order),

	TP_ARGS(i, paddr, size, ua, r, max_order),

	TP_STRUCT__entry(
		__field(int, i)
		__field(u64, paddr)
		__field(size_t, size)
		__field(u64, ua)
		__field(int, r)
		__field(int, max_order)
	),

	TP_fast_assign(
		__entry->i = i;
		__entry->paddr = paddr;
		__entry->size = size;
		__entry->ua = ua;
		__entry->r = r;
		__entry->max_order = max_order;
	),

	TP_printk("#%d: pa=0x%012llx sz=%zu ua=%llx r=%d max_order=%d",
		  __entry->i, __entry->paddr,
		  __entry->size, __entry->ua, __entry->r, __entry->max_order
	)
);

TRACE_EVENT(iopt_pages_npinned,

	TP_PROTO(struct iopt_pages *pages, long npages, long np),

	TP_ARGS(pages, npages, np),

	TP_STRUCT__entry(
		__field(struct iopt_pages *, pages)
		__field(long, npages)
		__field(long, npinned)
		__field(long, np)
	),

	TP_fast_assign(
		__entry->pages = pages;
		__entry->npages = npages;
		__entry->npinned = __entry->pages->npinned;
		__entry->np = np;
	),

	TP_printk("@%lx %ld => %ld / %ld / %ld",
		  (unsigned long) __entry->pages,
		  __entry->npages, __entry->pages->npinned, __entry->npinned, __entry->np
	)
);

TRACE_EVENT(unmap,

	TP_PROTO(unsigned long iova, size_t size, size_t unmapped_size),

	TP_ARGS(iova, size, unmapped_size),

	TP_STRUCT__entry(
		__field(u64, iova)
		__field(size_t, size)
		__field(size_t, unmapped_size)
	),

	TP_fast_assign(
		__entry->iova = iova;
		__entry->size = size;
		__entry->unmapped_size = unmapped_size;
	),

	TP_printk("IOMMU: iova=0x%016llx - 0x%016llx size=%zu unmapped_size=%zu",
		  __entry->iova, __entry->iova + __entry->size,
		  __entry->size, __entry->unmapped_size
	)
);

DECLARE_EVENT_CLASS(iommu_error,

	TP_PROTO(struct device *dev, unsigned long iova, int flags),

	TP_ARGS(dev, iova, flags),

	TP_STRUCT__entry(
		__string(device, dev_name(dev))
		__string(driver, dev_driver_string(dev))
		__field(u64, iova)
		__field(int, flags)
	),

	TP_fast_assign(
		__assign_str(device);
		__assign_str(driver);
		__entry->iova = iova;
		__entry->flags = flags;
	),

	TP_printk("IOMMU:%s %s iova=0x%016llx flags=0x%04x",
			__get_str(driver), __get_str(device),
			__entry->iova, __entry->flags
	)
);

DEFINE_EVENT(iommu_error, io_page_fault,

	TP_PROTO(struct device *dev, unsigned long iova, int flags),

	TP_ARGS(dev, iova, flags)
);
#endif /* _TRACE_IOMMU_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
