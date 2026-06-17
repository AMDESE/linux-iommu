/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI device driver header
 *
 * Copyright (C) 2025-2026 Advanced Micro Devices, Inc.
 */

#ifndef __DMA_SDXI_H
#define __DMA_SDXI_H

#include <linux/cdev.h>
#include <linux/dev_printk.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/errno.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/idr.h>
#include <linux/xarray.h>

#include "hw.h"
#include "mmio.h"
#include "version.h"

#define SDXI_DRV_NAME		"sdxi"
#define SDXI_DRV_DESC		"SDXI driver"

#define ID_TO_L2_INDEX(id)	(((id) >> 7) & 0x1FF)
#define ID_TO_L1_INDEX(id)	((id) & 0x7F)
#define L2_TABLE_ENTRIES	(1 << 9)
#define L1_TABLE_ENTRIES	(1 << 7)
#define L2_TABLE_SIZE		4096
#define L1_TABLE_SIZE		4096

#define OP_TYPE_ERRLOG          0x7f7

#define DESC_RING_BASE_PTR_SHIFT	6
#define CXT_STATUS_PTR_SHIFT		4
#define WRT_INDEX_PTR_SHIFT		3

#define L1_CXT_CTRL_PTR_SHIFT		6
#define L1_CXT_AKEY_PTR_SHIFT		12

struct sdxi_dev;
/**
 * struct sdxi_dev_ops - Bus-specific methods for SDXI devices.
 *
 * @irq_init: Allocate MSIs.
 * @irq_exit: Release MSIs.
 */
struct sdxi_dev_ops {
	int (*irq_init)(struct sdxi_dev *sdxi);
	void (*irq_exit)(struct sdxi_dev *sdxi);
	int (*irq_get)(struct sdxi_dev *sdxi, unsigned int msg);
};



/* Legacy interfaces kept until the PCI and context conversions land. */
struct sdxi_bus_ops {
	int (*init)(struct sdxi_dev *sdxi);
	int (*get_irq)(struct sdxi_dev *sdxi, unsigned int index);
};

enum {
	SDXI_ERROR_VECTOR = 0,
	SDXI_MIN_VECTORS = 1,
};

int sdxi_register(struct device *dev, const struct sdxi_bus_ops *ops);
void sdxi_unregister(struct device *dev);
/* End legacy interfaces. */

struct device;
struct dma_pool;

struct sdxi_dev {
	struct device *dev;
	resource_size_t ctrl_regs_bar;	/* ctrl registers base (BAR0) */
	resource_size_t dbs_bar;	/* doorbells base (BAR2) */
	void __iomem *ctrl_regs;	/* virt addr of ctrl registers */
	void __iomem *dbs;		/* virt addr of doorbells */

	struct sdxi_version sdxi_version;	/* SDXI version implemented by device */

	/* hardware capabilities (from cap0 & cap1) */
	u16 sfunc;			/* function's requester id */
	u32 db_stride;			/* doorbell stride in bytes */
	u64 max_ring_entries;		/* max # of ring entries supported */

	u32 max_akeys;			/* max akey # supported */
	u32 max_cxts;			/* max contexts # supported */
	u32 op_grp_cap;			/* supported operatation group cap */

	/* Legacy context table fields kept until the context conversion lands. */
	u16 max_cxtid;
	struct sdxi_cxt_L2_table *L2_table;
	dma_addr_t L2_dma;
	struct sdxi_cxt_L1_table *L1_table;
	dma_addr_t L1_dma;
	unsigned int nr_vectors;
	struct ida vectors;
	struct xarray client_cxts;
	const struct sdxi_bus_ops *bus_ops;
	/* End legacy context table fields. */


	/* rkey table (MMIO_RKEY) */
	struct mutex rkey_lock;
	struct sdxi_rkey_ent *rkey_table;
	dma_addr_t rkey_table_dma;
	u32 rkey_entries;
	u8 rkey_order;

	/* context management */
	struct mutex cxt_lock;		/* context protection */
	int cxt_count;
	u32 mmap_gen_ctr;
	struct sdxi_cxt_l2_table *l2_table;
	dma_addr_t l2_dma;
	/* list of context l1 tables, on-demand, access with [l2_idx] */
	struct sdxi_cxt_l1_table *l1_table_array[L2_TABLE_ENTRIES];
	/* all contexts, on-demand, access with [l2_idx][l1_idx] */
	struct sdxi_cxt **cxt_array[L2_TABLE_ENTRIES];

	struct dma_pool *write_index_pool;
	struct dma_pool *cxt_sts_pool;
	struct dma_pool *cxt_ctl_pool;
	struct dma_pool *cst_blk_pool;

	/* error log */
	int error_irq;
	struct sdxi_errlog_hd_ent *err_log;
	dma_addr_t err_log_dma;

	/* special contexts */
	struct sdxi_cxt *admin_cxt;	/* admin context */

	struct dma_device *dma_dev;

	const struct sdxi_dev_ops *dev_ops;

	/* char device support */
	struct cdev cdev;		/* cdev struct for each sdxi device */
	struct device *chardev;		/* device created for /dev/sdxi sysfs */
	int minor;			/* minor class id, used by pf_id */
	int pf_id;			/* PF id for /dev/sdxi node naming */
	int vf_id;			/* VF id for /dev/sdxi node naming */
	bool is_vf:1;		     /* raw MMIO_CAP0.field0.vf */
	bool pci_is_virtfn:1;	     /* PCI core enumerated SR-IOV VF */
	bool rkey_cap:1;	     /* MMIO_CAP1.rkey_cap */
	bool atomic_ops_enabled:1;   /* platform allows SDXI AtomicGrp */

	/* power management */
	struct mutex pm_lock;		/* serialize PM transitions */
	bool pm_suspended;		/* device is in suspended state */
	bool pm_fn_was_active;		/* function was active before suspend */
	u64 pm_ctl0;
	u64 pm_ctl2;
};

/* Legacy vector helpers kept until the PCI conversion lands. */
static inline int sdxi_alloc_vector(struct sdxi_dev *sdxi)
{
	return ida_alloc_range(&sdxi->vectors, SDXI_MIN_VECTORS,
			       sdxi->nr_vectors - 1, GFP_KERNEL);
}

static inline void sdxi_free_vector(struct sdxi_dev *sdxi, unsigned int nr)
{
	ida_free(&sdxi->vectors, nr);
}

static inline int sdxi_vector_to_irq(struct sdxi_dev *sdxi, unsigned int nr)
{
	WARN_ON_ONCE(!ida_exists(&sdxi->vectors, nr));
	return sdxi->bus_ops->get_irq(sdxi, nr);
}
/* End legacy vector helpers. */

static inline bool sdxi_dev_compatible(const struct sdxi_dev *sdxi,
				       struct sdxi_version v)
{
	return sdxi_version_ge(sdxi->sdxi_version, v);
}

/*
 * VF passthrough preserves MMIO_CAP0.VF inside the guest but loses the
 * host-side SR-IOV PF/VF topology, so keep the raw hardware bit separate
 * from the topology-aware driver classification.
 */
static inline bool sdxi_fn_reports_vf(const struct sdxi_dev *sdxi)
{
	return sdxi->is_vf;
}

static inline bool sdxi_is_vf_device(const struct sdxi_dev *sdxi)
{
	return sdxi_fn_reports_vf(sdxi) && sdxi->pci_is_virtfn;
}

#define IS_VF_DEVICE(sdxi)	sdxi_is_vf_device(sdxi)

static inline struct device *sdxi_to_dev(const struct sdxi_dev *sdxi)
{
	return sdxi->dev;
}

#define sdxi_dbg(s, fmt, ...) dev_dbg(sdxi_to_dev(s), fmt, ## __VA_ARGS__)
#define sdxi_info(s, fmt, ...) dev_info(sdxi_to_dev(s), fmt, ## __VA_ARGS__)
#define sdxi_err(s, fmt, ...) dev_err(sdxi_to_dev(s), fmt, ## __VA_ARGS__)

static inline int sdxi_irq_get(struct sdxi_dev *sdxi, unsigned int msg)
{
	if (!sdxi || !sdxi->dev_ops || !sdxi->dev_ops->irq_get)
		return -EOPNOTSUPP;

	return sdxi->dev_ops->irq_get(sdxi, msg);
}

int sdxi_device_init(struct sdxi_dev *sdxi, const struct sdxi_dev_ops *ops);
void sdxi_device_exit(struct sdxi_dev *sdxi);
int sdxi_device_suspend(struct sdxi_dev *sdxi);
int sdxi_device_resume(struct sdxi_dev *sdxi);
/* Chardev (IOCTL) */
int sdxi_chardev_init(void);
void sdxi_chardev_exit(void);
int sdxi_chardev_register(struct sdxi_dev *sdxi);
void sdxi_chardev_unregister(struct sdxi_dev *sdxi);

static inline u64 sdxi_read64(const struct sdxi_dev *sdxi, enum sdxi_reg reg)
{
	return ioread64(sdxi->ctrl_regs + reg);
}

static inline void sdxi_write64(struct sdxi_dev *sdxi, enum sdxi_reg reg, u64 val)
{
	iowrite64(val, sdxi->ctrl_regs + reg);
}

#endif /* __DMA_SDXI_H */
