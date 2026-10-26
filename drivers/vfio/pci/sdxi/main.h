/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 *
 * VFIO migration design
 * ---------------------
 * Advertise VFIO_MIGRATION_STOP_COPY | VFIO_MIGRATION_P2P so QEMU can migrate
 * VMs with more than one assigned SDXI VF. Single-VF migration needs only
 * STOP_COPY; P2P adds RUNNING_P2P arcs required by vfio_mig_get_next_state().
 *
 * P2P quiesce model (QAT-style fallback, not mlx5 initiator/responder)
 * SDXI 1.0a exposes function stop via GSRV_STOP_SF/HD (GSV_STOPG_* -> GSV_STOP).
 * There is no API to block cross-function/RKey or PCI peer DMA while host-memory
 * DMA continues. Per linux/vfio.h, when P2P cannot be isolated the driver must
 * stop all DMA. RUNNING_P2P therefore maps to the same hardware state as STOP:
 * sdxi_fn_stop() has driven the function to GSV_STOP before the arc completes.
 *
 * VFIO state vs SDXI fn_gsv during P2P
 *   VFIO RUNNING_P2P  ->  GSV_STOP  (all DMA off; BAR0 MMIO still responds)
 *   VFIO STOP         ->  GSV_STOP  (same; distinguished only in mig_state)
 *   VFIO RUNNING      ->  GSV_ACTIVE
 *
 * P2P FSM arcs (sdxi_step_state; Phase 1a — implemented)
 *   RUNNING        -> RUNNING_P2P : sdxi_fn_stop()
 *   RUNNING_P2P    -> RUNNING     : sdxi_start() incl. P2V context restart
 *   RUNNING_P2P    -> STOP        : no-op (already GSV_STOP)
 *   STOP           -> RUNNING_P2P : no-op (already GSV_STOP)
 *
 * PRE_COPY (Phase 1b — implemented; P2P-O3–O5, P2P-O8)
 *   Guest RAM dirtiness: IOMMU dirty pages (no log_ops). Device stream empty
 *   until STOP_COPY; sdxi_save_regs() runs at PRE_COPY_P2P -> STOP_COPY or
 *   STOP -> STOP_COPY (non-precopy path). The blob carries each context's
 *   post-stop status block, including read_idx (P2P-O8). Resume writes
 *   those bytes into guest RAM before P2V.
 *   RUNNING / RUNNING_P2P -> PRE_COPY / PRE_COPY_P2P : open save FD (no blob)
 *   Pause drain (before vCPUs stop): VFIO_DEVICE_FEATURE_SDXI_PAUSE
 *     forwards new doorbells in QEMU and calls sdxi_fn_stop_timeout()
 *     while the guest can still answer PRI. This does not change VFIO
 *     state. PRE_COPY -> PRE_COPY_P2P then finds the function already
 *     stopped.
 *   PRE_COPY -> PRE_COPY_P2P : sdxi_fn_stop()
 *   PRE_COPY_P2P -> PRE_COPY : sdxi_start()
 *   PRE_COPY_P2P -> STOP_COPY : sdxi_save_regs(); finalize stream
 *   PRE_COPY -> RUNNING / PRE_COPY_P2P -> RUNNING_P2P : close save FD
 *
 * STOP_COPY / RESUMING arcs are unchanged. open_device() reports STOP (not
 * RUNNING_P2P) when hardware is found in GSV_STOP after a failed migration.
 *
 * Out of scope (until spec/hardware adds API)
 *   mlx5-style SUSPEND_INITIATOR / SUSPEND_RESPONDER partial quiesce.
 *
 * Open question
 *   Guest SDXI drivers may observe GSV_STOP during the brief RUNNING_P2P window
 *   while QEMU pauses vCPUs (vfio_vmstate_change_prepare). QAT/XE accept full
 *   suspend here; validate under active guest workload in Phase 4 (P2P-002).
 */

#ifndef SDXI_VFIO_H
#define SDXI_VFIO_H

#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/sdxi.h>
#include <linux/types.h>
#include <linux/vfio.h>
#include <linux/vfio_pci_core.h>

#define SDXI_MIG_MAGIC		0x49584453	/* "SDXI" */
#define SDXI_MIG_VERSION	2

/* Device DMA address of a context-status block, then the 16 status bytes. */
struct sdxi_mig_cxt_sts {
	__le64 dma;
	__u8 sts[16];
} __packed;

struct sdxi_mig_blob {
	__le32 magic;
	__le32 version;
	__le64 cap0;
	__le64 cap1;
	__le64 ctl0;
	__le64 ctl2;
	__le64 cxt_l2;
	__le64 rkey;
	__le64 err_cfg;
	__le64 err_ctl;
	__le64 err_wrt;
	__le64 err_rd;
	__le32 nr_cxt;
	__le32 nr_pad;
	struct sdxi_mig_cxt_sts cxt[];
} __packed;

struct sdxi_mig_file {
	struct file			*filp;
	struct sdxi_vfio_pci_device	*sdev;
	struct mutex			 lock;
	loff_t			 pos;
	struct sdxi_mig_blob	*blob;
	size_t			 blob_len;
	size_t			 blob_cap;
	u32			 max_cxts;
	bool			 valid;
	bool			 precopy;
	bool			 finalized;
};

struct sdxi_vfio_pci_device {
	struct vfio_pci_core_device	core_dev;
	void __iomem			*bar0;

	struct mutex			 state_mutex;
	enum vfio_device_mig_state	 state;
	struct sdxi_mig_file		*save_file;
	struct sdxi_mig_file		*restore_file;
};

#endif /* SDXI_VFIO_H */
