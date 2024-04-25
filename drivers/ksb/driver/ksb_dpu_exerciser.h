// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#ifndef __KSB_DPU_EXERCISER_H
#define __KSB_DPU_EXERCISER_H

typedef enum ksb_dpu_op {
	KSB_DPU_OP_RD,
	KSB_DPU_OP_WR,
	KSB_DPU_OP_RD_WR,
	KSB_DPU_OP_PERF_WR,
	KSB_DPU_OP_PERF_RD,
	KSB_DPU_OP_INVALID
} ksb_dpu_op_t;

typedef struct ksb_dpu_cmd {
	ksb_dpu_op_t cmd;
	bool addr_mapped;
	bool dma_rd_fabric;
	int dpu_exe;
	void __user *src;
	void __user *dst;
	u32 dma_len;
	u64 loops;
}ksb_dpu_cmd_t;

typedef struct ksb_dpu_perf {
	uint64_t loops;			/** Number of completed test loops */
	uint64_t duration_ns;	/** Duration in nanoseconds */
}ksb_dpu_perf_t;

int dpu_exerciser_init(struct ksb_drv_ctx *ksb_drv);
void dpu_exerciser_fini(struct ksb_drv_ctx *ksb_drv);
int reserve_dpu_cmd_exe(int cmd_exe, bool perf);
void release_dpu_cmd_exe(int cmd_exe, bool perf);
int dpu_exerciser_execute_user_cmd(cdx_device_t *cdx_dev, ksb_dpu_cmd_t *usr_cmd);
int dpu_exerciser_execute_user_perf_cmd(cdx_device_t *cdx_dev, ksb_dpu_cmd_t *usr_cmd, ksb_dpu_perf_t *perf);
void dpu_exerciser_set_stats(cdx_device_t *cdx_dev, bool enable);
#endif
