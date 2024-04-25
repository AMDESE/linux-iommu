// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#ifndef __KSB_USER_H
#define __KSB_USER_H

/* CDM error code */
#define KSB_CDX_ERR_IO                 0xdead0001
#define KSB_CDX_ERR_PATTERN_MISMATCH   0xdead0002
#define KSB_CDX_ERR_INVAL_REQUEST_SIZE 0xdead0003
#define KSB_CDX_ERR_UNKNOWN            0xdeadffff

/* The maximum request size */
#define KSB_CDM_MAX_REQUEST_SIZE       256

#define CDX_IO 'd'

/* CDx Command structure.
 * The seed, req_size and req_count are
 * only applicable for CDM exerciser. */
typedef struct ksb_user_cmd_s {
	/* Source addr */
	void *src;
	/* Destination addr */
	void *dst;
	/* No need for dma mapping */
	uint8_t addr_mapped;
	/* DMA Read into fabric/dpu buffer */
	uint8_t dma_rd_fabric;
	/* Any value between 0-255 */
	unsigned char seed;
	/* The request size allowed upto KSB_CDM_MAX_REQUEST_SIZE */
	unsigned int req_size;
	/* No limit for the req counts */
	unsigned int req_count;
	/* DPU Exerciser instance */
	int dpu_exe_instance;
	/* MMIO data for write operation */
	uint64_t wr_data;
	/* MMIO data after read operation */
	uint64_t rd_data;
	/* For performace test, packet count */
	uint64_t in_pkts;

	/* CDM driver will set this as an output.
	 * Any non-zero value means an error during CDM operation.
	 * Please see the error code given above. */
	int err_code;
	/* For performance test result */
	/* Duration in nanoseconds */
	uint64_t out_duration_ns;
	/* Number of completed test loops */
	uint64_t out_loops;
} ksb_user_cmd_t;

/* CDx DMA stats enable Command structure. */
typedef struct ksb_stats_en_cmd_s {
	uint8_t enable;
} ksb_stats_en_cmd_t;

/* CDM message store command */
#define KSB_CDM_MSGST _IOWR(CDX_IO, 0, struct ksb_user_cmd_s)
/* CDM message load command */
#define KSB_CDM_MSGLD _IOWR(CDX_IO, 1, struct ksb_user_cmd_s)
/* MMIO write command */
#define KSB_MMIO_WR _IOWR(CDX_IO, 6, struct ksb_user_cmd_s)
/* MMIO read command */
#define KSB_MMIO_RD _IOWR(CDX_IO, 7, struct ksb_user_cmd_s)
/* MMIO write and read command */
#define KSB_MMIO_WR_RD _IOWR(CDX_IO, 8, struct ksb_user_cmd_s)
/* DPU exerciser command */
#define KSB_DMA_RD_WR_USER _IOWR(CDX_IO, 3, struct ksb_user_cmd_s)
#define KSB_DMA_RD_USER _IOWR(CDX_IO, 4, struct ksb_user_cmd_s)
#define KSB_DMA_WR_USER _IOWR(CDX_IO, 5, struct ksb_user_cmd_s)
/* DMA perf write command */
#define KSB_DMA_PERF_WR_USER _IOWR(CDX_IO, 9, struct ksb_user_cmd_s)
/* DMA perf read command */
#define KSB_DMA_PERF_RD_USER _IOWR(CDX_IO, 10, struct ksb_user_cmd_s)
/* DMA stats enable command */
#define KSB_DMA_STATS_ENABLE _IOWR(CDX_IO, 11, struct ksb_stats_en_cmd_s)

#endif
