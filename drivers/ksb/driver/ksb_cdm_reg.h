// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#ifndef __KSB_CDM_REG_H
#define __KSB_CDM_REG_H

#define CDM_OFFSET 0x400000

/*CDM Exerciser*/
/*CSR*/
#define CDM_GLOBAL_START 0xFC
#define CDM_SOFT_RSTN 0xF8
#define CDM_MSGST_HOST_START_ADDR_0_DST1 0x124
#define CDM_MSGST_HOST_START_ADDR_1_DST1 0x128
#define CDM_MSGLD_HOST_START_ADDR_0_DST1 0x134
#define CDM_MSGLD_HOST_START_ADDR_1_DST1 0x138
#define CDM_MSGLD_HOST_END_ADDR_0_DST1 0x13C
#define CDM_MSGLD_HOST_END_ADDR_1_DST1 0x140
#define CDM_MSGST_HOST_END_ADDR_0_DST1 0x12C
#define CDM_MSGST_HOST_END_ADDR_1_DST1 0x130
#define CDM_HOST_CTRL_REG_DST1 0x144
#define CDM_MSGST_CSI_DEST 0x16C
#define CDM_MSGLD_CSI_DEST 0x170
#define CDM_MSGLD_PASS_CNTR_DST1 0x10
#define CDM_MSGLD_FAIL_CNTR_DST1 0x14
#define CDM_MSGLD_CTRL_REG 0x4
#define CDM_MSGST_RSP_STAT 0x8
#define CDM_MSGLD_RSP_STAT 0xC
#define CDM_MSGST_CTRL_REG 0x0

/*MSGST_CMD_RAM*/
#define MSGST_CTRL0 0x8000
#define MSGST_CTRL1 0x8004
#define MSGST_CTRL2 0x8008
#define MSGST_CTRL3 0x800C
#define MSGST_CTRL4 0x8010
#define MSGST_CTRL5 0x8014
#define MSGST_CTRL6 0x8018
#define MSGST_CTRL7 0x801C

/*MSGLD_CMD_RAM*/
#define MSGLD_CTRL0 0x18000
#define MSGLD_CTRL1 0x18004
#define MSGLD_CTRL2 0x18008
#define MSGLD_CTRL3 0x1800C
#define MSGLD_CTRL4 0x18010

typedef uint32_t cdm_reg_t;

/**
 * msgload command layout.
 *
 * The cDM msgload exerciser cycles over commands in the MSGLD_PAYLOAD_RAM
 * issuing each one in turn to cDM. Looping back around if this is requested.
 * The exerciser uses the address in PCI0_MSGLD_HOST_START_ADDR_0 and
 * PCI0_MSGLD_HOST_START_ADDR_1 for reads from pci0 and
 * PSX_MSGLD_HOST_START_ADDR_0 and PSX_MSGLD_HOST_START_ADDR_1 for reads from
 * psx to work out the address the msgload should be targetted at. The first
 * load makes a read from the initial address configured above, the next from
 * this address plus the length of the previous and so on.
 *
 * The engine will validate the values using the seed and type_of_pattern in the
 * command. The seed sets the initial starting point and the type_of_pattern
 * tells the engine how the data stored in PSX/PCI0 was generated.
 *
 * See
 * https://cognidox.xilinx.com/XN-201427-PS Issues 1 (v2.0.0) and 1B (v2.1.0)
 */
typedef union cdm_msgld_cmd_s {
	struct {
		/* MSGLD_CTRL0 (0x0) */
		u32 length : 9;
		u32 msgld_op : 2;
		u32 data_width : 1;
		u32 relaxed_read : 1;
		u32 use_addr_spc_tbl__reserved : 1;
		u32 fnc : 16;
		u32 use_addr_tbl__reserved : 1;
		u32 addr_translated : 1;

		/* MSGLD_CTRL1 (0x4) */
		u32 rc_id : 6;
		u32 client_id : 4;
		u32 op : 2;
		u32 csi_dst : 5;
		u32 csi_dst_fifo : 9;
		u32 start_offset : 5;
		u32 reserved1 : 1;

		/* MSGLD_CTRL2 (0x8) */
		u32 response_cookie : 12;
		u32 no_snoop : 1;
		u32 ro : 1;
		u32 ido : 1;
		u32 seed_value : 8;
		u32 type_of_pattern : 2;
		u32 reserved2 : 7;

		/* MSGLD_CTRL3 (0xC) */
		u32 enable : 1;
		u32 pasid : 20;
		u32 execute_rq : 1;
		u32 privileged_mode_rq : 1;
		u32 reserved3 : 9;

		/* MSGLD_CTRL4 (0x10) */
		u32 nop : 16;
		u32 reserved4 : 16;
	} of;

	cdm_reg_t reg[5];
} cdm_msgld_cmd_t;

typedef union cdm_msgld_ctrl_reg_s {
	struct {
		u32 start : 1;
		u32 pkt_cnt : 1;
		u32 num_req : 30;
	} of;
	cdm_reg_t reg[1];
} cdm_msgld_ctrl_reg_t;

typedef union cdm_msgld_rsp_stat_s {
	struct {
		u32 resp_recv : 1;
		u32 req_sent : 1;
		u32 resv : 30;
	} of;
	cdm_reg_t reg[1];
} cdm_msgld_rsp_stat_t;

typedef union msgld_pass_cntr_s {
	struct {
		u32 pkt_pass_cntr;
	} of;
	cdm_reg_t reg[1];
} msgld_pass_cntr_t;

typedef union msgld_fail_cntr_s {
	struct {
		u32 pkt_fail_cntr;
	} of;
	cdm_reg_t reg[1];
} msgld_fail_cntr_t;

typedef union msgld_resp_s {
	struct {
		u32 response_cookie : 12;
		u32 start_offset : 5;
		u32 zero_byte : 1;
		u32 rc_id : 6;
		u32 mty : 5;
		u32 resv : 3;
	} of;
	cdm_reg_t reg[1];
} msgld_resp_t;

/**
 * The msgstore request counter wraps in hardware at < 32 bits.
 */
#define MSGST_REQ_CNTR_MASK ((1 << 30) - 1)

typedef union msgld_req_cntr_s {
	struct {
		u32 req_cnt_buf;
	} of;
	cdm_reg_t reg[1];
} msgld_req_cntr_t;

typedef union msgst_req_cntr_s {
	struct {
		u32 req_cnt_buf;
	} of;
	cdm_reg_t reg[1];
} msgst_req_cntr_t;

/**
 * Command response layout (RESPONSE_RAM register)
 *
 * See
 * https://cognidox.xilinx.com/XN-201427-PS Issue 1B
 */
typedef union response_s {
	struct {
		u32 client_id : 4;
		u32 error : 1;
		u32 start_offset : 5;
		u32 rc_id : 6;
		u32 zero_byte : 1;
		u32 status : 2;
		u32 error_status : 3;
		u32 mty : 5;
		u32 resv : 5;
	} of;
	cdm_reg_t reg[1];
} response_t;

/**
 * msgstore command layout.
 *
 * The cDM msgsotre exerciser cycles over commands in the MSGST_PAYLOAD_RAM
 * issuing each one in turn to cDM. Looping back around if this is requested.
 * The exerciser uses the address in PCI0_MSGST_HOST_ADDR_0 and
 * PCI0_MSGST_HOST_ADDR_1 for reads from pci0 and PSX_MSGST_HOST_ADDR_0 and
 * PSX_MSGST_HOST_ADDR_1 for reads from psx to work out the address the msgstore
 * should be targetted at. The first store makes a write to the initial address
 * configured above, the next from this address plus the length of the pervious
 * and so on.
 *
 * The engine will create the data to write to memory using the seed and
 * type_of_pattern in the command. The seed sets the initial starting point and
 * the type_of_pattern tells the engine how the data should be generated.
 *
 * See
 * https://cognidox.xilinx.com/XN-201592-TC Draft C (v3.1.x)
 */
typedef union cdm_msgst_cmd_s {
	struct {
		/* MSGST_CTRL0 (0x0) */
		u32 length : 9;
		u32 op : 2;
		u32 use_addr_spc_tbl__reserved : 1;
		u32 fnc : 16;
		u32 use_addr_tbl__reserved : 1;
		u32 addr_translated : 1;
		u32 reserved1 : 2;

		/* MSGST_CTRL1 (0x4) */
		u32 nop : 8;
		u32 reserved2 : 3;
		u32 th : 1;
		u32 ph : 2;
		u32 st_hi : 8;
		u32 csi_dst : 5;
		u32 start_offset : 5;

		/* MSGST_CTRL2 (0x8) */
		u32 response_req : 1;
		u32 response_cookie : 12;
		u32 data_width : 2;
		u32 client_id : 4;
		u32 csi_dst_fifo : 9;
		u32 reserved3 : 4;

		/* MSGST_CTRL3 (0xC) */
		u32 no_snoop : 1;
		u32 ro : 1;
		u32 ido : 1;
		u32 st2m_ordered : 1;
		u32 wait_pld_pkt_id : 16;
		u32 seed_value : 8;
		u32 type_of_pattern : 2;
		u32 execute_rq : 1;
		u32 privileged_mode_rq : 1;

		/* MSGST_CTRL4 (0x10) */
		union {
			u32 higher_addr;
			struct {
				u32 irq_vector : 16;
				u32 reserved4 : 16;
			};
		};

		/* MSGST_CTRL5 (0x14) */
		u32 ecc : 11;
		u32 enable : 1;
		u32 pasid : 20;
	} of;
	cdm_reg_t reg[6];
} cdm_msgst_cmd_t;

typedef union cdm_msgst_ctrl_reg_s {
	struct {
		u32 start : 1;
		u32 resv : 1;
		u32 num_req : 30;
	} of;
	cdm_reg_t reg[1];
} cdm_msgst_ctrl_reg_t;

typedef union cdm_msgst_rsp_stat_s {
	struct {
		u32 req_sent : 1;
		u32 resv : 31;
	} of;
	cdm_reg_t reg[1];
} cdm_msgst_rsp_stat_t;

typedef union cdm_msgst_resp_recv_cntr_s {
	struct {
		u32 resp_recv_cntr;
	} of;
	cdm_reg_t reg[1];
} cdm_msgst_resp_recv_cntr_t;

typedef union cdm_to_csi_dest_s {
	struct {
		uint32_t csi_dest_dst1 : 8;
		uint32_t csi_dest_dst2 : 8;
		uint32_t reserved : 16;
	} of;

	cdm_reg_t reg[1];
} cdm_to_csi_dest_t;

typedef union cdm_engine_address_s {
	struct {
		u32 lower;
		u32 higher;
	} split_addr;
	uint64_t addr;
	cdm_reg_t reg[2];
} cdm_engine_address_t;

typedef union cdm_mem_ctrl_s {
	struct {
		u32 done : 1;
		u32 reserved : 31;
	} of;
	cdm_reg_t reg[1];
} cdm_mem_ctrl_t;

typedef union cdm_engine_setup_s {
	struct {
		u32 reset : 1;	/**< Note this is active-low */
		u32 rsvd_1 : 31;
	} of;
	cdm_reg_t reg[1];
} cdm_engine_setup_t;

/**
 * Structure for enabling multiple cDM exerciser engines at once
 *
 * See
 * https://cognidox.xilinx.com/XN-201427-PS Issues 2
 */
typedef union cdm_engine_enable_s {
	struct {
		u32 msgstore : 1;
		u32 msgload : 1;
		u32 msgst_infinite : 1;
		u32 msgld_infinite : 1;
		u32 msgld_chk_bypass : 1;
		u32 rsvd_2 : 27;
	} of;
	cdm_reg_t reg[1];
} cdm_engine_enable_t;
#endif
