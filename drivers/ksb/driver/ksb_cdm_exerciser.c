// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#include <linux/kernel.h>
#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/pci.h>

#include <linux/cdev.h>
#include <uapi/linux/in.h>

#include "ksb_cdm_reg.h"
#include "ksb_cdx_dev.h"
#include "ksb_pci_drv.h"
#include "ksb_pci_io.h"
#include "ksb_cdm_exerciser.h"

/****************** Structure *************************/
typedef struct cdm_dma_reg_s {
	cdm_reg_t low_reg;
	cdm_reg_t high_reg;
} cdm_dma_reg_t;

typedef struct cdm_cmd_params_s {
	cdx_dev_dma_op_t op;
	u8 seed;
	u32 req_size;
	u32 req_count[CDM_DMA_MSGMAX];
} cdm_cmd_params_t;

/************************* Global Variables and const **********************/
static cdm_dma_reg_t cdm_dma_start[CDM_DMA_MSGMAX] =
					{
						{
							.low_reg = CDM_MSGST_HOST_START_ADDR_0_DST1,
							.high_reg = CDM_MSGST_HOST_START_ADDR_1_DST1,
						},

						{
							.low_reg = CDM_MSGLD_HOST_START_ADDR_0_DST1,
							.high_reg = CDM_MSGLD_HOST_START_ADDR_1_DST1,
						},
					 };

static cdm_dma_reg_t cdm_dma_end[CDM_DMA_MSGMAX] =
					{
						{
							.low_reg = CDM_MSGST_HOST_END_ADDR_0_DST1,
							.high_reg = CDM_MSGST_HOST_END_ADDR_1_DST1,
						},

						{
							.low_reg = CDM_MSGLD_HOST_END_ADDR_0_DST1,
							.high_reg = CDM_MSGLD_HOST_END_ADDR_1_DST1,
						},
					 };

/********************************************************************************/
#ifdef DBG_TRACE
static void cdm_exerciser_print_buf(uint8_t *src, u32 num_req, u32 req_size)
{
	char pr_buf[256];
	size_t offset = 0;
	size_t pos = 0;
	size_t index;
	size_t total_sz = 256;
	size_t len = num_req * req_size;
 
	memset(pr_buf, 0, sizeof(pr_buf));

	for (index = 0; index < len; index++) {
		offset = snprintf(pr_buf + pos, total_sz, "%.2u ", *(src + index));

		if (index != 0 && (index + 1) % 32 == 0) {
			printk("%s", pr_buf);
			memset(pr_buf, 0, sizeof(pr_buf));
			total_sz = 256;
			pos = 0;
			continue;
		}

		if (index % req_size == 0) {
			printk("Start of next Req:\n");
		}

		total_sz -= offset;
		pos += offset;
	}

	printk("%s\n", pr_buf);
}
#endif

/**
 * write into CDM device
 * @cdx_dev		Pointer to the CDM device
 * @offset		CDM Register offset
 * @size		Size in double word
 * @data	 	Data to write into CDM device
 */
static void cdm_exerciser_reg_wr(cdx_device_t *cdx_dev, u32 offset,
				 size_t size, u32 *data)
{
	u32 reg = CDM_OFFSET + offset;
	u32 i;

	for(i = 0; i < size; i++) {
		ksb_io_write32(cdx_dev->pci_dev,
			       reg + (i * sizeof(u32)), data[i]);
	}
}

/**
 * read into CDM device
 * @cdx_dev		Pointer to the CDM device
 * @offset		CDM Register offset
 * @size		Size in double word
 * @data	 	Data read from CDM device
 */
static void cdm_exerciser_reg_rd(cdx_device_t *cdx_dev, u32 offset,
				 size_t size, u32 *data)
{
	u32 reg = CDM_OFFSET + offset;
	u32 i;

	for(i = 0; i < size; i++) {
		data[i] = ksb_io_read32(cdx_dev->pci_dev,
					reg + (i * sizeof(u32)));
	}
}

static void cdm_msgst_cmd_init(cdm_msgst_cmd_t *cmd, unsigned func_id,
			       unsigned length, uint8_t seed)
{
	memset(cmd, 0, sizeof(*cmd));
	cmd->of.length = length;
	cmd->of.op = 0; /* Store MSG op */
	cmd->of.fnc = func_id;
	cmd->of.addr_translated = 0;
	cmd->of.csi_dst = 0x4; /* PCIe Controller 0 */
	cmd->of.start_offset = 0;
	cmd->of.response_req = 0;
	cmd->of.response_cookie = 0;
	cmd->of.data_width = 1; /* 32B interface width */
	cmd->of.client_id = 1; /* Client ID FAB1 */
	cmd->of.csi_dst_fifo = 0;
	cmd->of.no_snoop = 0;
	cmd->of.ro = 0;
	cmd->of.ido = 0;
	cmd->of.st2m_ordered = 0;
	cmd->of.wait_pld_pkt_id = 0;
	cmd->of.seed_value = seed;
	cmd->of.type_of_pattern = 1; /* Pattern increment by 1 */
	cmd->of.execute_rq = 0;
	cmd->of.privileged_mode_rq = 0;
	cmd->of.irq_vector = 0;
	cmd->of.th = 0;
	cmd->of.ph = 0;
	cmd->of.st_hi = 0;
	cmd->of.ecc = 0;
	cmd->of.enable = 0;
	cmd->of.pasid = 0;
	cmd->of.nop = 0;
}

static void cdm_msgld_cmd_init(cdm_msgld_cmd_t *cmd, unsigned func_id,
			       unsigned length, uint8_t seed)
{
	memset(cmd, 0, sizeof(*cmd));
	cmd->of.length = length;
	cmd->of.msgld_op = 0; /* Load MSG op */
	cmd->of.data_width = 1;
	cmd->of.relaxed_read = 0;
	cmd->of.fnc = func_id;
	cmd->of.addr_translated = 0;
	cmd->of.rc_id = 0xA; /* Read Channel ID */
	cmd->of.client_id = 1; /* Client ID FAB1 */
	cmd->of.op = 0;
	cmd->of.csi_dst = 0x4; /* PCIe Controller 0 */
	cmd->of.csi_dst_fifo = 0;
	cmd->of.start_offset = 0;
	cmd->of.response_cookie = 0x200; /* Cookie values should lie between 512 to 1023,
					    For now using hardcoded value */
	cmd->of.no_snoop = 0;
	cmd->of.ro = 0;
	cmd->of.ido = 0;
	cmd->of.seed_value = seed;
	cmd->of.type_of_pattern = 1;
	cmd->of.enable = 0;
	cmd->of.pasid = 0;
	cmd->of.execute_rq = 0;
	cmd->of.privileged_mode_rq = 0;
	cmd->of.nop = 0;
}

static void cdm_exerciser_init(cdx_device_t *cdx_dev)
{
	cdm_engine_setup_t global_setup;
	u32 zero_addr = 0;
	size_t size = SIZE_IN_DWORD(zero_addr);
	u32 i;

	global_setup.reg[0] = 0;

	/* Clear CDM global registers */
	cdm_exerciser_reg_wr(cdx_dev, CDM_GLOBAL_START, size, &zero_addr);
	cdm_exerciser_reg_wr(cdx_dev, CDM_SOFT_RSTN, size, &zero_addr);
	/* Pull the CDM out of soft reset */
	global_setup.of.reset = 1;
	cdm_exerciser_reg_wr(cdx_dev, CDM_SOFT_RSTN,
			     SIZE_IN_DWORD(global_setup), global_setup.reg);

	/* Clear store/load DMA address registers */
	for (i = 0; i < CDM_DMA_MSGMAX; i++) {
		cdm_exerciser_reg_wr(cdx_dev, cdm_dma_start[i].low_reg,
							 size, &zero_addr);
		cdm_exerciser_reg_wr(cdx_dev, cdm_dma_start[i].high_reg,
							 size, &zero_addr);

		cdm_exerciser_reg_wr(cdx_dev, cdm_dma_end[i].low_reg,
							 size, &zero_addr);
		cdm_exerciser_reg_wr(cdx_dev, cdm_dma_end[i].high_reg,
							 size, &zero_addr);
	}

	/* Clear store/load DMA control registers */
	cdm_exerciser_reg_wr(cdx_dev, CDM_HOST_CTRL_REG_DST1, size, &zero_addr);
	cdm_exerciser_reg_wr(cdx_dev, CDM_MSGST_CTRL_REG, size, &zero_addr);
	cdm_exerciser_reg_wr(cdx_dev, CDM_MSGLD_CTRL_REG, size, &zero_addr);

	/* Clear store/load CSI dest registers */
	cdm_exerciser_reg_wr(cdx_dev, CDM_MSGST_CSI_DEST, size, &zero_addr);
	cdm_exerciser_reg_wr(cdx_dev, CDM_MSGLD_CSI_DEST, size, &zero_addr);
}

static void
cdm_exerciser_mem_init(cdx_device_t *cdx_dev, cdx_dev_dma_op_t op)
{
	cdm_mem_ctrl_t mem_ctrl;
	cdm_to_csi_dest_t csi_dest;
	cdm_engine_address_t start_addr;
	cdm_engine_address_t end_addr;

	memset(&mem_ctrl, 0, sizeof(mem_ctrl));
	memset(&csi_dest, 0, sizeof(csi_dest));
	memset(&start_addr, 0, sizeof(start_addr));
	memset(&end_addr, 0, sizeof(end_addr));

	csi_dest.of.csi_dest_dst1 = 0x4; /* PCIe Controller 0 */
	start_addr.addr = cdx_dev->dma_msg_ctx[op].dma_addr;
	end_addr.addr = cdx_dev->dma_msg_ctx[op].dma_end_addr;

	/* Configure CSI Dest to CDM excerciser */
	cdm_exerciser_reg_wr(cdx_dev, CDM_MSGST_CSI_DEST,
			     SIZE_IN_DWORD(csi_dest), csi_dest.reg);
	cdm_exerciser_reg_wr(cdx_dev, CDM_MSGLD_CSI_DEST,
			     SIZE_IN_DWORD(csi_dest), csi_dest.reg);

	/* Configure DMA engine MEM */
	cdm_exerciser_reg_wr(cdx_dev, cdm_dma_start[op].low_reg,
			     SIZE_IN_DWORD(start_addr), start_addr.reg);
	cdm_exerciser_reg_wr(cdx_dev, cdm_dma_end[op].low_reg,
			     SIZE_IN_DWORD(end_addr), end_addr.reg);
	mem_ctrl.of.done = 1;
	cdm_exerciser_reg_wr(cdx_dev, CDM_HOST_CTRL_REG_DST1,
			     SIZE_IN_DWORD(mem_ctrl), mem_ctrl.reg);

}

static void
cdm_exerciser_cmd_init(cdx_device_t *cdx_dev, cdm_cmd_params_t *param)
{
	cdm_msgst_cmd_t msgst_cmd;
	cdm_msgld_cmd_t msgld_cmd;
	u32 msgst_cmd_offset;
	u32 msgld_cmd_offset;
	u32 seed_next;
	u32 func_id;
	u32 i;

	func_id = cdx_dev->pci_dev->devfn;
	cdm_msgst_cmd_init(&msgst_cmd, func_id, param->req_size, param->seed);
	cdm_msgld_cmd_init(&msgld_cmd, func_id, param->req_size, param->seed);

	/* Configure message store commands */
	seed_next = param->seed;
	for (i = 0; i < param->req_count[CDM_DMA_MSGST]; i++) {
		msgst_cmd.of.seed_value = seed_next;
		msgst_cmd_offset = (i * 0x20) + MSGST_CTRL0;
		cdm_exerciser_reg_wr(cdx_dev, msgst_cmd_offset,
				     SIZE_IN_DWORD(msgst_cmd), msgst_cmd.reg);
		seed_next += 1;
	}

	/* Configure message load commands */
	for (i = 0; i < param->req_count[CDM_DMA_MSGLD]; i++) {
		msgld_cmd_offset = (i * 0x20) + MSGLD_CTRL0;
		cdm_exerciser_reg_wr(cdx_dev, msgld_cmd_offset,
				     SIZE_IN_DWORD(msgld_cmd), msgld_cmd.reg);
	}
}

static void
cdm_exerciser_start(cdx_device_t *cdx_dev, cdm_cmd_params_t *param)
{
	cdm_msgld_ctrl_reg_t msgld_ctrl;
	cdm_msgst_ctrl_reg_t msgst_ctrl;
	cdm_engine_enable_t cdm_engine;

	memset(&msgld_ctrl, 0, sizeof(msgld_ctrl));
	memset(&msgst_ctrl, 0, sizeof(msgst_ctrl));
	memset(&cdm_engine, 0, sizeof(cdm_engine));

	cdm_engine.of.msgstore = (param->op == CDM_DMA_MSGST) ? 1 : 0;
	cdm_engine.of.msgload = (param->op == CDM_DMA_MSGLD) ? 1 : 0;

	msgst_ctrl.of.start = 0;
	msgst_ctrl.of.num_req = param->req_count[param->op];

	msgld_ctrl.of.start = 0;
	msgld_ctrl.of.pkt_cnt = 1;
	msgld_ctrl.of.num_req = param->req_count[param->op];

	cdm_exerciser_reg_wr(cdx_dev, CDM_MSGST_CTRL_REG,
			     SIZE_IN_DWORD(msgst_ctrl), msgst_ctrl.reg);
	cdm_exerciser_reg_wr(cdx_dev, CDM_MSGLD_CTRL_REG,
			     SIZE_IN_DWORD(msgld_ctrl), msgld_ctrl.reg);

	cdm_exerciser_reg_wr(cdx_dev, CDM_GLOBAL_START,
			     SIZE_IN_DWORD(cdm_engine), cdm_engine.reg);
}

static bool
cdm_exerciser_check_status(cdx_device_t *cdx_dev, cdm_cmd_params_t *param)
{
	cdm_msgld_rsp_stat_t msgld_rsp;
	cdm_msgst_rsp_stat_t msgst_rsp;
	msgld_pass_cntr_t msgld_pass;
	msgld_fail_cntr_t msgld_fail;
	u32 *data;
	u32 retry_count;
	u32 reg_off;
	bool status;

	msgld_rsp.reg[0] = 0;
	msgst_rsp.reg[0] = 0;
	msgld_pass.reg[0] = 0;
	msgld_fail.reg[0] = 0;
	status = false;
	retry_count = 5;

	reg_off = (param->op == CDM_DMA_MSGST) ? CDM_MSGST_RSP_STAT : \
                                             CDM_MSGLD_RSP_STAT;
	data = (param->op == CDM_DMA_MSGST) ? msgst_rsp.reg : msgld_rsp.reg;

	while (retry_count > 0) {
		mdelay(10);
		cdm_exerciser_reg_rd(cdx_dev, reg_off, SIZE_IN_DWORD(*data), data);
		if (param->op == CDM_DMA_MSGST && msgst_rsp.of.req_sent == 1) {
			status = true;
			break;
		}

		if (param->op == CDM_DMA_MSGLD &&
			msgld_rsp.of.resp_recv == 1 &&
			msgld_rsp.of.req_sent == 1) {
			cdm_exerciser_reg_rd(cdx_dev, CDM_MSGLD_PASS_CNTR_DST1,
					     SIZE_IN_DWORD(*data), msgld_pass.reg);
			cdm_exerciser_reg_rd(cdx_dev, CDM_MSGLD_FAIL_CNTR_DST1,
					     SIZE_IN_DWORD(*data), msgld_fail.reg);
#ifdef DBG_TRACE
			printk("MSG Load pass counter %u\n", msgld_pass.of.pkt_pass_cntr);
			printk("MSG Load fail counter %u\n", msgld_fail.of.pkt_fail_cntr);
#endif
			if (!msgld_fail.of.pkt_fail_cntr)
				status = true;
			break;
		}

		retry_count--;
	}

#ifdef DBG_TRACE
	cdm_exerciser_print_buf(cdx_dev->dma_msg_ctx[param->op].mem,
			  param->req_count[param->op], param->req_size);
#endif

	return status;
}

static bool cdm_exerciser_run(cdx_device_t *cdx_dev, cdm_cmd_params_t *param)
{
	cdm_exerciser_init(cdx_dev);
	cdm_exerciser_mem_init(cdx_dev, param->op);
	cdm_exerciser_cmd_init(cdx_dev, param);
	cdm_exerciser_start(cdx_dev, param);
	return cdm_exerciser_check_status(cdx_dev, param);
}

static bool cdm_exerciser_validate_msgst(u8 *req_mem, cdm_cmd_params_t *param)
{
	size_t i, j;
	size_t index;

	for (i = 0, index = 0; i < param->req_count[CDM_DMA_MSGST]; i++) {
		for (j = 0; j < param->req_size; j++) {
			if (req_mem[index++] != (uint8_t)(j + param->seed))
				return false;
		}

		param->seed += 1;
	}

	return true;
}

static void cdm_exerciser_populate_msgld(u8 *req_mem, cdm_cmd_params_t *param)
{
	size_t i, j;
	size_t index;

	for (i = 0, index = 0; i < param->req_count[CDM_DMA_MSGLD]; i++) {
		for (j = 0; j < param->req_size; j++)
			req_mem[index++] = (uint8_t)(j + param->seed);
	}
}

static int cdm_exerciser_run_msgst(cdx_device_t *cdx_dev,
				   cdm_cmd_params_t *param,
				   uint8_t *dev_buf)
{
	bool status;

	status = cdm_exerciser_run(cdx_dev, param);
	if (!status) {
		return EIO;
 	}

	status = cdm_exerciser_validate_msgst(dev_buf, param);
	if (!status) {
		return EINVAL;
	}

	memset(cdx_dev->dma_msg_ctx[CDM_DMA_MSGST].mem, 0, CDM_DEVICE_DMA_SIZE);
	return 0;
}

static int cdm_exerciser_run_msgld(cdx_device_t *cdx_dev,
				   cdm_cmd_params_t *param,
				   uint8_t *dev_buf)
{
	bool status;

	cdm_exerciser_populate_msgld(dev_buf, param);
	status = cdm_exerciser_run(cdx_dev, param);
	if (!status) 
		return EIO;

	return 0;
}

int cdm_exerciser_execute_cmd(cdx_device_t *cdx_dev, cdx_dev_dma_op_t op,
			      u8 seed, u32 req_size, u32 req_count)
{
	cdm_cmd_params_t param;
	size_t dev_buf_size;
	uint8_t *dev_buf;
	int num_req;
	int served_req;
	int ret;

	memset(&param, 0, sizeof(param));
	param.op = op;
	param.seed = seed;
	param.req_size = req_size;

	dev_buf = cdx_dev->dma_msg_ctx[op].mem;
	dev_buf_size = CDM_DEVICE_DMA_SIZE - CDM_EXERCISER_DATA_CHUNK_SIZE; 
	num_req = req_count;
	served_req = 0;
	while (num_req > 0) {
		served_req = MIN(MIN((dev_buf_size / param.req_size), num_req),
				 CDM_COMMAND_ENGINE_COUNT);
		param.req_count[op] = served_req;

		if (op == CDM_DMA_MSGST)
			ret = cdm_exerciser_run_msgst(cdx_dev, &param, dev_buf);
		else
			ret = cdm_exerciser_run_msgld(cdx_dev, &param, dev_buf);

		if (ret)
			break;

		/* The cdm_exerciser_run() increaments the seed value by One for
		 * for each request. Therefore, update the seed before processing
		 * the next batch of CDM requests */
		if (op == CDM_DMA_MSGST)
			param.seed += served_req;

		num_req -= served_req;
	}

	return ret;
}
