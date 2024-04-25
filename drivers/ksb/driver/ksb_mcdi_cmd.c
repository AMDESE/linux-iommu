// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#include <linux/module.h>

#include "ksb_pci_drv.h"
#include "ksb_mcdi.h"
#include "ksb_mcdi_cmd.h"

int ksb_mcdi_cmd_get_func_id(struct ksb_drv_ctx *ksb_drv, uint32_t *pf_id,
			     uint32_t *vf_id)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_FUNCTION_INFO_OUT_V2_LEN);
	struct ksb_mcdi *mc_ctx = &ksb_drv->mc_ctx;
	size_t outlen;
	int ret;

	ret = ksb_mcdi_rpc(mc_ctx, MC_CMD_GET_FUNCTION_INFO, NULL, 0,
			   outbuf, sizeof(outbuf), &outlen);
	if (ret)
		return ret;

	if (outlen != MC_CMD_GET_FUNCTION_INFO_OUT_V2_LEN)
		return -EIO;

	*pf_id = MCDI_DWORD(outbuf, GET_FUNCTION_INFO_OUT_V2_PF);
	*vf_id = MCDI_DWORD(outbuf, GET_FUNCTION_INFO_OUT_V2_VF);
	return 0;
}

int ksb_mcdi_cmd_get_addr_spc(struct ksb_drv_ctx *ksb_drv, uint64_t *addr_spc_id)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_EFTEST_GET_ADDR_SPC_ID_EXT_OUT_LEN);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_EFTEST_GET_ADDR_SPC_ID_EXT_IN_LEN);
	struct ksb_mcdi *mc_ctx = &ksb_drv->mc_ctx;
	size_t outlen;
	int ret;

	MCDI_SET_BYTE(inbuf, EFTEST_OP_IN_EFTEST_ID,
		      MC_CMD_EFTEST_OP_IN_EFTEST_GET_ADDR_SPC_ID_EXT);
	MCDI_SET_BYTE(inbuf, EFTEST_OP_IN_EFTEST_OP, MC_CMD_EFTEST_GET_ADDR_SPC_ID_EXT_IN_MAIN);

	MCDI_SET_WORD(inbuf, EFTEST_GET_ADDR_SPC_ID_EXT_IN_EFTEST_OP_RSVD, 0x0);
	MCDI_SET_DWORD(inbuf, EFTEST_GET_ADDR_SPC_ID_EXT_IN_PATH_ID, 1);

	ret = ksb_mcdi_rpc(mc_ctx, MC_CMD_EFTEST_OP, inbuf, sizeof(inbuf),
			   outbuf, sizeof(outbuf), &outlen);
	if (ret)
		return ret;

	*addr_spc_id = MCDI_QWORD(outbuf, EFTEST_GET_ADDR_SPC_ID_EXT_OUT_ADDR_SPC_ID);

	return 0;
}

int ksb_mcdi_cmd_get_addr_spc_fields(struct ksb_drv_ctx *ksb_drv,
				     struct dpu_addr_space *addr_space)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_EFTEST_EXPAND_ADDR_SPC_FIELDS_OUT_LEN);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_EFTEST_EXPAND_ADDR_SPC_FIELDS_V2_IN_LEN);
	struct ksb_mcdi *mc_ctx = &ksb_drv->mc_ctx;
	size_t outlen;
	int ret;

	MCDI_SET_BYTE(inbuf, EFTEST_OP_IN_EFTEST_ID,
		      MC_CMD_EFTEST_OP_IN_EFTEST_EXPAND_ADDR_SPC_FIELDS);
	MCDI_SET_BYTE(inbuf, EFTEST_OP_IN_EFTEST_OP,
		      MC_CMD_EFTEST_EXPAND_ADDR_SPC_FIELDS_V2_IN_EXPAND_ADDR_SPC);

	MCDI_SET_QWORD(inbuf, EFTEST_EXPAND_ADDR_SPC_FIELDS_V2_IN_ADDR_SPC_ID,
		       addr_space->addr_spc_id);
	MCDI_SET_DWORD(inbuf, EFTEST_EXPAND_ADDR_SPC_FIELDS_V2_IN_SRC,
		       MC_CMD_EFTEST_EXPAND_ADDR_SPC_FIELDS_V2_IN_CDM);

	ret = ksb_mcdi_rpc(mc_ctx, MC_CMD_EFTEST_OP, inbuf, sizeof(inbuf),
			   outbuf, sizeof(outbuf), &outlen);
	if (ret)
		return ret;

	addr_space->pasid_en = MCDI_BYTE(outbuf, EFTEST_EXPAND_ADDR_SPC_FIELDS_OUT_PASID_EN);
	addr_space->pasid = MCDI_WORD(outbuf, EFTEST_EXPAND_ADDR_SPC_FIELDS_OUT_PASID);
	addr_space->func_id = MCDI_WORD(outbuf, EFTEST_EXPAND_ADDR_SPC_FIELDS_OUT_REQUESTER_ID);
	addr_space->dpu_dst_id = MCDI_BYTE(outbuf, EFTEST_EXPAND_ADDR_SPC_FIELDS_OUT_DPU_DST_ID);

	return 0;
}
