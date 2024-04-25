// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#ifndef __KSB_MCDI_CMD
#define __KSB_MCDI_CMD

int ksb_mcdi_cmd_get_func_id(struct ksb_drv_ctx *ksb_drv,
			     u32 *pf_id, u32 *vf_id);

int ksb_mcdi_cmd_get_addr_spc_fields(struct ksb_drv_ctx *ksb_drv, struct dpu_addr_space *addr_space);

int ksb_mcdi_cmd_get_addr_spc(struct ksb_drv_ctx *ksb_drv, uint64_t *addr_spc_id);

#endif
