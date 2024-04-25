// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#ifndef __KSB_CDM_EXERCISER_H
#define __KSB_CDM_EXERCISER_H

#define CDM_COMMAND_ENGINE_COUNT 1024

int cdm_exerciser_execute_cmd(cdx_device_t *cdx_dev, cdx_dev_dma_op_t op,
			      u8 seed, u32 req_size, u32 req_count);
#endif
