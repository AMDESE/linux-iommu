// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt)     "AMD-Vi: " fmt
#define dev_fmt(fmt)    pr_fmt(fmt)

#include <linux/amd-iommu.h>

#include <asm/sev.h>

#include "amd_iommu.h"
#include "amd_iommu_types.h"
#include "amd_viommu.h"

const struct amd_sviommu_guest_ops *sev_guest_ops;

int amd_sviommu_register_guest_ops(const struct amd_sviommu_guest_ops *ops)
{
	sev_guest_ops = ops;
	return 0;
}
EXPORT_SYMBOL(amd_sviommu_register_guest_ops);

struct guest_cmd_buf_data {
	union {
		u64 data;
		struct {
			u64 cmdlen	  : 4,
			    reserved	  : 4,
			    cmdbuf_en	  : 1,
			    comwaitint_en : 1,
			    reserved2     : 2,
			    combase	  : 40,
			    reserved3     : 12;
		};
	};
};

int amd_sviommu_setup_cmd_buf(struct amd_iommu *iommu, bool enable)
{
	struct guest_cmd_buf_data data;

	memset(&data, 0, sizeof(struct guest_cmd_buf_data));
	data.cmdlen = iommu->cmd_buf_len;
	data.cmdbuf_en = enable;
	data.comwaitint_en = 0;

	data.combase = (iommu_virt_to_phys(iommu->cmd_buf) >> 12);

	if (!sev_guest_ops || !sev_guest_ops->setup_cmdbuf)
		return -EINVAL;

	pr_debug("%s: data=%#llx\n", __func__, data.data);
	return sev_guest_ops->setup_cmdbuf(iommu->devid, &data.data);
}

struct guest_evt_buf_data {
	union {
		u64 data;
		struct {
			u64 evtlen	    : 4,
			    evtblen	    : 4,
			    evtlog_en	    : 1,
			    evtint_en       : 1,
			    dual_evtlog_en  : 2,
			    evtbase	    : 40,
			    reserved        : 12;
		};
	};
};

int amd_sviommu_setup_evt_log(struct amd_iommu *iommu, bool enable)
{
	struct guest_evt_buf_data data;

	memset(&data, 0, sizeof(struct guest_evt_buf_data));
	data.evtlen = iommu->evt_buf_len;
	data.evtlog_en = enable;
	data.evtint_en = enable;
	data.evtbase = (iommu_virt_to_phys(iommu->evt_buf) >> 12);

	if (!sev_guest_ops || !sev_guest_ops->setup_evtlog)
		return -EINVAL;

	pr_debug("%s: data=%#llx\n", __func__, data.data);
	return sev_guest_ops->setup_evtlog(iommu->devid, &data.data);
}

struct guest_ppr_log_data {
	union {
		u64 data;
		struct {
			u64 pprlen	    : 4,
			    pprblen	    : 4,
			    pprlog_en	    : 1,
			    pprint_en       : 1,
			    ppr_en          : 1,
			    dualpprlog_en   : 2,
			    pprautorsp_en   : 1,
			    blkstopmrk_en   : 1,
			    pprautorspa_on  : 1,
			    pprlogbase      : 40,
			    reserved        : 12;
		};
	};
};

int amd_sviommu_setup_ppr_log(struct amd_iommu *iommu, bool enable)
{
	struct guest_ppr_log_data data;

	memset(&data, 0, sizeof(struct guest_ppr_log_data));
	data.pprlen = iommu->ppr_log_len;
	data.pprlog_en = enable;
	data.pprint_en = enable;
	data.ppr_en = enable;
	data.pprlogbase = (iommu_virt_to_phys(iommu->ppr_log) >> 12);

	if (!sev_guest_ops ||!sev_guest_ops->setup_pprlog)
		return -EINVAL;

	pr_debug("%s: data=%#llx\n", __func__, data.data);
	return sev_guest_ops->setup_pprlog(iommu->devid, &data.data);
}
