/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright 2008-2013 Solarflare Communications Inc.
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#ifndef KSB_MCDI_H
#define KSB_MCDI_H

#include <linux/mutex.h>
#include <linux/kref.h>
#include <linux/rpmsg.h>

#include "bitfield.h"
#include "mc_driver_pcol.h"

#ifdef DEBUG
#define KSB_WARN_ON_ONCE_PARANOID(x) WARN_ON_ONCE(x)
#define KSB_WARN_ON_PARANOID(x) WARN_ON(x)
#else
#define KSB_WARN_ON_ONCE_PARANOID(x) do {} while (0)
#define KSB_WARN_ON_PARANOID(x) do {} while (0)
#endif

/**
 * enum ksb_mcdi_mode - MCDI transaction mode
 * @MCDI_MODE_EVENTS: wait for an mcdi response callback.
 * @MCDI_MODE_FAIL: we think MCDI is dead, so fail-fast all calls
 */
enum ksb_mcdi_mode {
	MCDI_MODE_EVENTS,
	MCDI_MODE_FAIL,
};

#define MCDI_RPC_TIMEOUT	(10 * HZ)
#define MCDI_RPC_LONG_TIMEOU	(60 * HZ)
#define MCDI_RPC_POST_RST_TIME	(10 * HZ)

#define MCDI_BUF_LEN (8 + MCDI_CTL_SDU_LEN_MAX)

/**
 * enum ksb_mcdi_cmd_state - State for an individual MCDI command
 * @MCDI_STATE_QUEUED: Command not started and is waiting to run.
 * @MCDI_STATE_RETRY: Command was submitted and MC rejected with no resources,
 *	as MC have too many outstanding commands. Command will be retried once
 *	another command returns.
 * @MCDI_STATE_RUNNING: Command was accepted and is running.
 * @MCDI_STATE_RUNNING_CANCELLED: Command is running but the issuer cancelled
 *	the command.
 * @MCDI_STATE_FINISHED: Processing of this command has completed.
 */

enum ksb_mcdi_cmd_state {
	MCDI_STATE_QUEUED,
	MCDI_STATE_RETRY,
	MCDI_STATE_RUNNING,
	MCDI_STATE_RUNNING_CANCELLED,
	MCDI_STATE_FINISHED,
};

/**
 * struct ksb_mcdi - KSB MCDI Firmware interface, to interact
 *	with KSB controller.
 * @mcdi: MCDI interface
 * @mcdi_ops: MCDI operations
 * @r5_rproc : R5 Remoteproc device handle
 * @rpdev: RPMsg device
 * @ept: RPMsg endpoint
 * @work: Post probe work
 */
struct ksb_mcdi {
	/* MCDI interface */
	struct ksb_mcdi_data *mcdi;
	const struct ksb_mcdi_ops *mcdi_ops;

	struct rproc *r5_rproc;
	struct rpmsg_device *rpdev;
	struct rpmsg_endpoint *ept;
	struct work_struct work;
};

struct ksb_mcdi_ops {
	void (*mcdi_request)(struct ksb_mcdi *mc_ctx,
			     const struct ksb_dword *hdr, size_t hdr_len,
			     const struct ksb_dword *sdu, size_t sdu_len);
	void (*mcdi_response)(struct ksb_mcdi *mc_ctx, struct ksb_dword *outbuf,
			      size_t offset, size_t outlen);
	bool (*mcdi_rpc_timeout)(struct ksb_mcdi *mc_ctx, unsigned int cmd);
};

typedef void ksb_mcdi_async_completer(struct ksb_mcdi *mc_ctx,
				      unsigned long cookie, int rc,
				      struct ksb_dword *outbuf,
				      size_t outlen_actual);

/**
 * struct ksb_mcdi_cmd - An outstanding MCDI command
 * @ref: Reference count. There will be one reference if the command is
 *	in the mcdi_iface cmd_list, another if it's on a cleanup list,
 *	and a third if it's queued in the work queue.
 * @list: The data for this entry in mcdi->cmd_list
 * @cleanup_list: The data for this entry in a cleanup list
 * @work: The work item for this command, queued in mcdi->workqueue
 * @mcdi: The mcdi_iface for this command
 * @state: The state of this command
 * @inlen: inbuf length
 * @inbuf: Input buffer
 * @quiet: Whether to silence errors
 * @reboot_seen: Whether a reboot has been seen during this command,
 *	to prevent duplicates
 * @seq: Sequence number
 * @started: Jiffies this command was started at
 * @cookie: Context for completion function
 * @completer: Completion function
 * @handle: Command handle
 * @cmd: Command number
 * @rc: Return code
 * @outlen: Length of output buffer
 * @outbuf: Output buffer
 */
struct ksb_mcdi_cmd {
	struct kref ref;
	struct list_head list;
	struct list_head cleanup_list;
	struct work_struct work;
	struct ksb_mcdi_iface *mcdi;
	enum ksb_mcdi_cmd_state state;
	size_t inlen;
	const struct ksb_dword *inbuf;
	bool quiet;
	bool reboot_seen;
	u8 seq;
	unsigned long started;
	unsigned long cookie;
	ksb_mcdi_async_completer *completer;
	unsigned int handle;
	unsigned int cmd;
	int rc;
	size_t outlen;
	struct ksb_dword *outbuf;
	/* followed by inbuf data if necessary */
};

/**
 * struct ksb_mcdi_iface - MCDI protocol context
 * @mc_ctx: The associated NIC
 * @iface_lock: Serialise access to this structure
 * @outstanding_cleanups: Count of cleanups
 * @cmd_list: List of outstanding and running commands
 * @workqueue: Workqueue used for delayed processing
 * @cmd_complete_wq: Waitqueue for command completion
 * @db_held_by: Command the MC doorbell is in use by
 * @seq_held_by: Command each sequence number is in use by
 * @prev_handle: The last used command handle
 * @mode: Poll for mcdi completion, or wait for an mcdi_event
 * @prev_seq: The last used sequence number
 * @new_epoch: Indicates start of day or start of MC reboot recovery
 */
struct ksb_mcdi_iface {
	struct ksb_mcdi *mc_ctx;
	/* Serialise access */
	struct mutex iface_lock;
	unsigned int outstanding_cleanups;
	struct list_head cmd_list;
	struct workqueue_struct *workqueue;
	wait_queue_head_t cmd_complete_wq;
	struct ksb_mcdi_cmd *db_held_by;
	struct ksb_mcdi_cmd *seq_held_by[16];
	unsigned int prev_handle;
	enum ksb_mcdi_mode mode;
	u8 prev_seq;
	bool new_epoch;
};

/**
 * struct ksb_mcdi_data - extra state for NICs that implement MCDI
 * @iface: Interface/protocol state
 * @fn_flags: Flags for this function, as returned by %MC_CMD_DRV_ATTACH.
 */
struct ksb_mcdi_data {
	struct ksb_mcdi_iface iface;
	u32 fn_flags;
};

static inline struct ksb_mcdi_iface *ksb_mcdi_if(struct ksb_mcdi *mc_ctx)
{
	return mc_ctx->mcdi ? &mc_ctx->mcdi->iface : NULL;
}

int ksb_mcdi_init(struct ksb_mcdi *mc_ctx);
void ksb_mcdi_finish(struct ksb_mcdi *mc_ctx);

void ksb_mcdi_process_cmd(struct ksb_mcdi *mc_ctx, struct ksb_dword *outbuf, int len);
int ksb_mcdi_rpc(struct ksb_mcdi *mc_ctx, unsigned int cmd,
		 const struct ksb_dword *inbuf, size_t inlen,
		 struct ksb_dword *outbuf, size_t outlen, size_t *outlen_actual);

/*
 * We expect that 16- and 32-bit fields in MCDI requests and responses
 * are appropriately aligned, but 64-bit fields are only
 * 32-bit-aligned.
 */
#define MCDI_DECLARE_BUF(_name, _len) struct ksb_dword _name[DIV_ROUND_UP(_len, 4)] = {{0}}
#define _MCDI_PTR(_buf, _offset)					\
	((u8 *)(_buf) + (_offset))
#define MCDI_PTR(_buf, _field)						\
	_MCDI_PTR(_buf, MC_CMD_ ## _field ## _OFST)
#define _MCDI_CHECK_ALIGN(_ofst, _align)				\
	((void)BUILD_BUG_ON_ZERO((_ofst) & ((_align) - 1)),		\
	 (_ofst))
#define _MCDI_DWORD(_buf, _field)					\
	((_buf) + (_MCDI_CHECK_ALIGN(MC_CMD_ ## _field ## _OFST, 4) >> 2))

#define MCDI_BYTE(_buf, _field)						\
	((void)BUILD_BUG_ON_ZERO(MC_CMD_ ## _field ## _LEN != 1),	\
	 *MCDI_PTR(_buf, _field))
#define MCDI_WORD(_buf, _field)						\
	((void)BUILD_BUG_ON_ZERO(MC_CMD_ ## _field ## _LEN != 2),	\
	 le16_to_cpu(*(__force const __le16 *)MCDI_PTR(_buf, _field)))
#define MCDI_SET_DWORD(_buf, _field, _value)				\
	KSB_POPULATE_DWORD_1(*_MCDI_DWORD(_buf, _field), KSB_DWORD, _value)
#define MCDI_DWORD(_buf, _field)					\
	KSB_DWORD_FIELD(*_MCDI_DWORD(_buf, _field), KSB_DWORD)
#define MCDI_POPULATE_DWORD_1(_buf, _field, _name1, _value1)		\
	KSB_POPULATE_DWORD_1(*_MCDI_DWORD(_buf, _field),		\
			     MC_CMD_ ## _name1, _value1)
#define MCDI_SET_QWORD(_buf, _field, _value)				\
	do {								\
		KSB_POPULATE_DWORD_1(_MCDI_DWORD(_buf, _field)[0],	\
				     KSB_DWORD, (u32)(_value));	\
		KSB_POPULATE_DWORD_1(_MCDI_DWORD(_buf, _field)[1],	\
				     KSB_DWORD, (u64)(_value) >> 32);	\
	} while (0)
#define MCDI_QWORD(_buf, _field)					\
	(KSB_DWORD_FIELD(_MCDI_DWORD(_buf, _field)[0], KSB_DWORD) |	\
	(u64)KSB_DWORD_FIELD(_MCDI_DWORD(_buf, _field)[1], KSB_DWORD) << 32)

#define MCDI_SET_WORD(_buf, _field, _value) do {            \
    BUILD_BUG_ON(MC_CMD_ ## _field ## _LEN != 2);           \
    BUILD_BUG_ON(MC_CMD_ ## _field ## _OFST & 1);           \
    *(__force __le16 *)MCDI_PTR(_buf, _field) = cpu_to_le16(_value);\
    } while (0)

#define MCDI_SET_BYTE(_buf, _field, _value) do {            \
    BUILD_BUG_ON(MC_CMD_ ## _field ## _LEN != 1);           \
    *MCDI_PTR(_buf, _field) = (_value);\
    } while (0)

#endif /* KSB_MCDI_H */
