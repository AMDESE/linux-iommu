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

#include <linux/workqueue.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>

#include "ksb_pci_drv.h"
#include "ksb_dpu_reg.h"
#include "ksb_cdx_dev.h"
#include "ksb_pci_io.h"
#include "ksb_mcdi_cmd.h"
#include "bitfield.h"
#include "ksb_dpu_exerciser.h"

#define MAX_DPU_CMD_EXE		EF_DPU_DMA_READ_EXS_NUM
#define SL_DPU_PATH_SEQ_RATE_MAX 100
#define SL_DPU_PATH_SEQ_RATE_PERF 0x64

#define MAX_DMA_DESC	8

#define KSB_CEIL(a, b) (((a) + (b) - 1) / (b))

#define DEFAULT_PERF_CREDIT_POOL 0xe00
#define WAIT_LOCAL_POOL_CRDT 0x4
#define WAIT_EV_CRDT 0x5
#define DEFAULT_PERF_CRDT_EV 0x80
#define NO_EVENTS_FATAL	10
#define DEFAULT_SNAP_TIME_MS 1000
#define DEFAULT_SNAP_REQ_TIME_MS (DEFAULT_SNAP_TIME_MS / 4)
#define NO_EVENTS_FATAL_TIMEOUT (DEFAULT_SNAP_TIME_MS * 4)

struct dpu_ex_cmd {
	/** DPU Command type */
	ef_dpu_cmd_type_t type;
	/** Type of DPU Command source */
	ef_dpu_src_type_t src;
	/** Type of DPU Command destination */
	ef_dpu_dst_type_t dst;
	/** DPU Command Exerciser number where the command is executed */
	u8 ex_num;
	/** DPU event Exerciser number where the event is received */
	u8 ev_chan;
	/** Destination data channel */
	uint8_t dst_dchan;
	/** Event cookie */
	u16 cookie;
	/** Length of dma */
	u32 dma_len;
	/** Source DPU buffer Pool */
	int src_dpu_buf_pool;
	/** Destination DPU buffer Pool */
	int dst_dpu_buf_pool;
	/** Buffer head */
	u32 buf;
	/** True if DPU should free buffer after reading (if src is DPU Buffer) */
	bool src_buf_free;
	/** The percent of cycles that can be consumed by commands in path */
	unsigned seq_rate;
	/** Additional control to sequence rate */
	unsigned seq_rate_low;
	/** DPU address space */
	struct dpu_addr_space addr_space;
	/** DPU Buffer command sub type */
	enum dpu_cmd_buf_subtype_t buf_type;
	/** Route control for dual commands */
	sideband_route_ctrl_t route_ctrl;
	/** Edit bufid inside the command for dual commands */
	bool edit_src_bufid;
	/** If waiting for context then source of the context for dual commands */
	sideband_wait_ctxt_src_t wait_ctxt_src;

	/* Page array */
	struct page *pages[MAX_DMA_DESC];
	/* sg list */
	struct scatterlist sg[MAX_DMA_DESC];
	/* DPU hw command */
	ksb_oword_t hw_cmd[MAX_DMA_DESC + 1];
	/* CPU cmd lenth */
	int cmd_len;
	/* sg list count */
	int sgl;
};

struct dpu_ex_ev {
	bool valid;
	bool err;
	bool discrim;
	uint16_t cookie;
	uint16_t buf_head;
	union {
		uint16_t buf_tail;
		uint16_t err_info;
	};
};

static DECLARE_BITMAP(dpu_cmd_exe, MAX_DPU_CMD_EXE);
static DEFINE_MUTEX(dpu_cmd_exe_lock);

int reserve_dpu_cmd_exe(int cmd_exe, bool perf)
{
	int bit = -1;

	mutex_lock(&dpu_cmd_exe_lock);

	if (cmd_exe == -1) {
		bit = find_first_zero_bit(dpu_cmd_exe, MAX_DPU_CMD_EXE);
		if (bit >= MAX_DPU_CMD_EXE || (perf && bit == (MAX_DPU_CMD_EXE - 1))) {
			mutex_unlock(&dpu_cmd_exe_lock);
			return -1;
		}
		set_bit(bit, dpu_cmd_exe);
		if (perf && test_and_set_bit(bit + 1, dpu_cmd_exe)) {
			clear_bit(bit, dpu_cmd_exe);
			pr_err("Could not allocate extra cmd exe for perf mode\n");
		}
	}
	else if (cmd_exe < MAX_DPU_CMD_EXE || (perf && bit != (MAX_DPU_CMD_EXE - 1))) {
		if (!test_and_set_bit(cmd_exe, dpu_cmd_exe)) {
			bit = cmd_exe;
			if (perf && test_and_set_bit(bit + 1, dpu_cmd_exe)) {
				clear_bit(bit, dpu_cmd_exe);
				pr_err("Could not allocate extra cmd exe for perf mode\n");
			}
		}
	}

	mutex_unlock(&dpu_cmd_exe_lock);

	return bit;
}

void release_dpu_cmd_exe(int cmd_exe, bool perf)
{
	mutex_lock(&dpu_cmd_exe_lock);
	clear_bit(cmd_exe, dpu_cmd_exe);
	if (perf)
		clear_bit(cmd_exe + 1, dpu_cmd_exe);
	mutex_unlock(&dpu_cmd_exe_lock);
}

static inline void
dpu_exerciser_reg_wr(struct pci_dev *pci_dev, u32 offset, u32 data)
{
	u32 reg = DPU_EXERCISER_OFFSET + offset;

	ksb_io_write32(pci_dev, reg, data);
}

static inline u32
dpu_exerciser_reg_rd(struct pci_dev *pci_dev, u32 offset)
{
	u32 reg = DPU_EXERCISER_OFFSET + offset;

	return ksb_io_read32(pci_dev, reg);
}

static enum dpu_cmd_type_t
cmd_type_ef_to_hw(ef_dpu_cmd_type_t type)
{
  switch( type ) {
#define EF2HW(_tag)                                                            \
  case EF_DPU_CMD_##_tag:                                                      \
    return DPU_CMD_##_tag;

    EF2HW(RD);
    EF2HW(WR);
    EF2HW(RX);
    EF2HW(TX);
    EF2HW(RD_BARRIER);
    EF2HW(BUF);
    EF2HW(BUF_WRITE);

#undef EF2HW
  }

  return 0;
}

static void dpu_reset(cdx_device_t *cdx_dev)
{
	int i;
	u32 reg_val;
	u32 cmd_exs_num;
	u32 all_exs_mask;
	u32 cmd_values[MAX_DPU_CMD_EXE * 3];
	u32 cmd_offset = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_CMD_OFFSET);
	u32 cmd_step = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_CMD_STEP_OFFSET);

	reg_val = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_CONFIG);
	cmd_exs_num = BITFIELD_GET(reg_val, DPUEX_COM_REG_EX_CONFIG_NUM_CMD_CH_EX);
	all_exs_mask = ((u32) 1 << cmd_exs_num) - 1;

	for (i = 0; i < cmd_exs_num; ++i) {
		cmd_values[i] = dpu_exerciser_reg_rd(cdx_dev->pci_dev, cmd_offset + (cmd_step * i) + DPUEX_CMD_REG_PERF_CRDT_CMD);
		cmd_values[i + 1] = dpu_exerciser_reg_rd(cdx_dev->pci_dev, cmd_offset + (cmd_step * i) + DPUEX_CMD_REG_PERF_CRDT_DMA_RD);
		cmd_values[i + 2] = dpu_exerciser_reg_rd(cdx_dev->pci_dev, cmd_offset + (cmd_step * i) + DPUEX_CMD_REG_PERF_CRDT_DMA_WR);
	}

	/* As per snapper, reset.
	 * See description for DPUEX_COM_REG_EX_CMD_RST_CTRL:
	 * SW is responsible for managing CMD/DMARD/DMAWR credits by reading their
	 * current value prior to reset and writing it back in after reset has
	 * completed.
	 */
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, DPUEX_COM_REG_EX_CMD_RST_CTRL, 0x000001ff);
	msleep(100);
	reg_val = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_CMD_RST_STS);
	if (reg_val != all_exs_mask)
		pr_err("Failed to reset dpu exercisers\n");

	for (i = 0; i < cmd_exs_num; ++i) {
		dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + (cmd_step * i) + DPUEX_CMD_REG_PERF_CRDT_CMD, cmd_values[i]);
		dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + (cmd_step * i) + DPUEX_CMD_REG_PERF_CRDT_DMA_RD, cmd_values[i + 1]);
		dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + (cmd_step * i) + DPUEX_CMD_REG_PERF_CRDT_DMA_WR, cmd_values[i + 2]);
	}

	dpu_exerciser_reg_wr(cdx_dev->pci_dev, DPUEX_COM_REG_EX_EVNT_RST_CTRL, all_exs_mask);
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, DPUEX_COM_REG_EX_U2D_RST_CTRL, 0x0000007f);
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, DPUEX_COM_REG_EX_D2U_RST_CTRL, 0x0000007f);
}

#define SL_DPU_EX_STATS_SNAP_BUSY_MAX_POLL_US     (5 * 1000000)
#define SL_DPU_EX_STATS_SNAP_BUSY_POLL_INTERVAL_US 1

static bool ex_stats_snap_ready(cdx_device_t *cdx_dev, u32 cmd_offset, u16 *snap_cnt)
{
	ktime_t now, finish;
	struct ksb_dword reg_val;

	now = ktime_get();
	finish = ktime_add_us(now, SL_DPU_EX_STATS_SNAP_BUSY_MAX_POLL_US);

	/* Wait till snap busy is cleared */
	do {
		now = ktime_get();

		reg_val.ksb_u32 = dpu_exerciser_reg_rd(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_SNAP_BUSY);
		*snap_cnt = BITFIELD_GET(reg_val.ksb_u32, DPUEX_CMD_REG_SNAP_BUSY_SNAP_CNT);
		reg_val.ksb_u32 = BITFIELD_GET(reg_val.ksb_u32, DPUEX_CMD_REG_SNAP_BUSY_SNAP_BUSY);

		udelay(SL_DPU_EX_STATS_SNAP_BUSY_POLL_INTERVAL_US);
	} while (reg_val.ksb_u32 != 0 && ktime_before(now, finish));

	return !reg_val.ksb_u32;
}

static u32 ex_stats_read_ev_active(cdx_device_t *cdx_dev, u32 cmd_offset)
{
	return dpu_exerciser_reg_rd(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_SNAP_EV_ACTV);
}

static void ex_perf_cmd_set_loop(cdx_device_t *cdx_dev, u32 cmd_offset, u64 loops, bool clear)
{
	struct ksb_dword reg_val;

	if (clear) {
		KSB_POPULATE_DWORD_1(reg_val, DPUEX_CMD_REG_SET_LOOPS_H_NUM_LOOPS_CTRL, PERF_MODE_LOOPS_CTRL_STOP_ONLY);
		dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_SET_LOOPS_H, reg_val.ksb_u32);

		KSB_POPULATE_DWORD_2(reg_val, DPUEX_CMD_REG_GET_LOOPS_H_CUR_LOOPS_SEQID, 0,
			DPUEX_CMD_REG_GET_LOOPS_H_CUR_LOOPS_CLR, 1);
		dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_GET_LOOPS_H, reg_val.ksb_u32);
	}

	KSB_POPULATE_DWORD_1(reg_val, DPUEX_CMD_REG_SET_LOOPS_L_NUM_LOOPS_L, (loops & ~((u32)0)));
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_SET_LOOPS_L, reg_val.ksb_u32);

	KSB_POPULATE_DWORD_2(reg_val, DPUEX_CMD_REG_SET_LOOPS_H_NUM_LOOPS_H,
			(loops >> PERF_MODE_NUM_LOOPS_L_WIDTH) & (((u64)1 << DPUEX_CMD_REG_SET_LOOPS_H_NUM_LOOPS_H_WIDTH) - 1),
			DPUEX_CMD_REG_SET_LOOPS_H_NUM_LOOPS_CTRL,
			(loops > 0) ? PERF_MODE_LOOPS_CTRL_WRITE_AND_START
			: PERF_MODE_LOOPS_CTRL_WRITE_ONLY);
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_SET_LOOPS_H, reg_val.ksb_u32);
}

static void ex_perf_d2u_set_loop(cdx_device_t *cdx_dev, ef_dpu_ex_data_channel_t chan,
		u32 d2u_offset, u64 loops, bool clear)
{
	struct ksb_dword reg_val;

	if (clear) {
		switch (chan ) {
			case EF_DPU_EX_DATA_CHANNEL_0:
				KSB_POPULATE_DWORD_1(reg_val, DPUEX_D2U_REG_SET_LOOPS_H_0_NUM_LOOPS_CTRL, PERF_MODE_LOOPS_CTRL_STOP_ONLY);
				dpu_exerciser_reg_wr(cdx_dev->pci_dev, d2u_offset + DPUEX_D2U_REG_SET_LOOPS_H_0, reg_val.ksb_u32);

				KSB_POPULATE_DWORD_1(reg_val, DPUEX_D2U_REG_GET_LOOPS_H_0_CUR_LOOPS_CLR, 1);
				dpu_exerciser_reg_wr(cdx_dev->pci_dev, d2u_offset + DPUEX_D2U_REG_GET_LOOPS_H_0, reg_val.ksb_u32);
			break;
			case EF_DPU_EX_DATA_CHANNEL_1:
				KSB_POPULATE_DWORD_1(reg_val, DPUEX_D2U_REG_SET_LOOPS_H_1_NUM_LOOPS_CTRL, PERF_MODE_LOOPS_CTRL_STOP_ONLY);
				dpu_exerciser_reg_wr(cdx_dev->pci_dev, d2u_offset + DPUEX_D2U_REG_SET_LOOPS_H_1, reg_val.ksb_u32);

				KSB_POPULATE_DWORD_1(reg_val, DPUEX_D2U_REG_GET_LOOPS_H_1_CUR_LOOPS_CLR, 1);
				dpu_exerciser_reg_wr(cdx_dev->pci_dev, d2u_offset + DPUEX_D2U_REG_GET_LOOPS_H_1, reg_val.ksb_u32);
			break;
		}
	}

	switch (chan) {
		case EF_DPU_EX_DATA_CHANNEL_0:
			KSB_POPULATE_DWORD_1(reg_val, DPUEX_D2U_REG_SET_LOOPS_L_0_NUM_LOOPS_L, (loops & ~((u32)0)));
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, d2u_offset + DPUEX_D2U_REG_SET_LOOPS_L_0, reg_val.ksb_u32);

			KSB_POPULATE_DWORD_2(reg_val, DPUEX_D2U_REG_SET_LOOPS_H_0_NUM_LOOPS_H,
					(loops >> PERF_MODE_NUM_LOOPS_L_WIDTH) & (((u64)1 << DPUEX_CMD_REG_SET_LOOPS_H_NUM_LOOPS_H_WIDTH) - 1),
					DPUEX_D2U_REG_SET_LOOPS_H_0_NUM_LOOPS_CTRL,
					(loops > 0) ? PERF_MODE_LOOPS_CTRL_WRITE_AND_START
					: PERF_MODE_LOOPS_CTRL_WRITE_ONLY);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, d2u_offset + DPUEX_D2U_REG_SET_LOOPS_H_0, reg_val.ksb_u32);
			break;
		case EF_DPU_EX_DATA_CHANNEL_1:
			KSB_POPULATE_DWORD_1(reg_val, DPUEX_D2U_REG_SET_LOOPS_L_1_NUM_LOOPS_L, (loops & ~((u32)0)));
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, d2u_offset + DPUEX_D2U_REG_SET_LOOPS_L_1, reg_val.ksb_u32);

			KSB_POPULATE_DWORD_2(reg_val, DPUEX_D2U_REG_SET_LOOPS_H_1_NUM_LOOPS_H,
					(loops >> PERF_MODE_NUM_LOOPS_L_WIDTH) & (((u64)1 << DPUEX_CMD_REG_SET_LOOPS_H_NUM_LOOPS_H_WIDTH) - 1),
					DPUEX_D2U_REG_SET_LOOPS_H_1_NUM_LOOPS_CTRL,
					(loops > 0) ? PERF_MODE_LOOPS_CTRL_WRITE_AND_START
					: PERF_MODE_LOOPS_CTRL_WRITE_ONLY);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, d2u_offset + DPUEX_D2U_REG_SET_LOOPS_H_1, reg_val.ksb_u32);
			break;
	}
}

static ef_dpu_ex_data_channel_t dchan_num2chan(uint8_t dchan_num)
{
	/* Each data exerciser N has two data channel interfaces:
	 * {2N + offset, 2N + 1 + offset}.
	 * Offset is even, and it's determined by the number of data channels
	 * connected to NoC, as they cannot be used with exercisers.
	 *
	 * See XN-201325-AN-F 2.2.1.2 Exerciser Connection Topology for details.
	 */
	return (dchan_num % EF_DPU_DATA_CHANNELS_NUM == 0) ? EF_DPU_EX_DATA_CHANNEL_0 : EF_DPU_EX_DATA_CHANNEL_1;
}

static unsigned dchan_num2ex_num(uint8_t dchan_num)
{
	/* A pair {2N + offset, 2N + 1 + offset} of data channel interfaces
	 * corresponds to data exerciser N.
	 * Offset is even, and it's determined by the number of data channels
	 * connected to NoC, as they cannot be used with exercisers.
	 *
	 * See XN-201325-AN-F 2.2.1.2 Exerciser Connection Topology for details.
	 */
	dchan_num -= EF_DPU_MAX_NOC_DCHAN_NUM;

	return dchan_num / EF_DPU_DATA_CHANNELS_NUM;
}

static void dpu_ex_d2u_get_info(struct dpu_ex_cmd *dpu_cmd, ef_dpu_ex_data_channel_t *chan, unsigned *ex_num)
{
	*chan = dchan_num2chan(dpu_cmd->dst_dchan);
	*ex_num = dchan_num2ex_num(dpu_cmd->dst_dchan);
}

static void unmap_user_buf_from_sgl(cdx_device_t *cdx_dev, ksb_dpu_cmd_t *usr_cmd, struct dpu_ex_cmd *dpu_cmd)
{
	int i;
	struct page **pages = dpu_cmd->pages;

	if (usr_cmd->addr_mapped)
		return;

	for (i = 0; i < dpu_cmd->sgl; i++) {
		dma_unmap_page(&cdx_dev->pci_dev->dev, dpu_cmd->sg[i].dma_address,
			dpu_cmd->sg[i].length, DMA_BIDIRECTIONAL);
		put_page(pages[i]);
	}
}

static int map_user_buf_to_sgl(cdx_device_t *cdx_dev, ksb_dpu_cmd_t *usr_cmd, struct dpu_ex_cmd *dpu_cmd, bool write)
{
	unsigned long buf;
	int nr_pages, rv, i;
	unsigned long first, last;
	ssize_t dma_len = usr_cmd->dma_len;
	struct page **pages = dpu_cmd->pages;
	struct scatterlist *sg = dpu_cmd->sg;

	if (write)
		buf = (unsigned long)usr_cmd->dst;
	else
		buf = (unsigned long)usr_cmd->src;

	if (usr_cmd->addr_mapped) {
		sg[0].dma_address = buf;
		sg[0].length = usr_cmd->dma_len;
		dpu_cmd->sgl = 1;
		return 0;
	}

	/* Calculate number of pages */
	first = (buf & PAGE_MASK) >> PAGE_SHIFT;
	last  = ((buf + dma_len - 1) & PAGE_MASK) >> PAGE_SHIFT;
	nr_pages = last - first + 1;

	if (nr_pages >= MAX_DMA_DESC)
		return -EIO;

	rv = get_user_pages_fast((unsigned long)buf, nr_pages, 1/* write */, pages);
	if (rv != nr_pages) {
		pr_err("Failed get_user_pages_fast %d:%d\n", rv, nr_pages);
		return -EINVAL;
	}

	for (i = 0; i < nr_pages; i++) {
		unsigned int offset = offset_in_page(buf);
		unsigned int nbytes = min_t(unsigned int, PAGE_SIZE - offset, dma_len);
		struct page *pg = pages[i];

		if (EF_DPU_DMA_DESC_MAX_LEN < nbytes)
			goto err;

		sg_set_page(&sg[i], pg, nbytes, offset);

		sg[i].dma_address = dma_map_page(&cdx_dev->pci_dev->dev, pg, offset, nbytes, DMA_BIDIRECTIONAL);
		if (unlikely(dma_mapping_error(&cdx_dev->pci_dev->dev, sg[i].dma_address))) {
			pr_err("Failed to dma map sg\n");
			goto err;
		}

		buf += nbytes;
		dma_len -= nbytes;
	}

	dpu_cmd->sgl = nr_pages;

	return 0;
err:
	dpu_cmd->sgl = i;
	unmap_user_buf_from_sgl(cdx_dev, usr_cmd, dpu_cmd);
	return -EIO;
}

#define HUGE_PAGE_SZ BIT(21)
static void unmap_user_hp(cdx_device_t *cdx_dev, ksb_dpu_cmd_t *usr_cmd, struct dpu_ex_cmd *dpu_cmd)
{
	struct page **pages = dpu_cmd->pages;

	if (usr_cmd->addr_mapped)
		return;

	dma_unmap_page(&cdx_dev->pci_dev->dev, dpu_cmd->sg[0].dma_address, HUGE_PAGE_SZ, DMA_BIDIRECTIONAL);
	put_page(pages[0]);
}

static int map_user_hp_to_sgl(cdx_device_t *cdx_dev, ksb_dpu_cmd_t *usr_cmd, struct dpu_ex_cmd *dpu_cmd, bool write)
{
	unsigned long buf;
	int dma_descs, rv, i;
	dma_addr_t dma_address;
	ssize_t dma_len = usr_cmd->dma_len;
	struct page **pages = dpu_cmd->pages;
	struct scatterlist *sg = dpu_cmd->sg;

	/* Calculate number of dma desc */
	dma_descs = ((dma_len - 1) / EF_DPU_DMA_DESC_MAX_LEN) + 1;
	if (dma_descs >= MAX_DMA_DESC)
		return -EIO;

	if (write)
		buf = (unsigned long)usr_cmd->dst;
	else
		buf = (unsigned long)usr_cmd->src;

	if (!usr_cmd->addr_mapped) {
		rv = get_user_pages_fast((unsigned long)buf, 1 /* single huge page */, 1/* write */, pages);
		if (rv != 1) {
			pr_err("Failed get_user_pages_fast %d\n", rv);
			return -EINVAL;
		}

		if (!PageHuge(pages[0])) {
			pr_err("Invalid hugepage passed for mapping\n");
			put_page(pages[0]);
			return -EINVAL;
		}

		dma_address = dma_map_page(&cdx_dev->pci_dev->dev, pages[0], offset_in_page(buf), HUGE_PAGE_SZ, DMA_BIDIRECTIONAL);
		if (unlikely(dma_mapping_error(&cdx_dev->pci_dev->dev, dma_address))) {
			pr_err("Failed to dma map sg\n");
			put_page(pages[0]);
			return -EIO;
		}

	} else {
		dma_address = (dma_addr_t)buf;
	}

	for (i = 0; i < dma_descs; i++) {
		sg[i].dma_address = dma_address + ( i * EF_DPU_DMA_DESC_MAX_LEN);
		sg[i].length = dma_len >= EF_DPU_DMA_DESC_MAX_LEN ? EF_DPU_DMA_DESC_MAX_LEN : dma_len;
		dma_len -= EF_DPU_DMA_DESC_MAX_LEN;
	}

	dpu_cmd->sgl = dma_descs;

	return 0;
}

static void fill_in_dpu_cmd_words(struct dpu_ex_cmd *dpu_cmd)
{
	int total_cmds = dpu_cmd->cmd_len;
	KSB_SET_OWORD_FIELD(*dpu_cmd->hw_cmd, DPU_CMD_HDR_CH_CMD_WORDS, total_cmds);
}

static ksb_oword_t fill_in_dpu_hw_cmd_buf_hdr(struct dpu_ex_cmd *dpu_cmd)
{
	ksb_oword_t hw_cmd_hdr = {0};

	/* Command length */
	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_CMD_WORDS, 1);
	/* Command type */
	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_TYPE, cmd_type_ef_to_hw(dpu_cmd->type));
	/* Unused for buffer header */
	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_PATH, 0);
	/* Event channel */
	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_EV_CHAN, dpu_cmd->ev_chan);
	/* Set cookie for event */
	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_COOKIE, dpu_cmd->cookie);
	/* Buffer command operation */
	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_BUF_HDR_CB_SUBTYPE, dpu_cmd->buf_type);

	switch (dpu_cmd->buf_type) {
	case EF_DPU_CMD_BUF_ST_ALLOC:
		KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_BUF_HDR_ALLOC_POOL, dpu_cmd->src_dpu_buf_pool);
		KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_BUF_HDR_ALLOC_BYTES, dpu_cmd->dma_len);
		break;
	case EF_DPU_CMD_BUF_ST_FREE:
		KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_BUF_HDR_FREE_BUF, dpu_cmd->buf);
		KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_BUF_HDR_FREE_BUF_POOL, dpu_cmd->src_dpu_buf_pool);
		break;
	default:
		break;
	}

	dpu_cmd->hw_cmd[dpu_cmd->cmd_len++] = hw_cmd_hdr;

	return hw_cmd_hdr;
}

static ksb_oword_t fill_in_dpu_hw_cmd_hdr(struct dpu_ex_cmd *dpu_cmd)
{
	ksb_oword_t hw_cmd_hdr = {0};

	/* Command length */
	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_CMD_WORDS, 2);
	/* Command type */
	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_TYPE, cmd_type_ef_to_hw(dpu_cmd->type));
	/* Data path : 0: Offload engine 1: Bypass */
	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_PATH, 1);
	/* Event channel */
	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_EV_CHAN, dpu_cmd->ev_chan);
	/* Set cookie for event */
	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_COOKIE, dpu_cmd->cookie);

	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_SRC_TYPE, dpu_cmd->src);
	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_SRC_HDR_BYTES, 0);
	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_SRC_PAYLOAD_BYTES, dpu_cmd->dma_len);
	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_SRC_PAYLOAD_OFF, 0x0);
	/* Not applicable */
	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_SRC_DCHAN, 0);

	switch (dpu_cmd->src) {
	case EF_DPU_SRC_BUF:
		/* Buffer id */
		KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_SRC_BUF, dpu_cmd->buf);
		KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_SRC_BUF_FREE, dpu_cmd->src_buf_free);
		break;
	case EF_DPU_SRC_DMA:
		KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_SRC_DMA_NUM_DESC, dpu_cmd->sgl);
		break;
	default:
		break;
	}

	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_DST_TYPE, dpu_cmd->dst);
	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_DST_BUF_POOL, dpu_cmd->dst_dpu_buf_pool);

	switch (dpu_cmd->dst) {
	case EF_DPU_DST_DMA:
		/* DMA dest descriptors */
		KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_DST_DMA_NUM_DESC, dpu_cmd->sgl);
		break;
	case EF_DPU_DST_DCHAN:
		KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_DST_DCHAN, dpu_cmd->dst_dchan);
		KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_DST_DCHAN_MAX_WORDS, 0);
	default:
		break;
	}

	KSB_SET_OWORD_FIELD(hw_cmd_hdr, DPU_CMD_HDR_CH_SRC_BUF_POOL, dpu_cmd->src_dpu_buf_pool);

	dpu_cmd->hw_cmd[dpu_cmd->cmd_len++] = hw_cmd_hdr;

	return hw_cmd_hdr;
}

static
ksb_oword_t fill_in_dpu_hw_dma_desc(struct dpu_ex_cmd *dpu_cmd, int sg_loc)
{
	struct ksb_dword pasid = { 0 };
	struct ksb_dword attr = { 0 };
	struct ksb_dword tph = { 0 };
	ksb_qword_t addr_space = { 0 };
	ksb_oword_t hw_desc = { 0 };

	KSB_SET_DWORD_FIELD(pasid, DPU_PCIE_PASID_ENABLE, dpu_cmd->addr_space.pasid_en);
	KSB_SET_DWORD_FIELD(pasid, DPU_PCIE_PASID_PASID, dpu_cmd->addr_space.pasid);
	KSB_SET_DWORD_FIELD(pasid, DPU_PCIE_PASID_EXECUTE_RQ, 0);
	KSB_SET_DWORD_FIELD(pasid, DPU_PCIE_PASID_PRIVILEGED_MODE_RQ, 0);

	KSB_SET_QWORD_FIELD(addr_space, DPU_ADDR_SPC_DST, dpu_cmd->addr_space.dpu_dst_id);

	KSB_SET_QWORD_FIELD(addr_space, DPU_ADDR_SPC_FUNC_ID, dpu_cmd->addr_space.func_id);
	KSB_SET_QWORD_FIELD(addr_space, DPU_ADDR_SPC_PASID, pasid.ksb_u32);

	KSB_SET_DWORD_FIELD(attr, DPU_PCIE_ATTR_NO_SNOOP, 0);
	KSB_SET_DWORD_FIELD(attr, DPU_PCIE_ATTR_RO, 0);
	KSB_SET_DWORD_FIELD(attr, DPU_PCIE_ATTR_IDO, 0);

	KSB_SET_DWORD_FIELD(tph, DPU_PCIE_TPH_TH, 0);
	KSB_SET_DWORD_FIELD(tph, DPU_PCIE_TPH_PH, 0);
	KSB_SET_DWORD_FIELD(tph, DPU_PCIE_TPH_ST, 0);

	KSB_SET_OWORD_FIELD(hw_desc, DPU_DMA_DESC_DD_ADDR, dpu_cmd->sg[sg_loc].dma_address);
	KSB_SET_OWORD_FIELD(hw_desc, DPU_DMA_DESC_DD_LENGTH, dpu_cmd->sg[sg_loc].length);

	KSB_SET_OWORD_FIELD(hw_desc, DPU_DMA_DESC_DD_ADDR_SPACE, addr_space.u64[0]);
	KSB_SET_OWORD_FIELD(hw_desc, DPU_DMA_DESC_DD_ADDR_TRANSLATED, 0);
	KSB_SET_OWORD_FIELD(hw_desc, DPU_DMA_DESC_DD_ATTR, attr.ksb_u32);
	KSB_SET_OWORD_FIELD(hw_desc, DPU_DMA_DESC_DD_TPH, tph.ksb_u32);

	if (dpu_cmd->type == EF_DPU_CMD_RD)
		KSB_SET_OWORD_FIELD(hw_desc, DPU_DMA_DESC_DD_RD_RELAXED_ORDER, 0);
	else
		KSB_SET_OWORD_FIELD(hw_desc, DPU_DMA_DESC_DD_WR_PAD, 0);

	return hw_desc;
}

static void fill_in_dpu_hw_dma_descs(struct dpu_ex_cmd *dpu_cmd)
{
	int i;

	for (i = 0; i < dpu_cmd->sgl; ++i)
		dpu_cmd->hw_cmd[dpu_cmd->cmd_len++] = fill_in_dpu_hw_dma_desc(dpu_cmd, i);
}

static void dpu_dump_err_info(u16 err_info)
{
	printk("Where : %d\n", BITFIELD_GET(err_info, DPU_ERR_INFO_WHERE));
	printk("Err info: %0X\n", err_info);
}

static void dpu_poll_ev(cdx_device_t *cdx_dev, u32 event_offset, struct dpu_ex_ev *ev)
{
	u32 reg_val;
	u16 buf_tail_err_info;

	reg_val = dpu_exerciser_reg_rd(cdx_dev->pci_dev, event_offset + DPUEX_EV_REG_EVENT_0);
	ev->valid = BITFIELD_GET(reg_val, DPUEX_EV_REG_EVENT_0_EV_VALID);
	ev->err = BITFIELD_GET(reg_val, DPUEX_EV_REG_EVENT_0_EV_ERR);
	ev->discrim = BITFIELD_GET(reg_val, DPUEX_EV_REG_EVENT_0_EV_DISCRIM);
	ev->cookie = BITFIELD_GET(reg_val, DPUEX_EV_REG_EVENT_0_EV_COOKIE);

	reg_val = dpu_exerciser_reg_rd(cdx_dev->pci_dev, event_offset + DPUEX_EV_REV_EVENT_1);
	ev->buf_head = BITFIELD_GET(reg_val, DPUEX_EV_REV_EVENT_1_EV_BUF_HEAD);
	buf_tail_err_info = BITFIELD_GET(reg_val, DPUEX_EV_REV_EVENT_1_EV_BUF_TAIL_ERR_INFO);

	if (ev->err)
		ev->err_info = buf_tail_err_info;
	else
		ev->buf_tail = buf_tail_err_info;
}

static int
dpu_execute_single_cmd(cdx_device_t *cdx_dev, struct dpu_ex_cmd *dpu_cmd, int cmd_chan)
{
	int i, write_num = 0;
	struct ksb_dword reg_val;
	struct dpu_ex_ev ev;
	u32 cmd_offset = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_CMD_OFFSET);
	u32 cmd_step = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_CMD_STEP_OFFSET);
	u32 event_offset = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_EVNT_OFFSET);
	u32 event_step = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_EVNT_STEP_OFFSET);
	int num_writes = KSB_CEIL(dpu_cmd->cmd_len, EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND);

	cmd_offset = cmd_offset + (cmd_step * cmd_chan);
	event_offset = event_offset + (event_step * cmd_chan);

	/* Num loop low */
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_SET_LOOPS_L, 0x00000001);
	/* Num loop high */
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_SET_LOOPS_H, 0x00000000);
	/* Loop status clear */
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_GET_LOOPS_H, 0x10000000);
	/* Cookie control mask */
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_COOKIE_CTRL, 0x00000000);
	/* DMA Address inc */
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_ADDR_INC_BASE, 0x00000000);
	/* DMA Address inc mask */
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_ADDR_INC_MASK, 0x00000000);
	/* Exerciser DMA Address Increment Table Load */
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_ADDR_INC_LOAD, 0x00000000);
	/* Perf credit control */
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_CRDT_CTRL, 0x00000000);
	/* set perf mode */
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_CONTROL, 0x00000000);
	/* Reset event perf control */
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, event_offset + DPUEX_CMD_REG_PERF_CRDT_EV, 0x00000000);

#define DPUEX_SIDEBAND_REG(_reg)                                               \
    DPUEX_CMD_REG_PERF_CMD_SIDE_##_reg + write_num * DPUEX_CMD_REG_PERF_CMD_SIDE_##_reg##_STEP

#define DPUEX_CMD_REG(_reg)                                                    \
	DPUEX_CMD_REG_CMD_##_reg + write_num * DPUEX_CMD_REG_CMD_##_reg##_STEP

	for (write_num = 0; write_num < num_writes; ++write_num) {
		dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(31_0),
			dpu_cmd->hw_cmd[write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND].u32[0]);
		dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(63_32),
			dpu_cmd->hw_cmd[write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND].u32[1]);
		dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(95_64),
			dpu_cmd->hw_cmd[write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND].u32[2]);
		dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(127_96),
			dpu_cmd->hw_cmd[write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND].u32[3]);

		/* Write hw descs */
		if (write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND + 1 == dpu_cmd->cmd_len) {
			ksb_oword_t hw_desc = { 0 };

			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(159_128), hw_desc.u32[0]);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(191_160), hw_desc.u32[1]);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(223_192), hw_desc.u32[2]);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(255_224), hw_desc.u32[3]);
		} else {
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(159_128),
				dpu_cmd->hw_cmd[write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND + 1].u32[0]);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(191_160),
				dpu_cmd->hw_cmd[write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND + 1].u32[1]);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(223_192),
				dpu_cmd->hw_cmd[write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND + 1].u32[2]);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(255_224),
				dpu_cmd->hw_cmd[write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND + 1].u32[3]);
		}

		/* Second write 32b empty sideband */
		dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_SIDEBAND_REG(31_0), 0x00000000);
		dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_SIDEBAND_REG(63_32), 0x00000000);

		/* Third write tlast */
		if (write_num == (num_writes - 1))
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_CMD_SIDE +  write_num * DPUEX_CMD_REG_CMD_SIDE_STEP, 0x10);
		else
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_CMD_SIDE +  write_num * DPUEX_CMD_REG_CMD_SIDE_STEP, 0x0);
	}

#undef DPUEX_CMD_REG
#undef DPUEX_SIDEBAND_REG

	/* Final write command control */
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_SET_LOOPS_L, 0x00000001);
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_SET_LOOPS_H, 0x00000000);

	KSB_POPULATE_DWORD_3(reg_val, DPUEX_CMD_REG_CONTROL_TEST_EN, 1,
						DPUEX_CMD_REG_CONTROL_START_ADDR, 0,
						DPUEX_CMD_REG_CONTROL_STOP_ADDR, num_writes - 1);

	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_CONTROL, reg_val.ksb_u32);

	for (i = 0; i < 5; ++i) {
		dpu_poll_ev(cdx_dev, event_offset, &ev);
		dpu_exerciser_reg_rd(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_CRDT_POOL);
		if (ev.err) {
			dpu_dump_err_info(ev.err_info);
			dpu_exerciser_reg_rd(cdx_dev->pci_dev, event_offset + DPUEX_EV_REG_EVENT_COUNT);
			return -EIO;
		} else if (ev.valid) {
			dpu_cmd->buf = ev.buf_head;
			return 0;
		}

		msleep(10);
	}

	return -EIO;
}

static void
dpu_execute_single_perf_cmd(cdx_device_t *cdx_dev, struct dpu_ex_cmd *dpu_cmd, int cmd_chan)
{
	int write_num = 0;
	struct ksb_dword reg_val;
	u32 cmd_offset = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_CMD_OFFSET);
	u32 cmd_step = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_CMD_STEP_OFFSET);
	u32 event_offset = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_EVNT_OFFSET);
	u32 event_step = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_EVNT_STEP_OFFSET);
	int num_writes = KSB_CEIL(dpu_cmd->cmd_len, EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND);

	cmd_offset = cmd_offset + (cmd_step * cmd_chan);
	event_offset = event_offset + (event_step * cmd_chan);

	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_SET_LOOPS_H, 0x20000000);
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_GET_LOOPS_H, 0x10000000);
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_SET_LOOPS_L, 0x00000000);
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_SET_LOOPS_H, 0x00000000);

	KSB_POPULATE_DWORD_5(reg_val, DPUEX_CMD_REG_PERF_CONTROL_PERF_EN, 1,
			DPUEX_CMD_REG_PERF_CONTROL_NXT_CMD_EN, 0,
			DPUEX_CMD_REG_PERF_CONTROL_SEQ_RATE_CTRL, dpu_cmd->seq_rate,
			DPUEX_CMD_REG_PERF_CONTROL_NXT_CMD_RATE_CTRL, dpu_cmd->seq_rate,
			DPUEX_CMD_REG_PERF_CONTROL_SEQ_RATE_CTRL_LOW, dpu_cmd->seq_rate_low);

	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_CONTROL, reg_val.ksb_u32);
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_EV_CAM_CTRL, 0x00000004);
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, event_offset + DPUEX_CMD_REG_PERF_CRDT_EV, 0x00000001);
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_COOKIE_CTRL, 0x00000fff);
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_ADDR_INC_BASE, 0x00000000);
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_ADDR_INC_MASK, 0x000fffff);
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_ADDR_INC_LOAD, 0x00000000);

#define DPUEX_SIDEBAND_REG(_reg)                                               \
    DPUEX_CMD_REG_PERF_CMD_SIDE_##_reg + write_num * DPUEX_CMD_REG_PERF_CMD_SIDE_##_reg##_STEP

#define DPUEX_CMD_REG(_reg)                                                    \
	DPUEX_CMD_REG_CMD_##_reg + write_num * DPUEX_CMD_REG_CMD_##_reg##_STEP

	for (write_num = 0; write_num < num_writes; ++write_num) {
		dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(31_0),
			dpu_cmd->hw_cmd[write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND].u32[0]);
		dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(63_32),
			dpu_cmd->hw_cmd[write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND].u32[1]);
		dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(95_64),
			dpu_cmd->hw_cmd[write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND].u32[2]);
		dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(127_96),
			dpu_cmd->hw_cmd[write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND].u32[3]);

		/* Write hw descs */
		if (write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND + 1 == dpu_cmd->cmd_len) {
			ksb_oword_t hw_desc = { 0 };

			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(159_128), hw_desc.u32[0]);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(191_160), hw_desc.u32[1]);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(223_192), hw_desc.u32[2]);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(255_224), hw_desc.u32[3]);
		} else {
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(159_128),
				dpu_cmd->hw_cmd[write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND + 1].u32[0]);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(191_160),
				dpu_cmd->hw_cmd[write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND + 1].u32[1]);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(223_192),
				dpu_cmd->hw_cmd[write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND + 1].u32[2]);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG(255_224),
				dpu_cmd->hw_cmd[write_num * EF_DPU_HW_CMD_WORDS_NUM_PER_SIDEBAND + 1].u32[3]);
		}

		/* Write 32b sideband */
		if (write_num == 0) {
			KSB_POPULATE_DWORD_3(reg_val, DPUEX_CMD_REG_PERF_CMD_SIDE_31_0_CMD_HEADER0, 1,
				DPUEX_CMD_REG_PERF_CMD_SIDE_31_0_WAIT_CTXT_SRC, dpu_cmd->wait_ctxt_src,
				DPUEX_CMD_REG_PERF_CMD_SIDE_31_0_EDIT_BUFID_EN, dpu_cmd->edit_src_bufid);

			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_SIDEBAND_REG(31_0), reg_val.ksb_u32);

			KSB_POPULATE_DWORD_2(reg_val, DPUEX_CMD_REG_PERF_CMD_SIDE_63_32_ROUTE_CTRL, dpu_cmd->route_ctrl,
				DPUEX_CMD_REG_PERF_CMD_SIDE_63_32_CTXT_STR_EN, 1);

			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_SIDEBAND_REG(63_32), reg_val.ksb_u32);
		} else {
			/* For dma desc, write empty sideband */
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_SIDEBAND_REG(31_0), 0x00000000);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_SIDEBAND_REG(63_32),  0x00000000);
		}

		/* Third write tlast */
		if (write_num == (num_writes - 1))
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_CMD_SIDE +  write_num * DPUEX_CMD_REG_CMD_SIDE_STEP, 0x10);
		else
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_CMD_SIDE +  write_num * DPUEX_CMD_REG_CMD_SIDE_STEP, 0x0);
	}

#undef DPUEX_CMD_REG
#undef DPUEX_SIDEBAND_REG

	/* Final write command control */
	KSB_POPULATE_DWORD_3(reg_val, DPUEX_CMD_REG_CONTROL_TEST_EN, 0,
						DPUEX_CMD_REG_CONTROL_START_ADDR, 0,
						DPUEX_CMD_REG_CONTROL_STOP_ADDR, num_writes - 1);

	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_CONTROL, reg_val.ksb_u32);
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_CRDT_CTRL, 0x00000000);
}

static int prepare_dpu_rd_wr_cmd(cdx_device_t *cdx_dev, ksb_dpu_cmd_t *usr_cmd)
{
	int rc;
	struct dpu_ex_cmd *dpu_cmd;

	dpu_cmd = kzalloc(sizeof(*dpu_cmd), GFP_KERNEL);
	if (!dpu_cmd)
		return -ENOMEM;

	dpu_cmd->type = EF_DPU_CMD_RD;
	dpu_cmd->src = EF_DPU_SRC_DMA;
	dpu_cmd->dst = EF_DPU_DST_BUF;
	dpu_cmd->ex_num = usr_cmd->dpu_exe;
	dpu_cmd->ev_chan = usr_cmd->dpu_exe;
	dpu_cmd->cookie = 0xcafe;
	dpu_cmd->dma_len = usr_cmd->dma_len;
	dpu_cmd->src_dpu_buf_pool = 0;
	dpu_cmd->dst_dpu_buf_pool = 0;
	dpu_cmd->addr_space = cdx_dev->addr_space;

	rc = map_user_buf_to_sgl(cdx_dev, usr_cmd, dpu_cmd, false);
	if (rc)
		goto fini;

	fill_in_dpu_hw_cmd_hdr(dpu_cmd);
	fill_in_dpu_hw_dma_descs(dpu_cmd);
	fill_in_dpu_cmd_words(dpu_cmd);

	rc = dpu_execute_single_cmd(cdx_dev, dpu_cmd, usr_cmd->dpu_exe);
	if (rc) {
		unmap_user_buf_from_sgl(cdx_dev, usr_cmd, dpu_cmd);
		goto fini;
	}

	unmap_user_buf_from_sgl(cdx_dev, usr_cmd, dpu_cmd);

	dpu_cmd->cmd_len = 0;

	dpu_cmd->type = EF_DPU_CMD_WR;
	dpu_cmd->src = EF_DPU_SRC_BUF;
	dpu_cmd->dst = EF_DPU_DST_DMA;
	dpu_cmd->ex_num = usr_cmd->dpu_exe;
	dpu_cmd->ev_chan = usr_cmd->dpu_exe;
	dpu_cmd->cookie = 0xdead;
	dpu_cmd->dma_len = usr_cmd->dma_len;
	dpu_cmd->src_dpu_buf_pool = 0;
	dpu_cmd->dst_dpu_buf_pool = 0;
	dpu_cmd->addr_space = cdx_dev->addr_space;
	dpu_cmd->src_buf_free = true;

	rc = map_user_buf_to_sgl(cdx_dev, usr_cmd, dpu_cmd, true);
	if (rc)
		goto fini;

	fill_in_dpu_hw_cmd_hdr(dpu_cmd);
	fill_in_dpu_hw_dma_descs(dpu_cmd);
	fill_in_dpu_cmd_words(dpu_cmd);

	rc = dpu_execute_single_cmd(cdx_dev, dpu_cmd, usr_cmd->dpu_exe);

	unmap_user_buf_from_sgl(cdx_dev, usr_cmd, dpu_cmd);
fini:
	kfree(dpu_cmd);

	return rc;
}

static int prepare_dpu_wr_cmd(cdx_device_t *cdx_dev, ksb_dpu_cmd_t *usr_cmd)
{
	int rc;
	struct dpu_ex_cmd *dpu_cmd;

	dpu_cmd = kzalloc(sizeof(*dpu_cmd), GFP_KERNEL);
	if (!dpu_cmd)
		return -ENOMEM;

	dpu_cmd->type = EF_DPU_CMD_BUF;
	dpu_cmd->buf_type = (enum dpu_cmd_buf_subtype_t)EF_DPU_CMD_BUF_ST_ALLOC;
	dpu_cmd->ex_num = usr_cmd->dpu_exe;
	dpu_cmd->ev_chan = usr_cmd->dpu_exe;
	dpu_cmd->cookie = 0xfade;
	dpu_cmd->dma_len = usr_cmd->dma_len;
	dpu_cmd->src_dpu_buf_pool = 0;
	dpu_cmd->dst_dpu_buf_pool = 0;
	dpu_cmd->addr_space = cdx_dev->addr_space;

	fill_in_dpu_hw_cmd_buf_hdr(dpu_cmd);
	fill_in_dpu_cmd_words(dpu_cmd);

	rc = dpu_execute_single_cmd(cdx_dev, dpu_cmd, usr_cmd->dpu_exe);
	if (rc)
		goto fini;

	dpu_cmd->cmd_len = 0;

	dpu_cmd->type = EF_DPU_CMD_WR;
	dpu_cmd->src = EF_DPU_SRC_BUF;
	dpu_cmd->dst = EF_DPU_DST_DMA;
	dpu_cmd->ex_num = usr_cmd->dpu_exe;
	dpu_cmd->ev_chan = usr_cmd->dpu_exe;
	dpu_cmd->cookie = 0xdead;
	dpu_cmd->dma_len = usr_cmd->dma_len;
	dpu_cmd->src_dpu_buf_pool = 0;
	dpu_cmd->dst_dpu_buf_pool = 0;
	dpu_cmd->addr_space = cdx_dev->addr_space;
	dpu_cmd->src_buf_free = true;
	usr_cmd->dst = usr_cmd->src;

	rc = map_user_buf_to_sgl(cdx_dev, usr_cmd, dpu_cmd, true);
	if (rc)
		goto fini;

	fill_in_dpu_hw_cmd_hdr(dpu_cmd);
	fill_in_dpu_hw_dma_descs(dpu_cmd);
	fill_in_dpu_cmd_words(dpu_cmd);

	rc = dpu_execute_single_cmd(cdx_dev, dpu_cmd, usr_cmd->dpu_exe);

	unmap_user_buf_from_sgl(cdx_dev, usr_cmd, dpu_cmd);
fini:
	kfree(dpu_cmd);

	return rc;
}

static int prepare_dpu_rd_cmd(cdx_device_t *cdx_dev, ksb_dpu_cmd_t *usr_cmd)
{
	int rc;
	struct dpu_ex_cmd *dpu_cmd;

	dpu_cmd = kzalloc(sizeof(*dpu_cmd), GFP_KERNEL);
	if (!dpu_cmd)
		return -ENOMEM;

	dpu_cmd->type = EF_DPU_CMD_RD;
	dpu_cmd->src = EF_DPU_SRC_DMA;
	dpu_cmd->dst = EF_DPU_DST_BUF;
	dpu_cmd->ex_num = usr_cmd->dpu_exe;
	dpu_cmd->ev_chan = usr_cmd->dpu_exe;
	dpu_cmd->cookie = 0xcafe;
	dpu_cmd->dma_len = usr_cmd->dma_len;
	dpu_cmd->src_dpu_buf_pool = 0;
	dpu_cmd->dst_dpu_buf_pool = 0;
	dpu_cmd->addr_space = cdx_dev->addr_space;

	rc = map_user_buf_to_sgl(cdx_dev, usr_cmd, dpu_cmd, false);
	if (rc)
		goto fini;

	fill_in_dpu_hw_cmd_hdr(dpu_cmd);
	fill_in_dpu_hw_dma_descs(dpu_cmd);
	fill_in_dpu_cmd_words(dpu_cmd);

	rc = dpu_execute_single_cmd(cdx_dev, dpu_cmd, usr_cmd->dpu_exe);
	if (rc) {
		unmap_user_buf_from_sgl(cdx_dev, usr_cmd, dpu_cmd);
		goto fini;
	}

	unmap_user_buf_from_sgl(cdx_dev, usr_cmd, dpu_cmd);

	dpu_cmd->cmd_len = 0;

	dpu_cmd->type = EF_DPU_CMD_BUF;
	dpu_cmd->buf_type = (enum dpu_cmd_buf_subtype_t)EF_DPU_CMD_BUF_ST_FREE;

	dpu_cmd->src = EF_DPU_SRC_BUF;
	dpu_cmd->dst = EF_DPU_DST_DMA;
	dpu_cmd->ex_num = usr_cmd->dpu_exe;
	dpu_cmd->ev_chan = usr_cmd->dpu_exe;
	dpu_cmd->cookie = 0xface;
	dpu_cmd->dma_len = usr_cmd->dma_len;
	dpu_cmd->src_dpu_buf_pool = 0;
	dpu_cmd->dst_dpu_buf_pool = 0;

	fill_in_dpu_hw_cmd_buf_hdr(dpu_cmd);
	fill_in_dpu_cmd_words(dpu_cmd);

	rc = dpu_execute_single_cmd(cdx_dev, dpu_cmd, usr_cmd->dpu_exe);

fini:
	kfree(dpu_cmd);

	return rc;
}

static int prepare_dpu_perf_rd_cmd(cdx_device_t *cdx_dev, ksb_dpu_cmd_t *usr_cmd, ksb_dpu_perf_t *perf)
{
	int rc;
	unsigned ex_num;
	u32 zero_ev_cnt = 0;
	struct ksb_dword reg_val;
	struct dpu_ex_cmd *dpu_cmd;
	int cmd_chan = usr_cmd->dpu_exe;
	u16 snap_start = 0, snap_cnt = 0;
	uint64_t rec_events = 0, exp_events;
	struct timespec64 start_ts, end_ts;
	struct timespec64 delta;
	ef_dpu_ex_data_channel_t chan;
	u32 cmd_offset = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_CMD_OFFSET);
	u32 cmd_step = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_CMD_STEP_OFFSET);
	u32 d2u_offset = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_D2U_OFFSET);
	u32 d2u_step = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_D2U_STEP_OFFSET);

	dpu_cmd = kzalloc(sizeof(*dpu_cmd), GFP_KERNEL);
	if (!dpu_cmd)
		return -ENOMEM;

	dpu_cmd->type = EF_DPU_CMD_RD;
	dpu_cmd->src = EF_DPU_SRC_DMA;
	dpu_cmd->dst = EF_DPU_DST_DCHAN;
	dpu_cmd->ex_num = usr_cmd->dpu_exe;
	dpu_cmd->ev_chan = usr_cmd->dpu_exe;
	dpu_cmd->dst_dchan = dpu_cmd->ev_chan + EF_DPU_MAX_NOC_DCHAN_NUM;
	dpu_cmd->cookie = 0xcafe;
	dpu_cmd->dma_len = usr_cmd->dma_len;
	dpu_cmd->src_dpu_buf_pool = 0;
	dpu_cmd->dst_dpu_buf_pool = 0;
	dpu_cmd->addr_space = cdx_dev->addr_space;
	dpu_cmd->route_ctrl = SIDEBAND_ROUTE_CTRL_DROP;
	dpu_cmd->wait_ctxt_src = SIDEBAND_WAIT_CTXT_SRC_NONE;
	dpu_cmd->edit_src_bufid = false;

	/** Maximum percent of cycles that can be consumed by commands */
	dpu_cmd->seq_rate = SL_DPU_PATH_SEQ_RATE_PERF;
	dpu_cmd->seq_rate_low = 0;

	rc = map_user_hp_to_sgl(cdx_dev, usr_cmd, dpu_cmd, false);
	if (rc)
		goto fini;

	fill_in_dpu_hw_cmd_hdr(dpu_cmd);
	fill_in_dpu_hw_dma_descs(dpu_cmd);
	fill_in_dpu_cmd_words(dpu_cmd);

	dpu_execute_single_perf_cmd(cdx_dev, dpu_cmd, usr_cmd->dpu_exe);

	dpu_ex_d2u_get_info(dpu_cmd, &chan, &ex_num);

	cmd_offset = cmd_offset + (cmd_step * cmd_chan);
	d2u_offset = d2u_offset + (d2u_step * ex_num);

	switch (chan) {
		case EF_DPU_EX_DATA_CHANNEL_0:
			/* Switch data channel-in exerciser to perf mode */
			KSB_POPULATE_DWORD_2(reg_val, DPUEX_D2U_REG_PERF_CONTROL_0_PERF_EN, 1,
					DPUEX_D2U_REG_PERF_CONTROL_0_SEQ_RATE_CTRL, dpu_cmd->seq_rate);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, d2u_offset + DPUEX_D2U_REG_PERF_CONTROL_0, reg_val.ksb_u32);

			/* Set expected frame length */
			KSB_POPULATE_DWORD_1(reg_val, DPUEX_D2U_REG_PACKET_DATA_0_LENGTH, dpu_cmd->dma_len);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, d2u_offset + DPUEX_D2U_REG_PACKET_DATA_0, reg_val.ksb_u32);

			/* Set start and stop addresses */
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, d2u_offset + DPUEX_D2U_REG_CONTROL_0, 0x00000000);
			break;
		case EF_DPU_EX_DATA_CHANNEL_1:
			KSB_POPULATE_DWORD_2(reg_val, DPUEX_D2U_REG_PERF_CONTROL_1_PERF_EN, 1,
					DPUEX_D2U_REG_PERF_CONTROL_1_SEQ_RATE_CTRL, dpu_cmd->seq_rate);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, d2u_offset + DPUEX_D2U_REG_PERF_CONTROL_1, reg_val.ksb_u32);

			/* Set expected frame length */
			KSB_POPULATE_DWORD_1(reg_val, DPUEX_D2U_REG_PACKET_DATA_1_LENGTH, dpu_cmd->dma_len);
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, d2u_offset + DPUEX_D2U_REG_PACKET_DATA_1, reg_val.ksb_u32);

			/* Set start and stop addresses */
			dpu_exerciser_reg_wr(cdx_dev->pci_dev, d2u_offset + DPUEX_D2U_REG_CONTROL_1, 0x00000000);
			break;
	}

    {
		ktime_t now;
		ktime_get_real_ts64(&start_ts);

		if (!ex_stats_snap_ready(cdx_dev, cmd_offset, &snap_start)) {
			pr_err("Failed to get ready snap\n");
		} else {
			/* Load the counters */
			exp_events = usr_cmd->loops;
			ex_perf_d2u_set_loop(cdx_dev, chan, d2u_offset, exp_events, true);
			ex_perf_cmd_set_loop(cdx_dev, cmd_offset, exp_events, false);

			now = ktime_get();

			while (rec_events < exp_events && (zero_ev_cnt < NO_EVENTS_FATAL)) {
				u32 ev;
				if (!ex_stats_snap_ready(cdx_dev, cmd_offset, &snap_cnt))
					break;

				if (snap_start == snap_cnt) {
					if (ktime_ms_delta(ktime_get(), now) > NO_EVENTS_FATAL_TIMEOUT) {
						pr_err("Failed to get increamental snapshot. Aborting...\n");
						break;
					}

					msleep(DEFAULT_SNAP_REQ_TIME_MS);
					continue;
				} else if ((snap_start + 1) == snap_cnt) {
					ev = ex_stats_read_ev_active(cdx_dev, cmd_offset);
					if (ev != 0)
						rec_events += ev;
					else
						zero_ev_cnt++;

					++snap_start;
					now = ktime_get();
					msleep(DEFAULT_SNAP_REQ_TIME_MS);
				} else {
					pr_err("Got the bad snap eeries: %0d Expected: %0d. Aborting...\n", snap_start, snap_cnt);
					break;
				}
			}

			ktime_get_real_ts64(&end_ts);
			delta = timespec64_sub(end_ts, start_ts);
			perf->loops = rec_events;
			perf->duration_ns = timespec64_to_ns(&delta);
			pr_debug("Total received events: %0llu zero events: %u\n", rec_events, zero_ev_cnt);
		}
    }

	unmap_user_hp(cdx_dev, usr_cmd, dpu_cmd);
fini:
	kfree(dpu_cmd);

	return rc;
}

static int prepare_dpu_perf_rd_host_to_buff_cmd(cdx_device_t *cdx_dev, ksb_dpu_cmd_t *usr_cmd, ksb_dpu_perf_t *perf)
{
	int rc;
	struct timespec64 delta;
	struct dpu_ex_cmd *dpu_cmd;
	int cmd_chan = usr_cmd->dpu_exe;
	u16 snap_cnt = 0, snap_start = 0;
	struct timespec64 start_ts, end_ts;
	uint64_t rec_events = 0, exp_events;
	u32 next_cmd_offset, zero_ev_cnt = 0;
	u32 cmd_offset = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_CMD_OFFSET);
	u32 cmd_step = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_CMD_STEP_OFFSET);

	cmd_offset = cmd_offset + (cmd_step * cmd_chan);
	next_cmd_offset = cmd_offset + cmd_step;

	dpu_cmd = kzalloc(sizeof(*dpu_cmd), GFP_KERNEL);
	if (!dpu_cmd)
		return -ENOMEM;

	dpu_cmd->type = EF_DPU_CMD_RD;
	dpu_cmd->src = EF_DPU_SRC_DMA;
	dpu_cmd->dst = EF_DPU_DST_BUF;
	dpu_cmd->ex_num = usr_cmd->dpu_exe;
	dpu_cmd->ev_chan = usr_cmd->dpu_exe;
	dpu_cmd->dst_dchan = dpu_cmd->ev_chan + EF_DPU_MAX_NOC_DCHAN_NUM;
	dpu_cmd->cookie = 0xcafe;
	dpu_cmd->dma_len = usr_cmd->dma_len;
	dpu_cmd->src_dpu_buf_pool = 0;
	dpu_cmd->dst_dpu_buf_pool = 0;
	dpu_cmd->addr_space = cdx_dev->addr_space;
	dpu_cmd->route_ctrl = SIDEBAND_ROUTE_CTRL_DPU_LOCAL;
	dpu_cmd->wait_ctxt_src = SIDEBAND_WAIT_CTXT_SRC_NONE;
	dpu_cmd->edit_src_bufid = false;

	/** Maximum percent of cycles that can be consumed by commands */
	dpu_cmd->seq_rate = SL_DPU_PATH_SEQ_RATE_PERF;
	dpu_cmd->seq_rate_low = 0;

	rc = map_user_hp_to_sgl(cdx_dev, usr_cmd, dpu_cmd, false);
	if (rc)
		goto fini;

	fill_in_dpu_hw_cmd_hdr(dpu_cmd);
	fill_in_dpu_hw_dma_descs(dpu_cmd);
	fill_in_dpu_cmd_words(dpu_cmd);

	dpu_execute_single_perf_cmd(cdx_dev, dpu_cmd, usr_cmd->dpu_exe);

	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_CRDT_POOL_CTRL, 0x00000000);
	/* TODO: Find exact credits from firmware */
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_CRDT_POOL, DEFAULT_PERF_CREDIT_POOL);

	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_CRDT_CTRL, WAIT_LOCAL_POOL_CRDT);
	msleep(1);
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_CRDT_CTRL, WAIT_EV_CRDT);
	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_CRDT_EV, DEFAULT_PERF_CRDT_EV);

	dpu_cmd->cmd_len = 0;

	dpu_cmd->type = EF_DPU_CMD_BUF;
	dpu_cmd->buf_type = (enum dpu_cmd_buf_subtype_t)EF_DPU_CMD_BUF_ST_FREE;

	dpu_cmd->src = EF_DPU_SRC_BUF;
	dpu_cmd->dst = EF_DPU_DST_DMA;
	dpu_cmd->ex_num = usr_cmd->dpu_exe + 1;
	dpu_cmd->ev_chan = usr_cmd->dpu_exe + 1;
	dpu_cmd->cookie = 0xface;
	dpu_cmd->buf = 0xFFFF;
	dpu_cmd->dma_len = usr_cmd->dma_len;
	dpu_cmd->src_dpu_buf_pool = 0;
	dpu_cmd->dst_dpu_buf_pool = 0;
	dpu_cmd->route_ctrl = SIDEBAND_ROUTE_CTRL_DROP;
	dpu_cmd->wait_ctxt_src = SIDEBAND_WAIT_CTXT_SRC_OTHER_EX;
	dpu_cmd->edit_src_bufid = true;

	fill_in_dpu_hw_cmd_buf_hdr(dpu_cmd);
	fill_in_dpu_cmd_words(dpu_cmd);

	dpu_execute_single_perf_cmd(cdx_dev, dpu_cmd, usr_cmd->dpu_exe + 1);

	dpu_exerciser_reg_wr(cdx_dev->pci_dev, cmd_offset + DPUEX_CMD_REG_PERF_CRDT_POOL_CTRL, 0x00000000);

	{
		ktime_t now;
		ktime_get_real_ts64(&start_ts);

		if (!ex_stats_snap_ready(cdx_dev, cmd_offset, &snap_start)) {
			pr_err("Failed to get ready snap\n");
		} else {
			/* Load the counters */
			exp_events = usr_cmd->loops;
			ex_perf_cmd_set_loop(cdx_dev, cmd_offset, exp_events, false);
			ex_perf_cmd_set_loop(cdx_dev, next_cmd_offset, exp_events, false);

			now = ktime_get();

			while (rec_events < exp_events && (zero_ev_cnt < NO_EVENTS_FATAL)) {
				u32 ev;

				if (!ex_stats_snap_ready(cdx_dev, cmd_offset, &snap_cnt))
					break;

				if (snap_start == snap_cnt) {
					if (ktime_ms_delta(ktime_get(), now) > NO_EVENTS_FATAL_TIMEOUT) {
						pr_err("Failed to get increamental snapshot. Aborting...\n");
						break;
					}

					msleep(DEFAULT_SNAP_REQ_TIME_MS);
					continue;
				} else if ((snap_start + 1) == snap_cnt) {
					ev = ex_stats_read_ev_active(cdx_dev, cmd_offset);
					if (ev != 0)
						rec_events += ev;
					else
						zero_ev_cnt++;

					++snap_start;
					now = ktime_get();
					msleep(DEFAULT_SNAP_REQ_TIME_MS);
				} else {
					pr_err("Got the bad snap eeries: %0d Expected: %0d. Aborting...\n", snap_start, snap_cnt);
					break;
				}
			}

			ktime_get_real_ts64(&end_ts);
			delta = timespec64_sub(end_ts, start_ts);
			perf->loops = rec_events;
			perf->duration_ns = timespec64_to_ns(&delta);
			pr_debug("Total received events: %0llu zero events: %u\n", rec_events, zero_ev_cnt);
		}
	}

	unmap_user_hp(cdx_dev, usr_cmd, dpu_cmd);
fini:
	kfree(dpu_cmd);

	return rc;
}

static int prepare_dpu_perf_wr_cmd(cdx_device_t *cdx_dev, ksb_dpu_cmd_t *usr_cmd, ksb_dpu_perf_t *perf)
{
	int rc;
	struct dpu_ex_cmd *dpu_cmd;
	u32 orig_buf, zero_ev_cnt = 0;
	u16 snap_cnt = 0, snap_start = 0;
	struct timespec64 start_ts, end_ts;
	uint64_t rec_events = 0, exp_events;
	struct timespec64 delta;
	u32 cmd_offset = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_CMD_OFFSET);
	u32 cmd_step = dpu_exerciser_reg_rd(cdx_dev->pci_dev, DPUEX_COM_REG_EX_CMD_STEP_OFFSET);

	cmd_offset = cmd_offset + (cmd_step * usr_cmd->dpu_exe);

	dpu_cmd = kzalloc(sizeof(*dpu_cmd), GFP_KERNEL);
	if (!dpu_cmd)
		return -ENOMEM;

	/* Allocate a buffer in DPU.host */
	dpu_cmd->type = EF_DPU_CMD_BUF;
	dpu_cmd->buf_type = DPU_CMD_BUF_ST_ALLOC;
	dpu_cmd->ex_num = usr_cmd->dpu_exe;
	dpu_cmd->ev_chan = usr_cmd->dpu_exe;
	dpu_cmd->cookie = 0xfade;
	dpu_cmd->dma_len = usr_cmd->dma_len;
	dpu_cmd->src_dpu_buf_pool = 0;
	dpu_cmd->dst_dpu_buf_pool = 0;
	dpu_cmd->addr_space = cdx_dev->addr_space;
	dpu_cmd->route_ctrl = SIDEBAND_ROUTE_CTRL_DROP;
	dpu_cmd->wait_ctxt_src = SIDEBAND_WAIT_CTXT_SRC_NONE;
	dpu_cmd->edit_src_bufid = false;

	fill_in_dpu_hw_cmd_buf_hdr(dpu_cmd);
	fill_in_dpu_cmd_words(dpu_cmd);

	rc = dpu_execute_single_cmd(cdx_dev, dpu_cmd, usr_cmd->dpu_exe);
	if (rc)
		goto fini;

	orig_buf =  dpu_cmd->buf;

	/* Execute DMA write */
	dpu_cmd->cmd_len = 0;

	dpu_cmd->type = EF_DPU_CMD_WR;
	dpu_cmd->src = EF_DPU_SRC_BUF;
	dpu_cmd->dst = EF_DPU_DST_DMA;
	dpu_cmd->ex_num = usr_cmd->dpu_exe;
	dpu_cmd->ev_chan = usr_cmd->dpu_exe;
	dpu_cmd->cookie = 0xdead;
	dpu_cmd->dma_len = usr_cmd->dma_len;
	dpu_cmd->src_dpu_buf_pool = 0;
	dpu_cmd->dst_dpu_buf_pool = 0;
	dpu_cmd->addr_space = cdx_dev->addr_space;
	usr_cmd->dst = usr_cmd->src;
	dpu_cmd->src_buf_free = false;
	dpu_cmd->seq_rate_low = 0x2;
	dpu_cmd->route_ctrl = SIDEBAND_ROUTE_CTRL_DROP;
	dpu_cmd->wait_ctxt_src = SIDEBAND_WAIT_CTXT_SRC_NONE;
	dpu_cmd->edit_src_bufid = false;
	dpu_cmd->seq_rate = SL_DPU_PATH_SEQ_RATE_PERF;
	dpu_cmd->seq_rate_low = 0;

	rc = map_user_hp_to_sgl(cdx_dev, usr_cmd, dpu_cmd, true);
	if (rc)
		goto fini;

	fill_in_dpu_hw_cmd_hdr(dpu_cmd);
	fill_in_dpu_hw_dma_descs(dpu_cmd);
	fill_in_dpu_cmd_words(dpu_cmd);

	dpu_execute_single_perf_cmd(cdx_dev, dpu_cmd, usr_cmd->dpu_exe);

	{
		ktime_t now;
		ktime_get_real_ts64(&start_ts);

		if (!ex_stats_snap_ready(cdx_dev, cmd_offset, &snap_start)) {
			pr_err("Failed to get ready snap\n");
		} else {
			/* Load the counters */
			exp_events = usr_cmd->loops;
			ex_perf_cmd_set_loop(cdx_dev, cmd_offset, exp_events, false);

			now = ktime_get();

			while (rec_events < exp_events && (zero_ev_cnt < NO_EVENTS_FATAL)) {
				u32 ev;

				if (!ex_stats_snap_ready(cdx_dev, cmd_offset, &snap_cnt))
					break;

				if (snap_start == snap_cnt) {
					if (ktime_ms_delta(ktime_get(), now) > NO_EVENTS_FATAL_TIMEOUT) {
						pr_err("Failed to get increamental snapshot. Aborting...\n");
						break;
					}

					msleep(DEFAULT_SNAP_REQ_TIME_MS);
					continue;
				} else if ((snap_start + 1) == snap_cnt) {
					ev = ex_stats_read_ev_active(cdx_dev, cmd_offset);
					if (ev != 0)
						rec_events += ev;
					else
						zero_ev_cnt++;

					++snap_start;
					now = ktime_get();
					msleep(DEFAULT_SNAP_REQ_TIME_MS);
				} else {
					pr_err("Got the bad snap eeries: %0d Expected: %0d. Aborting...\n", snap_start, snap_cnt);
					break;
				}
			}

			ktime_get_real_ts64(&end_ts);
			delta = timespec64_sub(end_ts, start_ts);
			perf->loops = rec_events;
			perf->duration_ns = timespec64_to_ns(&delta);
			pr_debug("Total received events: %0llu zero events: %u\n", rec_events, zero_ev_cnt);
		}
	}

	unmap_user_hp(cdx_dev, usr_cmd, dpu_cmd);

	/* Free DPU.host buffer */
	dpu_cmd->cmd_len = 0;
	dpu_cmd->buf = orig_buf;

	dpu_cmd->type = EF_DPU_CMD_BUF;
	dpu_cmd->buf_type = DPU_CMD_BUF_ST_FREE;

	dpu_cmd->src = EF_DPU_SRC_BUF;
	dpu_cmd->dst = EF_DPU_DST_DMA;
	dpu_cmd->ex_num = usr_cmd->dpu_exe;
	dpu_cmd->ev_chan = usr_cmd->dpu_exe;
	dpu_cmd->cookie = 0xface;
	dpu_cmd->dma_len = usr_cmd->dma_len;
	dpu_cmd->src_dpu_buf_pool = 0;
	dpu_cmd->dst_dpu_buf_pool = 0;
	dpu_cmd->route_ctrl = SIDEBAND_ROUTE_CTRL_DROP;
	dpu_cmd->wait_ctxt_src = SIDEBAND_WAIT_CTXT_SRC_NONE;
	dpu_cmd->edit_src_bufid = false;

	fill_in_dpu_hw_cmd_buf_hdr(dpu_cmd);
	fill_in_dpu_cmd_words(dpu_cmd);

	rc = dpu_execute_single_cmd(cdx_dev, dpu_cmd, usr_cmd->dpu_exe);

fini:
	kfree(dpu_cmd);

	return rc;
}

int dpu_exerciser_execute_user_cmd(cdx_device_t *cdx_dev, ksb_dpu_cmd_t *usr_cmd)
{
	switch (usr_cmd->cmd) {
	case KSB_DPU_OP_RD:	return prepare_dpu_rd_cmd(cdx_dev, usr_cmd);
	case KSB_DPU_OP_WR:	return prepare_dpu_wr_cmd(cdx_dev, usr_cmd);
	case KSB_DPU_OP_RD_WR:	return prepare_dpu_rd_wr_cmd(cdx_dev, usr_cmd);
	default:	return -EINVAL;
	}
}

int dpu_exerciser_execute_user_perf_cmd(cdx_device_t *cdx_dev, ksb_dpu_cmd_t *usr_cmd, ksb_dpu_perf_t *perf)
{
	switch (usr_cmd->cmd) {
	case KSB_DPU_OP_PERF_WR:    return prepare_dpu_perf_wr_cmd(cdx_dev, usr_cmd, perf);
	case KSB_DPU_OP_PERF_RD:
		if (usr_cmd->dma_rd_fabric)
			return prepare_dpu_perf_rd_cmd(cdx_dev, usr_cmd, perf);
		else
			return prepare_dpu_perf_rd_host_to_buff_cmd(cdx_dev, usr_cmd, perf);
	default:	return -EINVAL;
	}
}

static void ex_stats_collector(struct work_struct *work)
{
	cdx_device_t *cdx_dev;
	struct ksb_dword reg_val;
	struct delayed_work *dwork;

	dwork = to_delayed_work(work);
	cdx_dev = container_of(dwork, struct cdx_device_s, stats_work);

	mutex_lock(&cdx_dev->stats_lock);

	if (cdx_dev->stats_enabled) {
		KSB_POPULATE_DWORD_1(reg_val, DPUEX_COM_REG_PERF_STAT_SNAP_CTRL_DPU_SNAP, 1);
		dpu_exerciser_reg_wr(cdx_dev->pci_dev, DPUEX_COM_REG_PERF_STAT_SNAP_CTRL_OFFSET, reg_val.ksb_u32);
	}

	mutex_unlock(&cdx_dev->stats_lock);


	queue_delayed_work(cdx_dev->stats_wq, &cdx_dev->stats_work, msecs_to_jiffies(DEFAULT_SNAP_TIME_MS));
}

void dpu_exerciser_set_stats(cdx_device_t *cdx_dev, bool enable)
{
	if (!cdx_dev)
		return;

	mutex_lock(&cdx_dev->stats_lock);
	cdx_dev->stats_enabled = enable & cdx_dev->user_stats_en;
	mutex_unlock(&cdx_dev->stats_lock);
}

int dpu_exerciser_init(struct ksb_drv_ctx *ksb_drv)
{
	int ret;
	cdx_device_t *cdx_dev = ksb_drv->cdx_ctx;

	ret = ksb_mcdi_cmd_get_addr_spc(ksb_drv, &cdx_dev->addr_space.addr_spc_id);
	if (ret)
		return ret;

	ret = ksb_mcdi_cmd_get_addr_spc_fields(ksb_drv, &cdx_dev->addr_space);
	if (ret)
		return ret;

	if (cdx_dev->addr_space.func_id == 0) {
		/* Reset DPU */
		dpu_reset(cdx_dev);

		bitmap_zero(dpu_cmd_exe, MAX_DPU_CMD_EXE);

		cdx_dev->stats_wq = create_singlethread_workqueue("ksb_dpu_ex_stats");
		if (!cdx_dev->stats_wq) {
			pr_err("Failed to create stats workqueue\n");
			return -EINVAL;
		}

		mutex_init(&cdx_dev->stats_lock);
		cdx_dev->stats_enabled = false;
		cdx_dev->user_stats_en = false;
		INIT_DELAYED_WORK(&cdx_dev->stats_work, ex_stats_collector);
		queue_delayed_work(cdx_dev->stats_wq, &cdx_dev->stats_work, msecs_to_jiffies(DEFAULT_SNAP_TIME_MS));
	}

	return 0;
}

void dpu_exerciser_fini(struct ksb_drv_ctx *ksb_drv)
{
	cdx_device_t *cdx_dev = ksb_drv->cdx_ctx;

	if (cdx_dev->addr_space.func_id != 0)
		return;

	if (cdx_dev->stats_wq) {
		cancel_delayed_work_sync(&cdx_dev->stats_work);
		destroy_workqueue(cdx_dev->stats_wq);
		cdx_dev->stats_wq = NULL;
	}
}
