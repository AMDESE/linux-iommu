// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI completion status block helpers.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/sched/signal.h>

/*
 * Upper bound on how long to busy-wait for a descriptor completion
 * before giving up. A healthy completion lands in microseconds; a
 * non-completion means the device errored (e.g. "Function stopped")
 * and will never signal, so bound it rather than spin forever.
 */
#define SDXI_COMPLETION_TIMEOUT_MS 5000

#include "completion.h"
#include "descriptor.h"

struct sdxi_completion {
	struct sdxi_dev *sdxi;
	struct sdxi_cst_blk *cst_blk;
	dma_addr_t cst_blk_dma;
};

struct sdxi_completion *sdxi_completion_alloc(struct sdxi_dev *sdxi)
{
	struct sdxi_completion *sc __free(kfree) = kmalloc(sizeof(*sc),
							   GFP_KERNEL);
	struct sdxi_cst_blk *cst_blk;
	dma_addr_t cst_blk_dma;

	if (!sc)
		return NULL;

	/* Should use a dma_pool. */
	cst_blk = dma_alloc_coherent(sdxi_to_dev(sdxi), sizeof(*cst_blk),
				     &cst_blk_dma, GFP_KERNEL);
	if (!cst_blk)
		return NULL;

	memset(cst_blk, 0, sizeof(*cst_blk));
	cst_blk->signal = cpu_to_le64(1);

	*sc = (typeof(*sc)) {
		.sdxi        = sdxi,
		.cst_blk     = cst_blk,
		.cst_blk_dma = cst_blk_dma,
	};

	return_ptr(sc);
}

void sdxi_completion_free(struct sdxi_completion *sc)
{
	dma_free_coherent(sdxi_to_dev(sc->sdxi), sizeof(*sc->cst_blk),
			  sc->cst_blk, sc->cst_blk_dma);
	kfree(sc);
}

int sdxi_completion_poll(const struct sdxi_completion *sc)
{
	ktime_t timeout = ktime_add_ms(ktime_get(), SDXI_COMPLETION_TIMEOUT_MS);

	while (READ_ONCE(sc->cst_blk->signal) != 0) {
		if (ktime_after(ktime_get(), timeout)) {
			dev_err(sdxi_to_dev(sc->sdxi),
				"completion poll timed out after %u ms (flags=0x%x)\n",
				SDXI_COMPLETION_TIMEOUT_MS,
				le32_to_cpu(sc->cst_blk->flags));
			return -ETIMEDOUT;
		}
		cpu_relax();
	}

	/*
	 * signal == 0 means the device wrote the completion. The ER bit
	 * is a completed-with-error, not a success; callers of this poll
	 * do not inspect it themselves.
	 */
	if (sdxi_completion_errored(sc)) {
		dev_err(sdxi_to_dev(sc->sdxi),
			"completion error (flags=0x%x)\n",
			sdxi_completion_flags(sc));
		return -EIO;
	}

	return 0;
}

static int sdxi_completion_wait_timeout_common(const struct sdxi_completion *sc,
					       unsigned int timeout_ms,
					       bool interruptible)
{
	unsigned long timeout = msecs_to_jiffies(timeout_ms);
	unsigned long deadline = jiffies + timeout;

	for (;;) {
		if (READ_ONCE(sc->cst_blk->signal) == 0)
			return 0;
		if (interruptible && signal_pending(current))
			return -ERESTARTSYS;
		if (timeout_ms && time_after(jiffies, deadline))
			return -ETIMEDOUT;
		usleep_range(50, 200);
	}
}

int sdxi_completion_wait_timeout(const struct sdxi_completion *sc,
				 unsigned int timeout_ms)
{
	return sdxi_completion_wait_timeout_common(sc, timeout_ms, true);
}

int sdxi_completion_wait_timeout_nosignal(const struct sdxi_completion *sc,
					  unsigned int timeout_ms)
{
	return sdxi_completion_wait_timeout_common(sc, timeout_ms, false);
}

bool sdxi_completion_signaled(const struct sdxi_completion *sc)
{
	dma_rmb();
	return (sc->cst_blk->signal == 0);
}

bool sdxi_completion_errored(const struct sdxi_completion *sc)
{
	dma_rmb();
	return FIELD_GET(SDXI_CST_BLK_ER_BIT, le32_to_cpu(sc->cst_blk->flags));
}

u32 sdxi_completion_flags(const struct sdxi_completion *sc)
{
	dma_rmb();
	return le32_to_cpu(sc->cst_blk->flags);
}

void sdxi_completion_attach(struct sdxi_desc *desc,
			    const struct sdxi_completion *cs)
{
	sdxi_desc_set_csb(desc, cs->cst_blk_dma);
}
