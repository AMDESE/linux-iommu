/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * PF help for an SDXI VF that is being migrated.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#ifndef DMA_SDXI_MIGRATION_H
#define DMA_SDXI_MIGRATION_H

#include <linux/types.h>

struct pci_dev;

int sdxi_pf_restart_vf_contexts(struct pci_dev *vf, u16 vf_num,
				u16 cxt_start, u16 cxt_end, u64 db_value);

#endif /* DMA_SDXI_MIGRATION_H */
