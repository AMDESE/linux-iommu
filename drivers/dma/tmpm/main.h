/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD TMPM interface driver
 * https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/58151_0_51-PUB.pdf
 *
 * Copyright (C) 2025 Advanced Micro Devices, Inc.
 */

#ifndef TMPM_INC
#define TMPM_INC

extern unsigned long tmpm_sev_mask;
/*
 * Below two  macros are for guest pages, not hypervisor (host)
 * pages. For use in PAGE_MOVE_GUEST command.
 *
 * For Hypervisor (host) pages, use __psp_pa or __sme_set.
 */

#define __tmpm_sev_set(a) (__pa(a) | tmpm_sev_mask)
#define __tmpm_sev_set_phys(p) ((p) | tmpm_sev_mask)

#define ORDER_2MB 9
#define PAGES_2MB 512
#define RB_SIZE BIT(8)
#define RB_MAX_INDEX (RB_SIZE - 1)

/* Each TMPM mailbox register, offset from base address. */
#define REG_RBCTL (0 * sizeof(u32))
#define REG_RBTAIL (1 * sizeof(u32))
#define REG_RBHEAD (2 * sizeof(u32))
#define REG_CDATA (3 * sizeof(u32))
#define REG_RBLOW (4 * sizeof(u32))
#define REG_RBHIGH (5 * sizeof(u32))
#define REG_THRESH (6 * sizeof(u32))
#define REG_STATUS (7 * sizeof(u32))

/* Control register. */
#define RBCTL_PAUSE GENMASK(0, 0)
#define RBCTL_INIT GENMASK(1, 1)

/* Ring buffer tail register */
#define RBTAIL_TAIL GENMASK(15, 0)
#define RB_TAIL_ASID GENMASK(16, 31)

/* Ring buffer head register. */
#define RBHEAD_HEAD GENMASK(15, 0)

/* Data register. */
#define CDATA_BUFSIZE GENMASK(7, 0)

/* Status register */
#define STATUS_TOGGLE GENMASK(31, 31)
#define STATUS_WPTR_ERR GENMASK(26, 26)
#define STATUS_RB_ERR GENMASK(25, 25)

/* Simplified check for both types of rb error. */
#define RB_ERR GENMASK(26, 25)

#define STATUS_DRIVER_INIT GENMASK(1, 1)
#define STATUS_ENGINE_READY GENMASK(0, 0)

/*
 * An interval to time-out when we poll the status register toggle bit. Exceeding
 * this interval while polling the status register should only happen if the TMPM
 * is wedged.
 */
#define POLL_MSEC 25

/*
 * Shorter interval to wait for other conditions.
 */
#define POLL_USEC 25

/*
 * Each polling loop delays for POLL_USEC (25 us). To poll for POLL_MSEC:
 * POLL_LOOPS =  (USEC_PER_MSEC * POLL_USEC) / POLL_USEC which is reduced to
 * USEC_PER_MSEC.
 */
#define POLL_LOOPS USEC_PER_MSEC

/*
 * TMPM Command IDs and status codes. Subsequent patches will add command IDs.
 */
enum tmpm_cmd_id {
	TMPM_GET_CAPABILITIES = 0,
	TMPM_NOOP = 1,
	TMPM_PSMASH_IO = 0x05,
};

enum tmpm_cmd_status {
	TMPM_INVALID_PLATFORM_STATE = 0x01,
	TMPM_INVALID_PAGE_PADDR = 0x02,
	TMPM_INVALID_NUM_PAGES = 0x03,
	TMPM_MEM_POISONED = 0x04,
	TMPM_INVALID_PAGE_STATE = 0x05,
	TMPM_INVALID_PAGE_SIZE = 0x06,
	TMPM_RMP_NOTEXCLUSIVE = 0x07,
	TMPM_INVALID_GUEST = 0x08,
	TMPM_INVALID_GPA_PADDR = 0x09,
	TMPM_INVALID_HPTE_PADDR	= 0x0a,
	TMPM_INVALID_COMMAND = 0x0b,
	TMPM_INVALID_SRC_PG_PADDR = 0x0c,
	TMPM_INVALID_DST_PG_PADDR = 0x0d,
	TMPM_INVALID_GCTX_PG_PADDR = 0x0e,
	TMPM_INVALID_RMP_PADDR = 0x0f,
	TMPM_INVALID_NEXT = 0x10,
	TMPM_MEM_ABORTED = 0x11,
	TMPM_RSVD_FIELD_NOT_ZERO = 0x12,
	TMPM_VERSION_ERROR = 0x13,
	TMPM_INVALID_TMPM_LIST_ADDR = 0x14,
	TMPM_ADDRESSES_MISMATCH = 0x15,
	TMPM_PARTIAL_SUCCESS = 0x16,
	TMPM_RESOURCE_NOT_AVAILABLE = 0x17,
	TMPM_INVALID_OVERLAP = 0x18,
	TMPM_HW_MEM_ERR = 0x19,
	TMPM_SUCCESS = 0xf0,
};

/*
 * Migration entry sub-status, valid for individual entries on a
 * migration entry list.
 *
 * See section "Sub-Statuses" of the tmpm specification:
 */
enum tmpm_cmd_sub_status {
	TMPM_SUB_STATUS_UNUSED = 0x0,
	TMPM_SUB_STATUS_VALIDATE = 0x01,
	TMPM_SUB_STATUS_ACCESS = 0x02,
};

/* 16-byte ring-buffer entry. */
struct rb_entry {
	phys_addr_t list_paddr;
	u32 cmd_reg;
	u32 status_reg;
};

/* Masks apply to a ring buffer entry. */
#define RBENTRY_CMD GENMASK(7, 0)
#define RBENTRY_NUM_PAGES GENMASK(27, 16)

/* Apply to the rb_entry status_reg */
#define RBENTRY_STATUS GENMASK(7, 0)

static inline u8 read_rbe_status(struct rb_entry *rbe)
{
	/* Pairs with wmb() in submit_rb_entry(). */
	return (smp_load_acquire(&rbe->status_reg) & RBENTRY_STATUS);
}

struct get_capabilities {
	u32 cap_reg;
	u32 fw_reg;
	u32 spec_reg;
	u32 support_reg;
};

/* Apply to the get_capabilities spec_reg */
#define GC_FW_MAJOR GENMASK(31, 24)
#define GC_FW_MINOR GENMASK(23, 16)
/* Apply to the get_capabilities support_reg */
#define GC_SUP_RELOAD GENMASK(4, 4)
#define GC_SUP_PSMASH GENMASK(6, 6)
#define GC_SUP_PUNSMASH GENMASK(7, 7)


/* psmash_io command entry. */
struct psmash_io {
	phys_addr_t src_pg_paddr;
	phys_addr_t smash_hpte_paddr;
	phys_addr_t src_hpmd_paddr;
	union {
		phys_addr_t gctx_paddr;
		struct {
			phys_addr_t status:8;
			phys_addr_t sub_status:4;
			phys_addr_t gctx_pg_paddr:40;
			phys_addr_t reserved:4;
			phys_addr_t pte_suberr:4;
			phys_addr_t pte_err:4;
		};
	};
};

/* Apply to the psmash_io gctx_paddr. */

#define PSMASH_STATUS GENMASK_ULL(7, 0)
#define PSMASH_SUB_STATUS GENMASK_ULL(11, 8)
#define PSMASH_PTE_ERR GENMASK_ULL(63, 60)
#define PSMASH_PTE_SUB_ERR GENMASK_ULL(59, 56)

/*
 * Use this cleanup attribute to free order 0 pages
 * used to submit commands to the TMPM ring buffer.
 */
DEFINE_FREE(__free_pages, void *, if (_T) __free_pages(_T, 0))

/*
 * format_rb_entry() - Return a formatted ring buffer entry.
 *
 * @note: caller must set the host c-bit on the cmd_list
 * using __psp_pa() or __sme_set().
 */
static inline void format_rb_entry(struct rb_entry *entry,
				   phys_addr_t cmd_list,
				   u8 sub_cmd,
				   u16 cmd_list_pages)
{
	entry->cmd_reg = 0;
	entry->status_reg = 0;

	entry->list_paddr = cmd_list;

	entry->cmd_reg |= sub_cmd & RBENTRY_CMD;
	entry->cmd_reg |= ((cmd_list_pages << 16) & RBENTRY_NUM_PAGES);
}

struct tmpm {
	spinlock_t lock; /* Synchronize access to the ring buffer. */
	void __iomem *mbox;
	u16 rb_head_index;
	phys_addr_t rb_phys;
	void *rb_virt;
	struct device *dev;
	int irq;
	struct resource *res;
} ____cacheline_aligned;

enum tmpm_device_type {
	TMPM_DEVICE_PRIMARY = 1,
	TMPM_DEVICE_SECONDARY,
};

struct tmpm_device_data {
	enum tmpm_device_type type;
};

#endif /* TMPM_INC */
