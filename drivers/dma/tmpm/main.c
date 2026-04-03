// SPDX-License-Identifier: GPL-2.0-only
/*
 *
 * AMD TMPM interface driver
 * https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/58151_0_51-PUB.pdf
 *
 * Copyright (C) 2025 Advanced Micro Devices, Inc.
 */

#include <linux/acpi.h>
#include <linux/amd-iommu.h>
#include <linux/circ_buf.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/iommu.h>
#include <linux/mm.h>
#include <linux/platform_device.h>
#include <linux/psp-sev.h>
#include <amd_iommu.h>
#include <amd_iommu_types.h>

#include <vdso/bits.h>

#include <asm/sev.h>
#include <asm/svm.h>

#include "iommu.h"
#include "main.h"

unsigned long tmpm_sev_mask;
static struct platform_device *tmpm_platform_dev;
struct get_capabilities capabilities;

/*
 * read_mb_reg() - Read a TMPM mailbox register
 *
 * @tmpm - The TMPM driver object.
 * @reg - The register from which to read.
 *
 * Return: the contents of the register
 */
static bool in_probe;

static const char *regname(u32 reg)
{
	switch (reg) {
	case REG_RBCTL: return "REG_RBCTL";
	case REG_RBTAIL: return "REG_RBTAIL";
	case REG_RBHEAD: return "REG_RBHEAD";
	case REG_CDATA: return "REG_CDATA";
	case REG_RBLOW: return "REG_RBLOW";
	case REG_RBHIGH: return "REG_RBHIGH";
	case REG_THRESH: return "REG_THRESH";
	case REG_STATUS: return "REG_STATUS";
	}
	return "unknown";
}

static u32 read_mb_reg(struct tmpm *tmpm, u32 reg)
{
	u32 ret = readl(tmpm->mbox + reg);

	if (!in_probe)
		return ret;

	static u32 reg1 = -1, ret1, n;
	if (reg1 != reg || ret1 != ret) {
		if (n) {
			dev_err(tmpm->dev, "___K___ %s %u: (repeated %d) + %s(%x) => %x\n",
				__func__, __LINE__, n, regname(reg1), reg1, ret1);
			n = 0;
		}
		dev_err(tmpm->dev, "___K___ %s %u: %lx + %s(%x) => %x\n", __func__, __LINE__,
			(ulong) tmpm->mbox, regname(reg), reg, ret);
		ret1 = ret;
		reg1 = reg;
	} else {
		++n;
	}
	return ret;
}

/*
 * write_mb_reg() - Write to a TMPM mailbox register
 *
 * @tmpm - The TMPM driver object.
 * @reg - The register to which to write.
 * @val - The value to write.
 */
static void write_mb_reg(struct tmpm *tmpm, u32 reg, u32 val)
{
	if (in_probe)
		dev_err(tmpm->dev, "___K___ %s %u: %lx + %s(%x) <= %x\n", __func__, __LINE__,
			(ulong) tmpm->mbox, regname(reg), reg, val);
	writel(val, tmpm->mbox + reg);
}

/*
 * read_toggle() - Read the PM engine's toggle bit
 *
 * @tmpm - The TMPM driver object.
 *
 * @note: The toggle bit is in the REG_STATUS register. It is used to verify
 * that writes to the REG_RBCTL register have taken effect.
 *
 * Return: the value of the toggle bit (true or false)
 */
static bool read_toggle(struct tmpm *tmpm)
{
	return (read_mb_reg(tmpm, REG_STATUS) & STATUS_TOGGLE);
}

/*
 * write_ctl()
 *
 * @tmpm - The TMPM driver object.
 * @val - The command to write to the control register.
 *
 * @note: Write a command to the control register, poll the status register
 * toggle bit to verify the command is complete. Writes to the control register
 * always show completion by an inversion of the toggle bit.
 *
 * Return: zero upon success, or -EIO if timed out.
 */
static int write_ctl(struct tmpm *tmpm, u32 val)
{
	int i;
	bool prev = read_toggle(tmpm);

	write_mb_reg(tmpm, REG_RBCTL, val);

	for (i = 0; i < POLL_LOOPS; i++) {
		if (prev != read_toggle(tmpm))
			return 0;
		udelay(POLL_USEC);
	}

	dev_err(tmpm->dev,
		"TMPM: took longer than %d msecs to complete a command.\n",
		POLL_MSEC);

	return -EIO;
}

/*
 * read_tail() - Read the TMPM's ring buffer tail index.
 *
 * @tmpm - The TMPM driver object.
 *
 * @note: Caller should hold spinlock_t pm->lock
 *
 * Return: the current tail index of the TMPM ring buffer.
 */
static u16 read_tail(struct tmpm *tmpm)
{
	return read_mb_reg(tmpm, REG_RBTAIL) & RBTAIL_TAIL;
}

/*
 * write_head() - Update the TMPM ring buffer's head index
 *
 * @tmpm - The TMPM driver object.
 * @index  - The index to write to the TMPM's ring buffer  head register
 *
 * @note: Writing the TMPM's head index register awakens the device and causes it
 * to execute all commands queued between the previous head index and the
 * just-written head index.
 */
static void write_head(struct tmpm *tmpm, u16 index)
{
	write_mb_reg(tmpm, REG_RBHEAD, index);
	tmpm->rb_head_index = index;
}

/*
 * read_head() - Read the ring buffer head index.
 *
 * @tmpm - The TMPM driver object.
 *
 * @note: Caller should hold spinlock_t pm->lock. The ring buffer head index is
 * write-only, so read the value that was last saved.
 */
static u16 read_head(struct tmpm *tmpm)
{
	return READ_ONCE(tmpm->rb_head_index);
}

/*
 * is_rb_empty() - Query if the ring buffer is empty
 *
 * @tmpm - The TMPM driver object.
 *
 * Return: true if the ring buffer is empty, false if TMPM object is already
 * locked or if the ring buffer is not empty. If the TMPM object is already
 * locked, the ring buffer is not empty.
 */
static bool is_rb_empty(struct tmpm *tmpm)
{
	bool empty = false;

	if (spin_trylock(&tmpm->lock)) {
		empty = read_head(tmpm) == read_tail(tmpm);
		spin_unlock(&tmpm->lock);
	}

	return empty;
}

static void cleanup_iommu(struct device *dev)
{
	dev_dbg(dev, "(%s): cleaning up iommu\n", __func__);
	tmpm_iommu_detach_devices();
	tmpm_iommu_put_all_domain();
}

/*
 * shutdown_tmpm_engine() - Stop the PM engine before allowing the driver to
 * unload.
 *
 * @tmpm - The TMPM driver object.
 *
 * Context: Always called when unloading the driver. May be called if TMPM driver
 *          experiences an error during initialization or generates an error
 *          interrupt.
 *
 * See section "PM Device Shutdown" of the Tiered Memory Page Migration spec.
 */
static void shutdown_tmpm_engine(struct tmpm *tmpm)
{
	struct tmpm_device_data *tmpm_match;
	u32 reg;
	int i;

	tmpm_match = (struct tmpm_device_data *)acpi_device_get_match_data(tmpm->dev);
	if (tmpm_match->type == TMPM_DEVICE_SECONDARY)
		return;
	rmp_update_io_ops(NULL);

        /* Pause the ring buffer. */
	if (write_ctl(tmpm, reg  | RBCTL_PAUSE))
		return;

	/*
	 * TMPM Spec. says to wait for the firmware to drain the ring buffer
	 * after setting the pause bit (above), but only if the ring buffer
	 * is not corrupt.
	 */
	if (!(read_mb_reg(tmpm, REG_STATUS) & RB_ERR)) {
		for (i = 0; !is_rb_empty(tmpm) && i < POLL_LOOPS; i++, udelay(POLL_USEC)) {
			if (read_mb_reg(tmpm, REG_STATUS) & RB_ERR) {
				dev_err(tmpm->dev,
					"TMPM: ring buffer has a bad index or is corrupt.\n");
				return;
			}
		}

		if (i == POLL_LOOPS)
			dev_err(tmpm->dev,
				"TMPM: Took longer than %d msecs to drain ring buffer.\n",
				POLL_MSEC);

	} else {
		dev_err(tmpm->dev, "TMPM: ring buffer has a bad index or is corrupt.\n");
	}

	/* Clear the driver initialized bit. */
	reg = read_mb_reg(tmpm, REG_RBCTL);
	reg &= ~RBCTL_INIT;
	if (write_ctl(tmpm, reg))
		return;

	/* Wait for driver_init_complete to be cleared by firmware. */

	for (i = 0; read_mb_reg(tmpm, REG_STATUS) & STATUS_DRIVER_INIT && i < POLL_LOOPS; i++)
		udelay(POLL_USEC);

	if (i == POLL_LOOPS)
		dev_err(tmpm->dev,
			"TMPM: Took longer than %d msecs to confirm init_complete is clear.\n",
			POLL_MSEC);
}

/*
 * Threaded interrupt handler. Called in a thread context. Sleeping OK, may
 * call shutdown_tmpm_engine().
 */
static irqreturn_t tmpm_interrupt_thread(int irq, void *dev)
{
	struct tmpm *tmpm = (struct tmpm *)dev;

	/*
	 * Check for a ring buffer write error, the TMPM will always generate an
	 * interrupt on such errors.
	 */
	if (read_mb_reg(tmpm, REG_STATUS) & RB_ERR) {
		dev_err(tmpm->dev,
			"Error, ring buffer head ptr is out of range or rb is corrupt\n");
		shutdown_tmpm_engine(tmpm);
	}

	return IRQ_HANDLED;
}

static irqreturn_t tmpm_interrupt(int irq, void *dev)
{
	return IRQ_WAKE_THREAD;
}

/*
 * free_rb() - Free the TMPM ring buffer
 *
 * @tmpm - The TMPM driver object.
 */
static void free_rb(struct tmpm *tmpm)
{
	if (cc_platform_has(CC_ATTR_HOST_SEV_SNP))
		snp_reclaim_pages(tmpm->rb_phys, 1, false);
	else
		free_page((unsigned long)tmpm->rb_virt);

	tmpm->rb_phys = 0ULL;
	tmpm->rb_virt = NULL;
}

/*
 * alloc_rb()
 *
 * @pm - The TMPM driver object.
 *
 * @note: The ring buffer must be one or more physically contiguous pages.
 *        The primary TMPM engine is always on node 0, so allocate the
 *        ring buffer also on node 0.
 *

 * @note: If RMP enforcement is enabled, the Ring Buffer must be aligned to a
 * 2M boundary and the RMP entry for the page must show the page in an HV-Fixed
 * state.
 *
 * Include the c-bit mask for SME mode in host kernel (non-guest) physical page
 * addresses. See "SPA (System Physical Address) Encoding" in the TMPM spec.
 *
 * Return: true if successful, false otherwise.
 */
static bool alloc_rb(struct tmpm *tmpm)
{
	struct page *page;
	int ret;

	if (cc_platform_has(CC_ATTR_HOST_SEV_SNP)) {
		struct page *pg;

		page = alloc_pages_node(dev_to_node(tmpm->dev), GFP_KERNEL, ORDER_2MB);
		if (!page)
			return false;

		/* Free pages we don't use for the ring buffer */

		split_page(page, ORDER_2MB);
		for (pg = page + 1; pg < page + PAGES_2MB; pg++)
			free_page((unsigned long)page_address(pg));

		/* If SNP active, ring buffer page must be set to hypervisor-fixed */

		ret = rmp_make_hv_fixed(page_to_pfn(page), 1);
		if (ret == -ENODEV)
			goto no_snp;
		if (ret) {
			dev_err(tmpm->dev, "rmp_make_hv_fixed() returned %d\n", ret);
			free_page((unsigned long)page_address(page));
			return false;
		}
	} else {
no_snp:
		page = alloc_pages_node(dev_to_node(tmpm->dev), GFP_KERNEL, 0);
		if (!page)
			return false;
	}

	tmpm->rb_virt = page_address(page);
	tmpm->rb_phys = __sme_pa(tmpm->rb_virt);

	return true;
}

/*
 * wait_rb_entry() - Poll for a TMPM command to return a status code.
 *
 * @entry - a pointer to a command contained in a ring buffer entry.
 *
 * @note: The command is complete when the ring buffer entry shows a status.
 * The status could be TMPM_SUCCESS or one of the error codes.
 *
 * Return: zero if command has a status, -EIO if it timed out.
 */
static int wait_rb_entry(struct rb_entry *entry)
{
	int i;

	for (i = 0; !read_rbe_status(entry) && i < POLL_LOOPS; i++)
		udelay(POLL_USEC);

	if (i == POLL_LOOPS) {
		struct tmpm *tmpm = platform_get_drvdata(tmpm_platform_dev);

		dev_dbg(tmpm->dev,
			"(%s): took longer than %d msecs to read a status value\n",
			__func__, POLL_MSEC);
		return -EIO;
	}

	return 0;
}

/*
 * submit_rb_entry() - Submit a ring buffer entry to the TMPM
 *                     and wait for completion or error status.
 *
 * @tmpm - The TMPM driver object.
 *
 * @entry - Pointer to formatted ring buffer entry, to be written into the TMPM
 *          ring buffer.
 * @cmd_state - Pointer to a state object to track the completion of the command.
 *
 * Return: zero upon success, -EIO upon timeout (POLL_MSEC) or upon an invalid
 *         ring buffer state.
 *
 * @note: Will not return until the TMPM writes a status to the ring buffer
 * entry, times out waiting, or the ring buffer is full or corrupt.
 */
static int submit_rb_entry(struct tmpm *tmpm, struct rb_entry *entry)
{
	struct rb_entry *rb_addr = tmpm->rb_virt;
	struct rb_entry *rb_slot;
	u16 index, tail;

	guard(spinlock)(&tmpm->lock);

	index = read_head(tmpm);
	if (WARN_ON_ONCE(index > RB_MAX_INDEX)) {
		shutdown_tmpm_engine(tmpm);
		return -EIO;
	}

	rb_slot = &rb_addr[index];

	tail = read_tail(tmpm);
	if (!CIRC_SPACE(index, tail, RB_SIZE)) {
		dev_err(tmpm->dev, "(%s): no space in ring buffer - try again\n", __func__);
		return -EAGAIN;
	}

	index++;
	if (index > RB_MAX_INDEX)
		index = 0;

	memcpy(rb_slot, entry, sizeof(struct rb_entry));

	/*
	 * TMPM engine will update this ring buffer entry after the write to the
	 * head index; insert a write barrier that will pair with read
	 * barrier elsewhere that reads the status of this entry. e.g.,
	 * read_rb_status().
	 */
	wmb();

	/* We just incremented or wrapped the index, write it to the TMPM. */
	write_head(tmpm, index);

	return wait_rb_entry(rb_slot);
}

static int _get_capabilities(struct tmpm *tmpm)
{
	struct page * __free(__free_pages) page;
	struct rb_entry rbe;
	int ret;

	page = alloc_pages(GFP_KERNEL | __GFP_ZERO, 0);
	if (!page) {
		dev_err(tmpm->dev, "TMPM: unable to allocate migration entry page\n");
		return -ENOMEM;
	}

	format_rb_entry(&rbe, __sme_pa(page_address(page)),
			TMPM_GET_CAPABILITIES, 0);

	ret = submit_rb_entry(tmpm, &rbe);

	if (!ret) {
		capabilities = *(struct get_capabilities *)page_address(page);
		return ret;
	}

	dev_err(tmpm->dev, "TMPM: error %d waiting for command completion\n", ret);
	shutdown_tmpm_engine(tmpm);

	return ret;
}

/*
 * get_capabilities() - issue the GET_CAPABILITIES to the TMPM.
 *
 * @tmpm - The TMPM driver object.
 */
static void get_capabilities(struct tmpm *tmpm)
{
	int ret = _get_capabilities(tmpm);

	if (!ret) {
		dev_dbg(tmpm->dev,
			"TMPM fw version: %ld.%ld cap=%x fw=%x spec=%x supp=%x\n",
			(capabilities.fw_reg & GC_FW_MAJOR) >> 24,
			(capabilities.fw_reg & GC_FW_MINOR) >> 16,
			capabilities.cap_reg,
			capabilities.fw_reg,
			capabilities.spec_reg,
			capabilities.support_reg
			);
		dev_dbg(tmpm->dev,
			"Reload FW supported: %s\n",
			capabilities.support_reg & GC_SUP_RELOAD ? "yes" : "no");
		dev_dbg(tmpm->dev,
			"PSMASH_IO supported: %s\n",
			capabilities.support_reg & GC_SUP_PSMASH ? "yes" : "no");
		dev_dbg(tmpm->dev,
			"PUNSMASH_IO supported %s\n",
			capabilities.support_reg & GC_SUP_PUNSMASH ? "yes" : "no");
	}
}

static bool have_capability(u32 mask)
{
	if (!capabilities.fw_reg) {
		struct tmpm *tmpm = platform_get_drvdata(tmpm_platform_dev);

		if (_get_capabilities(tmpm))
			return false;
	}
	return !!(capabilities.support_reg & mask);
}

/* Will be invoked by kvm_amd in place of psmash.
 * Preserve the convention of calling psmash with a host
 * physical address. Lookup and check the guest physical
 * address, which is the real DMA target.
 */

/*
 * host paddrs  should have encryption bit set by __sme_set.
 *
 * assigned (rmp entry) paddrs should have encryption bit
 * set by __tmpm_sev_set_phys
 */

static int __maybe_unused psmash_io(void *snp_context,
				    struct iommu_domain *domain,
				    unsigned long paddr)
{
	struct page * __free(__free_pages) smash_entry, *src_hpte_page;
	struct tmpm *tmpm = platform_get_drvdata(tmpm_platform_dev);
	phys_addr_t src_pte_paddr, gpa = 0ULL;
	struct psmash_io *psio_cmd;
	struct rb_entry rbe;
	int ret;

	if (!have_capability(GC_SUP_PSMASH)) {
		ret =  -ENODEV;
		goto out_trace;
	}

	if (paddr & ~PMD_MASK) {
		dev_err(tmpm->dev,
			"Error submitting non-aligned memory address %#016llx\n",
			(u64)paddr);
		ret = -EINVAL;
		goto out_trace;
	}

	/*
	 * Get the guest physical address from the host physical.
	 * gpa should be identical to the DMA address.
	 * Note: paddr confusingly called "iova" up the stack.
	 */

	gpa = rmp_get_gpa(paddr);

	/* Get the phys_addr_t of the source page iommu PTE */
	unsigned long size = 0;
	u64 *pte_vaddr = iommu_fetch_pte(domain, gpa, &size);

	if (!pte_vaddr) {
		pr_err("___K___ %s %u\n", __func__, __LINE__);
		ret = -EINVAL;
		goto out_trace;
	}

	if (size < SZ_2M) {
		pr_err("___K___ %s %u: gpa=%llx is already not 2M\n", __func__, __LINE__, gpa);
		ret = -EEXIST;
		goto out_trace;
	}

	phys_addr_t pde_paddr = iommu_virt_to_phys(pte_vaddr) & ((u64)~(PAGE_SIZE - 1));
	ret = tmpm_iommu_map(pde_paddr, pde_paddr, PAGE_SIZE,
			     IOMMU_READ | IOMMU_WRITE, GFP_KERNEL);
	if (ret) {
		pr_err("Error mapping IOMMU PDE %llx / %llx, ret=%d\n", (u64) pte_vaddr, pde_paddr, ret);
		goto out_trace;
	}

	src_pte_paddr = iommu_virt_to_phys(pte_vaddr);

	/* The contents of gpa PTE should match paddr. */
	trace_printk("hpa %#016llx gpa %#016llx contents of pte %#016llx\n",
		     (u64)paddr, (u64)gpa, *pte_vaddr);

	/* Get the command entry page */
	smash_entry = alloc_pages_node(0, GFP_KERNEL, 0);
	if (!smash_entry) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	/*
	 * TMPM firmware will fill this page with 512 PTEs to map
	 * the smashed 4k pages.
	 */
	src_hpte_page = alloc_pages_node(0, GFP_KERNEL, 0);
	if (!src_hpte_page) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	/* Preinit new PTEs as the TMPM spec requires */
	u64 *new_ptes = page_to_virt(src_hpte_page);
	for (unsigned i = 0; i < PAGE_SIZE / sizeof(u64); ++i) {
		union {
			u64 p;
			struct {
				u64 a1:12;
				u64 pfn:40;
				u64 a2:12;
			};
		} n = {
			/*
			 * 1 and 0x700 are reasonable values for IOPTE but
			 * this should really come from drivers/iommu/amd/io_pgtable.c
			 * alloc_pte() or something.
			 */
			.a1 = 1,
#define IOMMU_PAGE_MASK (((1ULL << 52) - 1) & ~0xfffULL) // Gone since 2fdf6db436e307
			.pfn = ((*pte_vaddr & IOMMU_PAGE_MASK) >> PAGE_SHIFT) + i,
			.a2 = *pte_vaddr >> 52,
		};
		new_ptes[i] = n.p;
	}

	/* Fill the command entry. */
	psio_cmd = page_address(smash_entry);
	/* Page to be psmashed */
	psio_cmd->src_pg_paddr = __sme_set(paddr);
	/* phys_addr_t of the page that will hold the 512 new IOMMU PTEs. */
	psio_cmd->smash_hpte_paddr = __sme_set(page_to_phys(src_hpte_page));
	/* phys_addr_t of the IOMMU PMD for the page being smashed. */
	psio_cmd->src_hpmd_paddr = __sme_set(src_pte_paddr);
	/* phys_addr_t of the SNP guest context. */
	psio_cmd->gctx_paddr = __sme_pa(snp_context);

	format_rb_entry(&rbe, __sme_set(page_to_phys(smash_entry)),
			TMPM_PSMASH_IO, 0);

	dev_notice(tmpm->dev,
		"TMPM: paddr=%lx gpa=%llx pte=%llx pte_pa=%llx => new=%llx\n",
		paddr, gpa,
		(u64) *pte_vaddr,
		src_pte_paddr,
		psio_cmd->smash_hpte_paddr);

	ret = submit_rb_entry(tmpm, &rbe);
	if (psio_cmd->pte_err || psio_cmd->pte_suberr || psio_cmd->sub_status || psio_cmd->status || ret)
		dev_err(tmpm->dev, "TMPM failed: ret=%d gctx=%llx pteerr=%x suberr=%x subst=%x st=%x\n",
		       ret, psio_cmd->gctx_paddr, psio_cmd->pte_err, psio_cmd->pte_suberr,
		       psio_cmd->sub_status, psio_cmd->status);

	/*
	 * don't free this page - it will be used by the IOMMU driver
	 * to host the 512 4k PTEs.
	 * TODO: have the IOMMU driver allocate the page?
	 */
	/* __free_pages(src_hpte_page, 0); */

out_unmap:
	tmpm_iommu_unmap(pde_paddr, PAGE_SIZE);
out_trace:
	return ret;
}

/*
 * Test the use of the IOMMU identity-mapping domain.
 */
 static bool tmpm_identity_mapping(void)
 {
	 struct page * __free(__free_pages) page;
	 phys_addr_t paddr;
	 dma_addr_t iova;
	 int ret;

	 page = alloc_pages(GFP_KERNEL, 0);
	 paddr = __sme_set(page_to_phys(page));
	 iova = paddr;
	 ret = tmpm_iommu_map(iova, paddr, PAGE_SIZE, IOMMU_READ | IOMMU_WRITE,
			      GFP_KERNEL);
	 if (ret)
		 return false;

	 tmpm_iommu_unmap(iova, PAGE_SIZE);
	 return true;
 }

/*
 * init_tmpm_engine() - Follow the protocol for initializing the TMPM device,
 *                      enumerated in the TMPM spec. "Device Initialization"
 *                      section.
 *
 * @tmpm - The TMPM driver object.
 *
 * Return: Zero upon success, < Zero upon error
 */
static __init int init_tmpm_engine(struct tmpm *tmpm)
{
	struct device *dev = tmpm->dev;
	int i;

	if (!(read_mb_reg(tmpm, REG_STATUS) & STATUS_ENGINE_READY)) {
		dev_err(dev, "TMPM Engine is not ready, exiting.\n");
		return -EIO;
	}

	if (read_mb_reg(tmpm, REG_STATUS) & STATUS_DRIVER_INIT) {
		dev_err(dev,
			"TMPM: Driver init status non-zero, need to re-start the driver.\n");
		shutdown_tmpm_engine(tmpm);
		return -EIO;
	}

	write_mb_reg(tmpm, REG_RBLOW, lower_32_bits(tmpm->rb_phys));
	write_mb_reg(tmpm, REG_RBHIGH, upper_32_bits(tmpm->rb_phys));

	/*
	 * Size of the ring buffer is one page, 256 entries. Leave the
	 * other bits of REG_CDATA clear.
	 */
	write_mb_reg(tmpm, REG_CDATA, 1);
	write_head(tmpm, 0);

	/*
	 * Set the init bit in the ctrl register. Leave the other bits clear.
	 **/
	if (write_ctl(tmpm, BIT(1)))
		return -EIO;

	/* Poll the status register driver init bit. */
	for (i = 0; i < POLL_LOOPS; i++) {
		if (read_mb_reg(tmpm, REG_STATUS) & STATUS_DRIVER_INIT)
			break;
		udelay(POLL_USEC);
	}

	if (i == POLL_LOOPS)
	{
		pr_err("___K___ %s %u: -EIO\n", __func__, __LINE__);
		for (int jj = 0; jj < 8; ++jj)
			read_mb_reg(tmpm, jj * sizeof(u32));
		return -EIO;
	}

	dev_dbg(dev, "(%s): Driver is initialized\n", __func__);

	get_capabilities(tmpm);

	return 0;
}

static __init int tmpm_setup_iommu(struct device *dev)
{
	int ret;

	dma_set_mask_and_coherent(dev, DMA_BIT_MASK(sizeof(u64)));

	ret = tmpm_iommu_enable();
	if (ret) {
		dev_dbg(dev, "(%s): Fail to enable IOMMU\n", __func__);
		return ret;
	}

	if (!tmpm_iommu_get_domain(dev)) {
		dev_dbg(dev, "(%s): Fail to allocate TMPM domain.\n",
			__func__);
		return ret;
	}

	ret = tmpm_iommu_domain_attach_device(dev);
	if (ret) {
		dev_dbg(dev, "(%s): Fail to setup add slave to domain.\n",
			__func__);
		return ret;
	}

	return 0;
}

struct rmp_io_ops tmpm_rmp_ops = {
	.name = "TMPM",
	.rmp_psmash_io = psmash_io,
};

static __init int probe(struct platform_device *pdev)
{
	int ret;
	struct tmpm *tmpm;
	struct device *dev = &pdev->dev;
	struct tmpm_device_data *tmpm_match;

	in_probe = true;

	tmpm_match = (struct tmpm_device_data *)acpi_device_get_match_data(dev);

	if (!tmpm_match) {
		dev_dbg(dev, "(%s): did not find device data\n", __func__);
		return -EINVAL;
	}

	if (tmpm_setup_iommu(dev)) {
		dev_err(dev, "TMPM error setting up IOMMU.\n");
		return -EINVAL;
	}

	if (tmpm_match->type == TMPM_DEVICE_SECONDARY) {
		dev_dbg(dev, "(%s): secondary TMPM device was probed\n",
			__func__);
		return 0;
	}

	dev_dbg(dev, "(%s): primary TMPM device was probed\n", __func__);

	/*
	 * Save a pointer to the platform device - there will only be one device
	 * and one client of the device (this driver).
	 */
	tmpm_platform_dev = pdev;

	/* Allocate the driver's TMPM device structure. */
	tmpm = devm_kzalloc(&pdev->dev, sizeof(*tmpm), GFP_KERNEL);
	if (!tmpm)
		return -ENOMEM;
	tmpm->dev = dev;

	/* Save the TMPM driver object to the platform device's private pointer */
	platform_set_drvdata(tmpm_platform_dev, tmpm);

	tmpm->res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!tmpm->res) {
		dev_err(dev, "TMPM: resources NULL\n");
		ret = -EINVAL;
		goto err_tmpm;
	}

	tmpm->mbox = devm_ioremap(dev,
				  tmpm->res->start,
				  tmpm->res->end - tmpm->res->start + 1);
	if (!tmpm->mbox) {
		dev_err(dev, "TMPM: unable to ioremap device mailbox.\n");
		ret = -EIO;
		goto err_tmpm;
	}
	dev_err(dev, "___K___ %s %u: devm_ioremap(%llx sz=%llx) => %lx\n", __func__, __LINE__,
		tmpm->res->start, tmpm->res->end - tmpm->res->start + 1, (ulong) tmpm->mbox);

	spin_lock_init(&tmpm->lock);

	tmpm->irq = platform_get_irq(pdev, 0);
	if (tmpm->irq < 0) {
		dev_err(dev, "TMPM: unable to get IRQ\n");
		ret = tmpm->irq;
		goto err_tmpm;
	}

	ret = devm_request_threaded_irq(dev, tmpm->irq, tmpm_interrupt,
					tmpm_interrupt_thread, IRQF_TRIGGER_HIGH,
					NULL, tmpm);
	if (ret) {
		dev_err(dev, "TMPM: Error %d requesting irq.\n", ret);
		goto err_tmpm;
	}

	/* Allocate the ring buffer for the TMPM engine. */
	if (!alloc_rb(tmpm)) {
		ret =  -ENOMEM;
		goto err_tmpm;
	}

	ret = init_tmpm_engine(tmpm);

	if (ret)
		goto err_rb;

	/*
	 * Moving pages associated with an SEV guest requires that
	 * the encryption bit be part of the SPA. If SEV is supported,
	 * explicitly retrieve the encryption bit position to be used.
	 * Even though SEV and SME use the same encryption bit, the
	 * explicit retrieval is required because SEV guests can be
	 * created without SME being active, therefore the SME mask
	 * can't be used.
	 */

	if (cpu_feature_enabled(X86_FEATURE_SEV))
		tmpm_sev_mask = 1UL << (cpuid_ebx(0x8000001f) & 0x3f);

	bool mapped = tmpm_identity_mapping();
	dev_err(dev, "TMPM Identity mapping supported: %s\n", mapped ? "Yes." : "No.");

	if (capabilities.support_reg & GC_SUP_PSMASH)
		rmp_update_io_ops(&tmpm_rmp_ops);

	in_probe = false;

	return ret;

err_rb:
	free_rb(tmpm);
err_tmpm:
	cleanup_iommu(&pdev->dev);
	tmpm_iommu_disable();
	platform_set_drvdata(tmpm_platform_dev, NULL);
	devm_kfree(dev, tmpm);

	in_probe = false;

	return ret;
}

static __exit void shutdown(struct platform_device *pdev)
{
	struct tmpm *tmpm = platform_get_drvdata(pdev);
	struct tmpm_device_data *tmpm_match;

	tmpm_match = (struct tmpm_device_data *)acpi_device_get_match_data(&pdev->dev);
	if (tmpm_match->type == TMPM_DEVICE_SECONDARY)
		return;

	/* Shut down the TMPM, don't worry about freeing driver resources. */
	shutdown_tmpm_engine(tmpm);
}

static __exit void remove(struct platform_device *pdev)
{
	struct tmpm *tmpm = platform_get_drvdata(pdev);
	struct tmpm_device_data *tmpm_match;

	tmpm_match = (struct tmpm_device_data *)acpi_device_get_match_data(&pdev->dev);
	if (tmpm_match->type == TMPM_DEVICE_SECONDARY)
		return;

	cleanup_iommu(&pdev->dev);
	tmpm_iommu_disable();

	shutdown_tmpm_engine(tmpm);
	free_rb(tmpm);

	return;
}

static struct tmpm_device_data tmpm_acpi_dev[] = {
	{.type = TMPM_DEVICE_PRIMARY},
	{.type = TMPM_DEVICE_SECONDARY},
	{},
};

static const struct acpi_device_id tmpm_acpi_match[] = {
	{.id = "AMDI0095",  /* TMPM  on Genoa device _HID */
	 .driver_data = (kernel_ulong_t)&tmpm_acpi_dev[0]},
	{.id = "AMDI0096",  /* All secondary TMPM  engines share this device _HID */
	 .driver_data = (kernel_ulong_t)&tmpm_acpi_dev[1]},
	{},
};
MODULE_DEVICE_TABLE(acpi, tmpm_acpi_match);

static struct platform_driver tmpm_driver __refdata = {
	.probe = probe,
	.remove = remove,
	.shutdown = shutdown,
	.driver = {
		.name = "tmpm",
		.acpi_match_table = ACPI_PTR(tmpm_acpi_match),
	},
};

module_platform_driver(tmpm_driver);

MODULE_AUTHOR("Mike Day <michael.day@amd.com>");
MODULE_DESCRIPTION("AMD TMPM Driver");
MODULE_VERSION("0.9");
MODULE_LICENSE("GPL");

