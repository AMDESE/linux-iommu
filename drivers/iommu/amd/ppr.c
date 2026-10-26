// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt)     "AMD-Vi: " fmt
#define dev_fmt(fmt)    pr_fmt(fmt)

#include <linux/amd-iommu.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/mmu_notifier.h>
#include <linux/wait.h>

#include <asm/iommu.h>

#include "amd_iommu.h"
#include "amd_iommu_types.h"

#include "../iommu-pages.h"

int __init amd_iommu_alloc_ppr_log(struct amd_iommu *iommu)
{
	iommu->ppr_log = iommu_alloc_4k_pages(iommu, GFP_KERNEL | __GFP_ZERO,
					      amd_iommu_pprlog_size);
	return iommu->ppr_log ? 0 : -ENOMEM;
}

void amd_iommu_enable_ppr_log(struct amd_iommu *iommu)
{
	u64 entry;

	if (iommu->ppr_log == NULL)
		return;

	iommu_feature_enable(iommu, CONTROL_PPR_EN);

	entry = iommu_virt_to_phys(iommu->ppr_log);
	entry |= (amd_iommu_pprlog_size == PPRLOG_SIZE_DEF) ?
			PPRLOG_LEN_MASK_DEF : PPRLOG_LEN_MASK_MAX;

	memcpy_toio(iommu->mmio_base + MMIO_PPR_LOG_OFFSET,
		    &entry, sizeof(entry));

	/* set head and tail to zero manually */
	writel(0x00, iommu->mmio_base + MMIO_PPR_HEAD_OFFSET);
	writel(0x00, iommu->mmio_base + MMIO_PPR_TAIL_OFFSET);

	iommu_feature_enable(iommu, CONTROL_PPRINT_EN);
	iommu_feature_enable(iommu, CONTROL_PPRLOG_EN);
}

void __init amd_iommu_free_ppr_log(struct amd_iommu *iommu)
{
	iommu_free_pages(iommu->ppr_log);
}

/*
 * This function restarts ppr logging in case the IOMMU experienced
 * PPR log overflow.
 */
void amd_iommu_restart_ppr_log(struct amd_iommu *iommu)
{
	u32 status;

	/*
	 * Overflow stops the log. The IRQ thread has already consumed
	 * the entries that were written. A group whose last page was
	 * dropped is still on the partial list; discard it before the
	 * log restarts and another group reuses the index.
	 */
	status = readl(iommu->mmio_base + MMIO_STATUS_OFFSET);
	if (status & MMIO_STATUS_PPR_RUN_MASK)
		return;

	if (iommu->iopf_queue)
		iopf_queue_discard_partial(iommu->iopf_queue);

	amd_iommu_restart_log(iommu, "PPR", CONTROL_PPRINT_EN,
			      CONTROL_PPRLOG_EN, MMIO_STATUS_PPR_RUN_MASK,
			      MMIO_STATUS_PPR_OVERFLOW_MASK);
}

static inline u32 ppr_flag_to_fault_perm(u16 flag)
{
	int perm = 0;

	if (flag & PPR_FLAG_READ)
		perm |= IOMMU_FAULT_PERM_READ;
	if (flag & PPR_FLAG_WRITE)
		perm |= IOMMU_FAULT_PERM_WRITE;

	/* Execute and privileged mode are carried in the PASID prefix. */
	if (!(flag & PPR_FLAG_GN))
		return perm;

	if (flag & PPR_FLAG_EXEC)
		perm |= IOMMU_FAULT_PERM_EXEC;
	if (!(flag & PPR_FLAG_US))
		perm |= IOMMU_FAULT_PERM_PRIV;

	return perm;
}

static bool ppr_is_valid(struct amd_iommu *iommu, u64 *raw)
{
	struct device *dev = iommu->iommu.dev;
	u16 devid = PPR_DEVID(raw[0]);

	if (PPR_FLAGS(raw[0]) & PPR_FLAG_RVSD) {
		dev_dbg(dev, "PPR logged [Invalid request format (device=%04x:%02x:%02x.%x "
			"pasid=0x%05llx address=0x%llx flags=0x%04llx tag=0x%03llx]\n",
			iommu->pci_seg->id, PCI_BUS_NUM(devid), PCI_SLOT(devid), PCI_FUNC(devid),
			PPR_PASID(raw[0]), raw[1], PPR_FLAGS(raw[0]), PPR_TAG(raw[0]));
		return false;
	}

	return true;
}

static void iommu_call_iopf_notifier(struct amd_iommu *iommu, u64 *raw)
{
	struct iommu_dev_data *dev_data;
	struct iopf_fault event;
	struct pci_dev *pdev;
	u16 devid = PPR_DEVID(raw[0]);

	if (PPR_REQ_TYPE(raw[0]) != PPR_REQ_FAULT) {
		pr_info_ratelimited("Unknown PPR request received\n");
		return;
	}

	/*
	 * PASID Stop Marker: L set, R and W clear (PCIe LRW = 0b100).
	 * No response is expected.
	 */
	if (PPR_TAG_LAST_PAGE(raw[0]) &&
	    !(PPR_FLAGS(raw[0]) & (PPR_FLAG_READ | PPR_FLAG_WRITE)))
		return;

	/*
	 * Probe never attached this device, or it is no longer on the
	 * bus. A kdump kernel can reuse a DTE that still has PPR set.
	 * The log entry carries the DeviceID, so complete the group
	 * here and do not touch dev_data.
	 */
	pdev = pci_get_domain_bus_and_slot(iommu->pci_seg->id,
					   PCI_BUS_NUM(devid), devid & 0xff);
	dev_data = pdev ? dev_iommu_priv_get(&pdev->dev) : NULL;
	if (!dev_data) {
		pr_info_ratelimited("PPR for unprobed device: 0x%x\n", devid);

		if (PPR_TAG_LAST_PAGE(raw[0])) {
			amd_iommu_complete_ppr(iommu, devid, PPR_PASID(raw[0]),
					       IOMMU_PAGE_RESP_FAILURE,
					       PPR_TAG(raw[0]),
					       PPR_FLAGS(raw[0]) & PPR_FLAG_GN);
		}
		pci_dev_put(pdev);
		return;
	}

	if (!ppr_is_valid(iommu, raw))
		goto out;

	memset(&event, 0, sizeof(struct iopf_fault));

	event.fault.type = IOMMU_FAULT_PAGE_REQ;
	event.fault.prm.perm = ppr_flag_to_fault_perm(PPR_FLAGS(raw[0]));
	event.fault.prm.addr = (u64)(raw[1] & PAGE_MASK);
	event.fault.prm.grpid = PPR_TAG(raw[0]);

	/*
	 * GN=0: the request had no PASID prefix and the log's PASID field
	 * is not meaningful. It is reported against the RID domain.
	 */
	if (PPR_FLAGS(raw[0]) & PPR_FLAG_GN) {
		event.fault.prm.pasid = PPR_PASID(raw[0]);

		/* PASID zero is used for requests without a PASID */
		if (event.fault.prm.pasid == 0 ||
		    event.fault.prm.pasid >= dev_data->max_pasids) {
			pr_info_ratelimited("Invalid PASID : 0x%x, device : 0x%x\n",
					    event.fault.prm.pasid, dev_data->devid);
			goto out;
		}

		event.fault.prm.flags |= IOMMU_FAULT_PAGE_RESPONSE_NEEDS_PASID;
		event.fault.prm.flags |= IOMMU_FAULT_PAGE_REQUEST_PASID_VALID;
	} else {
		event.fault.prm.pasid = IOMMU_NO_PASID;
	}
	if (PPR_TAG_LAST_PAGE(raw[0]))
		event.fault.prm.flags |= IOMMU_FAULT_PAGE_REQUEST_LAST_PAGE;

	/* Submit event */
	iommu_report_device_fault(&pdev->dev, &event);
	pci_dev_put(pdev);
	return;

out:
	/*
	 * A page-request group is completed once. Responding to a page
	 * that is not the last one sends another completion for the same
	 * group index, which can complete a newer group that reused it.
	 */
	if (PPR_TAG_LAST_PAGE(raw[0])) {
		amd_iommu_complete_ppr(iommu, devid, PPR_PASID(raw[0]),
				       IOMMU_PAGE_RESP_FAILURE,
				       PPR_TAG(raw[0]),
				       PPR_FLAGS(raw[0]) & PPR_FLAG_GN);
	}
	pci_dev_put(pdev);
}

static void __amd_iommu_poll_ppr_log(struct amd_iommu *iommu)
{
	u32 head, tail;

	lockdep_assert_held(&iommu->ppr_lock);
	atomic_inc(&iommu->ppr_active);

	head = readl(iommu->mmio_base + MMIO_PPR_HEAD_OFFSET);
	tail = readl(iommu->mmio_base + MMIO_PPR_TAIL_OFFSET);

	while (head != tail) {
		volatile u64 *raw;
		u64 entry[2];
		int i;

		raw = (u64 *)(iommu->ppr_log + head);

		/*
		 * Hardware bug: Interrupt may arrive before the entry is
		 * written to memory. If this happens we need to wait for the
		 * entry to arrive.
		 */
		for (i = 0; i < LOOP_TIMEOUT; ++i) {
			if (PPR_REQ_TYPE(raw[0]) != 0)
				break;
			udelay(1);
		}

		/* Avoid memcpy function-call overhead */
		entry[0] = raw[0];
		entry[1] = raw[1];

		/*
		 * To detect the hardware errata 733 we need to clear the
		 * entry back to zero. This issue does not exist on SNP
		 * enabled system. Also this buffer is not writeable on
		 * SNP enabled system.
		 */
		if (!amd_iommu_snp_en)
			raw[0] = raw[1] = 0UL;

		/* Update head pointer of hardware ring-buffer */
		head = (head + PPRLOG_ENTRY_SIZE) % amd_iommu_pprlog_size;
		writel(head, iommu->mmio_base + MMIO_PPR_HEAD_OFFSET);

		/* Handle PPR entry */
		iommu_call_iopf_notifier(iommu, entry);
	}

	/*
	 * Head has moved and every entry copied out of this pass has been
	 * reported. Drop ppr_active before publishing the completed pass:
	 * a waiter observing the new sequence must not sleep on a poll that
	 * has already completed.
	 */
	atomic_dec(&iommu->ppr_active);
	atomic_inc(&iommu->ppr_seq);
	wake_up_all(&iommu->ppr_wait);
}

/*
 * True when the log still holds a request from @devid, or a slot the
 * PPR thread has not consumed yet. A zero type means hardware has not
 * finished the write, so the DeviceID is not known yet.
 */
static bool ppr_log_pending(struct amd_iommu *iommu, u16 devid)
{
	u32 head, tail;

	head = readl(iommu->mmio_base + MMIO_PPR_HEAD_OFFSET);
	tail = readl(iommu->mmio_base + MMIO_PPR_TAIL_OFFSET);

	while (head != tail) {
		u64 val = READ_ONCE(*(u64 *)(iommu->ppr_log + head));

		if (!PPR_REQ_TYPE(val) || PPR_DEVID(val) == devid)
			return true;

		head = (head + PPRLOG_ENTRY_SIZE) % amd_iommu_pprlog_size;
	}

	return false;
}

/*
 * Wait until every log entry for @devid has been consumed and reported.
 * Callers of __amd_iommu_poll_ppr_log() own the head; this does not.
 */
void amd_iommu_wait_ppr_log(struct amd_iommu *iommu, u16 devid)
{
	unsigned long deadline = jiffies + 2 * HZ;

	if (!iommu->ppr_log)
		return;

	for (;;) {
		unsigned int seq = atomic_read(&iommu->ppr_seq);

		/*
		 * The thread advances the head before it reports the fault,
		 * so an empty log is not enough while a poll is still in
		 * iommu_report_device_fault(). Recheck seq so a poll that
		 * starts between the two reads cannot finish unseen.
		 */
		if (!ppr_log_pending(iommu, devid) &&
		    !atomic_read(&iommu->ppr_active) &&
		    atomic_read(&iommu->ppr_seq) == seq &&
		    !atomic_read(&iommu->ppr_active))
			return;

		if (!time_before(jiffies, deadline)) {
			pr_warn_ratelimited("IOMMU%d: timed out draining PPR log for device %04x\n",
					    iommu->index, devid);
			return;
		}

		wait_event_timeout(iommu->ppr_wait,
				   atomic_read(&iommu->ppr_seq) != seq,
				   deadline - jiffies);
	}
}

void amd_iommu_poll_ppr_log(struct amd_iommu *iommu)
{
	mutex_lock(&iommu->ppr_lock);
	__amd_iommu_poll_ppr_log(iommu);
	mutex_unlock(&iommu->ppr_lock);
}

/*
 * Consume PPR requests already logged for this device, then flush the
 * IOPF work they queued. The caller is releasing a PASID attach handle.
 */
void amd_iommu_drain_ppr_log(struct iommu_dev_data *dev_data)
{
	struct amd_iommu *iommu = get_amd_iommu_from_dev_data(dev_data);

	if (!iommu->ppr_log || !dev_data->iopf_refcount)
		return;

	mutex_lock(&iommu->ppr_lock);
	__amd_iommu_poll_ppr_log(iommu);
	mutex_unlock(&iommu->ppr_lock);

	iopf_queue_flush_dev(dev_data->dev);
}

/**************************************************************
 *
 * IOPF handling stuff
 */

/* Setup per-IOMMU IOPF queue if not exist. */
int amd_iommu_iopf_init(struct amd_iommu *iommu)
{
	int ret = 0;

	if (iommu->iopf_queue)
		return ret;

	snprintf(iommu->iopfq_name, sizeof(iommu->iopfq_name), "amdvi-%#x",
		 PCI_SEG_DEVID_TO_SBDF(iommu->pci_seg->id, iommu->devid));

	iommu->iopf_queue = iopf_queue_alloc(iommu->iopfq_name);
	if (!iommu->iopf_queue)
		ret = -ENOMEM;

	return ret;
}

/* Destroy per-IOMMU IOPF queue if no longer needed. */
void amd_iommu_iopf_uninit(struct amd_iommu *iommu)
{
	iopf_queue_free(iommu->iopf_queue);
	iommu->iopf_queue = NULL;
}

void amd_iommu_page_response(struct device *dev, struct iopf_fault *evt,
			     struct iommu_page_response *resp)
{
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);
	bool gn = evt->fault.prm.flags & IOMMU_FAULT_PAGE_REQUEST_PASID_VALID;

	amd_iommu_complete_ppr(get_amd_iommu_from_dev_data(dev_data),
			       dev_data->devid, resp->pasid, resp->code,
			       resp->grpid, gn);
}

int amd_iommu_enable_iopf(struct device *dev)
{
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);
	struct amd_iommu *iommu = get_amd_iommu_from_dev_data(dev_data);
	int ret;

	if (!dev_data->pri_enabled)
		return -ENODEV;

	/* iopf_refcount is protected by the group mutex. */
	iommu_group_mutex_assert(dev);
	if (dev_data->iopf_refcount) {
		dev_data->iopf_refcount++;
		return 0;
	}

	if (!iommu->iopf_queue)
		return -EINVAL;

	ret = iopf_queue_add_device(iommu->iopf_queue, dev);
	if (ret)
		return ret;

	dev_data->iopf_refcount = 1;
	return 0;
}

void amd_iommu_disable_iopf(struct device *dev)
{
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);
	struct amd_iommu *iommu = get_amd_iommu_from_dev_data(dev_data);

	/*
	 * PRI may already have been disabled by RID detach. The reference
	 * still owns the IOPF queue entry until the last fault-capable
	 * domain is gone.
	 */
	if (WARN_ON(!dev_data->iopf_refcount))
		return;

	iommu_group_mutex_assert(dev);
	if (--dev_data->iopf_refcount)
		return;

	iopf_queue_remove_device(iommu->iopf_queue, dev);
}

static int iopf_for_domain_set(struct iommu_domain *domain, struct device *dev)
{
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);

	if (!domain || !domain->iopf_handler)
		return 0;

	/*
	 * A device without PRI may handle SVA faults itself. Any other
	 * handler-owning domain needs the IOMMU page-request path.
	 */
	if (domain->type == IOMMU_DOMAIN_SVA &&
	    !(dev_data->flags & AMD_IOMMU_DEVICE_FLAG_PRI_SUP))
		return 0;

	return amd_iommu_enable_iopf(dev);
}

static void iopf_for_domain_remove(struct iommu_domain *domain,
				   struct device *dev)
{
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);

	if (!domain || !domain->iopf_handler)
		return;

	if (domain->type == IOMMU_DOMAIN_SVA &&
	    !(dev_data->flags & AMD_IOMMU_DEVICE_FLAG_PRI_SUP))
		return;

	amd_iommu_disable_iopf(dev);
}

int amd_iommu_iopf_for_domain_replace(struct iommu_domain *new,
				      struct iommu_domain *old,
				      struct device *dev)
{
	int ret;

	ret = iopf_for_domain_set(new, dev);
	if (ret)
		return ret;

	iopf_for_domain_remove(old, dev);
	return 0;
}
