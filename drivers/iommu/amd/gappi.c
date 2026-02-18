// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt)     "AMD-Vi: " fmt
#define dev_fmt(fmt)    pr_fmt(fmt)

#include <linux/irq.h>
#include <linux/msi.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/irqdomain.h>
#include <linux/hashtable.h>
#include <linux/amd-iommu.h>
#include <asm/apic.h>
#include <asm/hw_irq.h>

#include "amd_iommu.h"
#include "amd_iommu_types.h"

unsigned char gappi_name[32] = "GAPPI";
struct irq_domain *gappi_irqdomain;
struct fwnode_handle *gappi_fn;

static void set_gappidis(struct amd_ir_data *host_ir_data, bool set)
{
	struct irq_2_irte *irte_info = &host_ir_data->irq_2_irte;
	struct irte_ga *entry = (struct irte_ga *)host_ir_data->entry;

	host_ir_data->gappi.masked = set;

	/* If IRTE is not in guest mode, defer until guest mode is activated */
	if (!entry->lo.fields_vapic.guest_mode)
		return;

	pr_debug("%s: %s: devid=%#x, index=%u\n", __func__,
		 set ? "set" : "clear", irte_info->devid, irte_info->index);

	entry->lo.fields_vapic.gappi_dis = set ? 1 : 0;
	modify_irte_ga(host_ir_data->iommu, irte_info->devid, irte_info->index, entry);
}

static void gappi_unmask_irq(struct irq_data *irqd)
{
	struct amd_ir_data *host_ir_data = irqd->chip_data;

	set_gappidis(host_ir_data, false);
}

static void gappi_mask_irq(struct irq_data *irqd)
{
	struct amd_ir_data *host_ir_data = irqd->chip_data;

	set_gappidis(host_ir_data, true);
}

static int gappi_set_affinity(struct irq_data *irqd,
			      const struct cpumask *mask, bool force)
{
	int ret = -EINVAL;
        /* See the gappi_irqdomain_alloc() */
	struct amd_ir_data *ir_data = irqd->chip_data;

	if (WARN_ON(!ir_data->gappi.cfg))
		return ret;

	return amd_ir_set_gappi_affinity(irqd, mask, force);
}

static int gappi_set_wake(struct irq_data *irqd, unsigned int on)
{
	return on ? -EOPNOTSUPP : 0;
}

static struct irq_chip gappi_controller = {
	.name			= "GAPPI-MSI",
	.irq_unmask		= gappi_unmask_irq,
	.irq_mask		= gappi_mask_irq,
	.irq_ack		= irq_chip_ack_parent,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
	.irq_set_affinity       = gappi_set_affinity,
	.irq_set_wake		= gappi_set_wake,
	.flags			= IRQCHIP_MASK_ON_SUSPEND,
};

static int gappi_irqdomain_alloc(struct irq_domain *domain, unsigned int virq,
				 unsigned int nr_irqs, void *arg)
{
	struct irq_alloc_info *irq_info = arg;
	int i, ret;

	if (!irq_info || irq_info->type != X86_IRQ_ALLOC_TYPE_AMDVI)
		return -EINVAL;

	ret = irq_domain_alloc_irqs_parent(domain, virq, nr_irqs, irq_info);
	if (ret < 0) {
		pr_err("%s: Failing to allocate irq from parent. ret=%d", __func__, ret);
		return ret;
	}

	for (i = virq; i < virq + nr_irqs; i++) {
		struct irq_data *irqd = irq_domain_get_irq_data(domain, i);

		irqd->chip = &gappi_controller;

                /*
                 * Note:
                 * The irq_info is initialized in amd_ir_setup_posted_interrupt(),
                 * which is called from avic_pi_init().
                 */
		irqd->hwirq = irq_info->hwirq;
		irqd->chip_data = irq_info->data;
		__irq_set_handler(i, handle_edge_irq, 0, "edge");
	}

	return ret;
}

static void gappi_irqdomain_free(struct irq_domain *domain, unsigned int virq,
				 unsigned int nr_irqs)
{
	irq_domain_free_irqs_top(domain, virq, nr_irqs);
}

static int gappi_irqdomain_activate(struct irq_domain *domain,
				    struct irq_data *irqd, bool reserve)
{
	return 0;
}

static void gappi_irqdomain_deactivate(struct irq_domain *domain,
				       struct irq_data *irqd)
{
}

static const struct irq_domain_ops gappi_domain_ops = {
	.alloc			= gappi_irqdomain_alloc,
	.free			= gappi_irqdomain_free,
	.activate		= gappi_irqdomain_activate,
	.deactivate		= gappi_irqdomain_deactivate,
};

int gappi_init_irqdomain(void)
{
	/* No need for locking here (yet) as the init is single-threaded */
	if (gappi_irqdomain)
		return 0;

	gappi_fn = irq_domain_alloc_named_fwnode(gappi_name);
	if (!gappi_fn)
		return -EINVAL;

	gappi_irqdomain = irq_domain_create_hierarchy(x86_vector_domain, 0, 0,
						      gappi_fn, &gappi_domain_ops,
						      NULL);
	if (!gappi_irqdomain) {
		irq_domain_free_fwnode(gappi_fn);
		return -EINVAL;
	}

	return 0;
}

int (*iommu_gappi_notifier)(void *);

int amd_iommu_register_gappi_notifier(int (*notifier)(void *))
{
	iommu_gappi_notifier = notifier;

	/*
	 * Ensure all in-flight IRQ handlers run to completion before returning
	 * to the caller, e.g. to ensure module code isn't unloaded while it's
	 * being executed in the IRQ handler.
	 */
	if (!notifier)
		synchronize_rcu();

	return 0;
}
EXPORT_SYMBOL(amd_iommu_register_gappi_notifier);

static irqreturn_t gappi_handler(int irq, void *data)
{
	int ret;
	struct amd_ir_data *host_ir_data = (struct amd_ir_data *)data;
	struct amd_iommu *iommu = host_ir_data->iommu;

	if (!iommu_gappi_notifier)
		return IRQ_HANDLED;

	pr_debug("%s: iommu=%#x, irq=%d, devid=%#x\n",
		 __func__, iommu->devid, irq, host_ir_data->irq_2_irte.devid);

	ret = iommu_gappi_notifier(host_ir_data->vcpu);
	if (ret)
		pr_err("GAPPI: fail to wake up vcpu (%#x)\n", host_ir_data->ga_tag);

	return IRQ_HANDLED;
}

int gappi_setup_irq(struct amd_iommu_pi_data *pi_data)
{
	int irq, ret;
	struct irq_data *irqd;
	struct irq_alloc_info *irq_info;
	struct amd_ir_data *host_ir_data = pi_data->ir_data;
	struct gappi_info *gappi = &host_ir_data->gappi;

	if (!gappi_irqdomain || !pi_data->is_guest_mode)
		return 0;

	if (gappi->irq >= 0)
		return 0;

	irq_info = &gappi->irq_info;
	irq = irq_domain_alloc_irqs(gappi_irqdomain, 1, NUMA_NO_NODE, irq_info);
	if (irq < 0) {
		pr_err("%s: Failed to allocate irq=%d\n", __func__, irq);
		return irq;
	}

	irqd = irq_domain_get_irq_data(gappi_irqdomain, irq);
	ret = irq_domain_activate_irq(irqd, 0);

	if (ret) {
		irq_domain_free_irqs(irq, 1);
		return ret;
	}

	gappi->irq = irq;
	gappi->cfg = irq_cfg(gappi->irq);
        gappi->apicid = -1;
	snprintf(gappi->irq_name, sizeof(gappi->irq_name),
		 "GAPPI-%#x-%u", host_ir_data->irq_2_irte.devid, irq);

	pr_debug("%s: irq=%d, gappi_cfg.apicid=%#x\n", __func__,
		gappi->irq, gappi->cfg->dest_apicid);

	return request_irq(gappi->irq, gappi_handler, IRQD_NO_BALANCING, gappi->irq_name,
			   host_ir_data);
}
EXPORT_SYMBOL(gappi_setup_irq);

void gappi_destroy_irq(struct amd_iommu_pi_data *pi_data)
{
	struct amd_ir_data *host_ir_data = pi_data->ir_data;
	struct gappi_info *gappi = &host_ir_data->gappi;
	struct irq_data *irqd;

	if (!gappi_irqdomain)
		return;

	if (!gappi || gappi->irq < 0)
		return;

	pr_debug("%s: irq=%d, gappi_cfg.apicid=%#x\n", __func__,
		gappi->irq, gappi->cfg->dest_apicid);

	/* Drain any in-flight handler */
	synchronize_irq(gappi->irq);

	irq_set_affinity_and_hint(gappi->irq, NULL);

	/* Remove handler */
	free_irq(gappi->irq, host_ir_data);

	/* Deactivate domain programming */
	irqd = irq_domain_get_irq_data(gappi_irqdomain, gappi->irq);
	irq_domain_deactivate_irq(irqd);

	/* Free domain mapping + descriptor */
	irq_domain_free_irqs(gappi->irq, 1);

	gappi->irq = -1;
	gappi->cfg = NULL;
}
EXPORT_SYMBOL(gappi_destroy_irq);
