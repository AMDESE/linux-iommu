// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt)     "AMD-Vi: " fmt
#define dev_fmt(fmt)    pr_fmt(fmt)

#include <linux/irq.h>
#include <linux/msi.h>
#include <linux/cpumask.h>
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

	if (!check_feature2(FEATURE_GAPPIDISSUP))
		return;

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
	return -EOPNOTSUPP;
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
	if (ret < 0)
		return ret;

	for (i = virq; i < virq + nr_irqs; i++) {
		struct irq_data *irqd = irq_domain_get_irq_data(domain, i);

		irqd->chip = &gappi_controller;
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
