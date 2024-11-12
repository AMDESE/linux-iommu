// SPDX-License-Identifier: GPL-2.0
/*
 * AMD IOMMU driver
 *
 * Copyright (C) 2018 Advanced Micro Devices, Inc.
 *
 * Author: Gary R Hook <gary.hook@amd.com>
 */

#include <linux/debugfs.h>
#include <linux/pci.h>

#include "amd_iommu.h"
#include "../irq_remapping.h"

static struct dentry *amd_iommu_debugfs;

#define	MAX_NAME_LEN	20
#define	OFS_IN_SZ	8
#define	DEVID_IN_SZ	16
#define	IOVA_IN_SZ	70

static int mmio_offset = -1;
static int cap_offset = -1;
static int sbdf = -1;
static bool iova_valid = false;
static u64 iova;

static ssize_t iommu_mmio_write(struct file *filp, const char __user *ubuf,
				size_t cnt, loff_t *ppos)
{
	struct seq_file *m = filp->private_data;
	struct amd_iommu *iommu = m->private;
	int ret;

	if (cnt > OFS_IN_SZ)
		return -EINVAL;

	ret = kstrtou32_from_user(ubuf, cnt, 0, &mmio_offset);
	if (ret)
		return ret;

	if (mmio_offset > iommu->mmio_phys_end - 4) {
		mmio_offset = -1;
		return  -EINVAL;
	}

	return cnt;
}

static int iommu_mmio_show(struct seq_file *m, void *unused)
{
	if (mmio_offset >= 0)
		seq_printf(m, "0x%x\n", mmio_offset);
	else
		seq_puts(m, "No or invalid input provided\n");

	return 0;
}
DEFINE_SHOW_STORE_ATTRIBUTE(iommu_mmio);

static int iommu_mmio_dump_show(struct seq_file *m, void *unused)
{
	struct amd_iommu *iommu = m->private;
	u32 value;

	if (mmio_offset < 0) {
		seq_puts(m, "Please provide mmio register's offset\n");
		return 0;
	}

	value = readl(iommu->mmio_base + mmio_offset);
	seq_printf(m, "0x%08x\n", value);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(iommu_mmio_dump);

static ssize_t iommu_capability_write(struct file *filp, const char __user *ubuf,
				      size_t cnt, loff_t *ppos)
{
	int ret;

	if (cnt > OFS_IN_SZ)
		return -EINVAL;

	ret = kstrtou32_from_user(ubuf, cnt, 0, &cap_offset);
	if (ret)
		return ret;

	/* Capability register at offset 0x14 is the last IOMMU capability register. */
	if (cap_offset > 0x14) {
		cap_offset = -1;
		return -EINVAL;
	}

	return cnt;
}

static int iommu_capability_show(struct seq_file *m, void *unused)
{
	if (cap_offset >= 0)
		seq_printf(m, "0x%x\n", cap_offset);
	else
		seq_puts(m, "No or invalid input provided\n");

	return 0;
}
DEFINE_SHOW_STORE_ATTRIBUTE(iommu_capability);

static int iommu_capability_dump_show(struct seq_file *m, void *unused)
{
	struct amd_iommu *iommu = m->private;
	u32 value;
	int err;

	if (cap_offset < 0) {
		seq_puts(m, "Please provide capability register's offset\n");
		return 0;
	}

	err = pci_read_config_dword(iommu->dev, iommu->cap_ptr + cap_offset, &value);
	if (err) {
		seq_printf(m, "Not able to read capability register at 0x%x\n", cap_offset);
		return 0;
	}

	seq_printf(m, "0x%08x\n", value);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(iommu_capability_dump);

static int iommu_cmdbuf_show(struct seq_file *m, void *unused)
{
	struct amd_iommu *iommu = m->private;
	struct iommu_cmd *cmd;
	unsigned long flag;
	u32 head, tail;
	int i;

	raw_spin_lock_irqsave(&iommu->lock, flag);
	head = readl(iommu->mmio_base + MMIO_CMD_HEAD_OFFSET);
	tail = readl(iommu->mmio_base + MMIO_CMD_TAIL_OFFSET);
	seq_printf(m, "CMD Buffer Head Offset:%d Tail Offset:%d\n",
		   (head >> 4) & 0x7fff, (tail >> 4) & 0x7fff);
	for (i = 0; i < CMD_BUFFER_ENTRIES; i++) {
		cmd = (struct iommu_cmd *)(iommu->cmd_buf + i * sizeof(*cmd));
		seq_printf(m, "%3d: %08x%08x%08x%08x\n", i, cmd->data[0],
			   cmd->data[1], cmd->data[2], cmd->data[3]);
	}
	raw_spin_unlock_irqrestore(&iommu->lock, flag);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(iommu_cmdbuf);

static ssize_t devid_write(struct file *filp, const char __user *ubuf,
			   size_t cnt, loff_t *ppos)
{
	struct amd_iommu_pci_seg *pci_seg;
	int seg, bus, slot, func;
	struct amd_iommu *iommu;
	char *srcid_ptr;
	u16 devid;
	int i;

	sbdf = -1;

	if (cnt >= DEVID_IN_SZ)
		return -EINVAL;

	srcid_ptr = memdup_user_nul(ubuf, cnt);
	if (IS_ERR(srcid_ptr))
		return PTR_ERR(srcid_ptr);

	i = sscanf(srcid_ptr, "%x:%x:%x.%x", &seg, &bus, &slot, &func);
	if (i != 4) {
		i = sscanf(srcid_ptr, "%x:%x.%x", &bus, &slot, &func);
		if (i != 3) {
			kfree(srcid_ptr);
			return -EINVAL;
		}
		seg = 0;
	}

	devid = PCI_DEVID(bus, PCI_DEVFN(slot, func));

	/* Check if user device id input is a valid input */
	for_each_pci_segment(pci_seg) {
		if (pci_seg->id != seg)
			continue;
		if (devid > pci_seg->last_bdf) {
			kfree(srcid_ptr);
			return -EINVAL;
		}
		iommu = pci_seg->rlookup_table[devid];
		if (!iommu) {
			kfree(srcid_ptr);
			return -ENODEV;
		}
		break;
	}

	if (pci_seg->id != seg) {
		kfree(srcid_ptr);
		return -EINVAL;
	}

	sbdf = PCI_SEG_DEVID_TO_SBDF(seg, devid);

	kfree(srcid_ptr);

	return cnt;
}

static int devid_show(struct seq_file *m, void *unused)
{
	u16 devid;

	if (sbdf >= 0) {
		devid = PCI_SBDF_TO_DEVID(sbdf);
		seq_printf(m, "%04x:%02x:%02x:%x\n", PCI_SBDF_TO_SEGID(sbdf),
			   PCI_BUS_NUM(devid), PCI_SLOT(devid), PCI_FUNC(devid));
	} else
		seq_puts(m, "No or Invalid input provided\n");

	return 0;
}
DEFINE_SHOW_STORE_ATTRIBUTE(devid);

static void dump_dte(struct seq_file *m, struct amd_iommu_pci_seg *pci_seg, u16 devid)
{
	struct dev_table_entry *dev_table;
	struct amd_iommu *iommu;

	iommu = pci_seg->rlookup_table[devid];
	if (!iommu)
		return;

	dev_table = get_dev_table(iommu);
	if (!dev_table) {
		seq_puts(m, "Device table not found");
		return;
	}

	seq_printf(m, "%-12s %16s %16s %16s %16s iommu\n", "DeviceId",
		   "QWORD[3]", "QWORD[2]", "QWORD[1]", "QWORD[0]");
	seq_printf(m, "%04x:%02x:%02x:%x ", pci_seg->id, PCI_BUS_NUM(devid),
		   PCI_SLOT(devid), PCI_FUNC(devid));
	for (int i = 3; i >= 0; --i)
		seq_printf(m, "%016llx ", dev_table[devid].data[i]);
	seq_printf(m, "iommu%d\n", iommu->index);
}

static int iommu_devtbl_show(struct seq_file *m, void *unused)
{
	struct amd_iommu_pci_seg *pci_seg;
	u16 seg, devid;

	if (sbdf < 0) {
		seq_puts(m, "Please provide valid device id input\n");
		return 0;
	}
	seg = PCI_SBDF_TO_SEGID(sbdf);
	devid = PCI_SBDF_TO_DEVID(sbdf);

	for_each_pci_segment(pci_seg) {
		if (pci_seg->id != seg)
			continue;
		dump_dte(m, pci_seg, devid);
		break;
	}

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(iommu_devtbl);

static void dump_128_irte(struct seq_file *m, struct irq_remap_table *table)
{
	struct irte_ga *ptr, *irte;
	int index;

	for (index = 0; index < MAX_IRQS_PER_TABLE; index++) {
		ptr = (struct irte_ga *)table->table;
		irte = &ptr[index];

		if (AMD_IOMMU_GUEST_IR_VAPIC(amd_iommu_guest_ir) &&
		    !irte->lo.fields_vapic.valid)
			continue;
		else if (!irte->lo.fields_remap.valid)
			continue;
		seq_printf(m, "IRT[%04d] %016llx%016llx\n", index, irte->hi.val, irte->lo.val);
	}
}

static void dump_32_irte(struct seq_file *m, struct irq_remap_table *table)
{
	union irte *ptr, *irte;
	int index;

	for (index = 0; index < MAX_IRQS_PER_TABLE; index++) {
		ptr = (union irte *)table->table;
		irte = &ptr[index];

		if (!irte->fields.valid)
			continue;
		seq_printf(m, "IRT[%04d] %08x\n", index, irte->val);
	}
}

static void dump_irte(struct seq_file *m, u16 devid, struct amd_iommu_pci_seg *pci_seg)
{
	struct irq_remap_table *table;
	unsigned long flags;

	table = pci_seg->irq_lookup_table[devid];
	if (!table) {
		seq_printf(m, "IRQ lookup table not set for %04x:%02x:%02x:%x\n",
			   pci_seg->id, PCI_BUS_NUM(devid), PCI_SLOT(devid), PCI_FUNC(devid));
		return;
	}

	seq_printf(m, "DeviceId %04x:%02x:%02x:%x\n", pci_seg->id, PCI_BUS_NUM(devid),
		   PCI_SLOT(devid), PCI_FUNC(devid));

	raw_spin_lock_irqsave(&table->lock, flags);
	if (AMD_IOMMU_GUEST_IR_GA(amd_iommu_guest_ir))
		dump_128_irte(m, table);
	else
		dump_32_irte(m, table);
	seq_puts(m, "\n");
	raw_spin_unlock_irqrestore(&table->lock, flags);
}

static int iommu_irqtbl_show(struct seq_file *m, void *unused)
{
	struct amd_iommu_pci_seg *pci_seg;
	u16 devid, seg;

	if (!irq_remapping_enabled) {
		seq_puts(m, "Interrupt remapping is disabled\n");
		return 0;
	}

	if (sbdf < 0) {
		seq_puts(m, "Please provide valid device id input\n");
		return 0;
	}

	seg = PCI_SBDF_TO_SEGID(sbdf);
	devid = PCI_SBDF_TO_DEVID(sbdf);

	for_each_pci_segment(pci_seg) {
		if (pci_seg->id != seg)
			continue;
		dump_irte(m, devid, pci_seg);
		break;
	}

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(iommu_irqtbl);

static ssize_t iova_write(struct file *filp, const char __user *ubuf,
			   size_t cnt, loff_t *ppos)
{
	int ret;

	if (cnt >= IOVA_IN_SZ)
		return -EINVAL;

	iova_valid = false;

	ret = kstrtou64_from_user(ubuf, cnt, 0, &iova);
	if (ret)
		return ret;

	iova_valid = true;

	return cnt;
}

static int iova_show(struct seq_file *m, void *unused)
{
	if(iova_valid)
		seq_printf(m, "0x%llx", iova);
	else
		seq_puts(m, "No or Invalid input provided\n");

	return 0;
}
DEFINE_SHOW_STORE_ATTRIBUTE(iova);

static inline void dump_pgtable_walk_v1(struct seq_file *m, u64 *path, int *index,
					int *printed, int mode, unsigned long page_size,
					unsigned long cnt, int last_level)
{
	int indent, i, j;

	for (i = mode - 1; i >= last_level ; i--) {
		if (printed[i])
			continue;
		printed[i] = 1;
		indent = mode - i - 1;
		for (j = indent ; j > 0 ; j--)
			seq_puts(m, "\t");
		switch (i) {
		case 0:
			seq_puts(m, "PTE");
			break;
		default:
			seq_puts(m, "PDE");
		}
		seq_printf(m, "[L:%d]%03d:0x%016llx", i + 1, index[i], path[i]);
		seq_printf(m, " PR=%llx", path[i] & IOMMU_PTE_PR);
		seq_printf(m, " A=%llx", (path[i] & IOMMU_PTE_A) >> 5);
		seq_printf(m, " IR=%llx", (path[i] & IOMMU_PTE_IR) >> 61);
		seq_printf(m, " IW=%llx", (path[i] & IOMMU_PTE_IW) >> 62);
		seq_printf(m, " NL=%llx", (path[i] & IOMMU_V1_PTE_NL) >> 9);
		seq_printf(m, " N_ADDR=%010llx", (path[i] & IOMMU_PAGE_MASK) >> 12);
		if (i == last_level) {
			seq_printf(m, " D=%llx", (path[i] & IOMMU_PTE_HD) >> 6);
			seq_printf(m, " U=%llx", (path[i] & IOMMU_PTE_U) >> 59);
			seq_printf(m, " FC=%llx", (path[i] & IOMMU_PTE_FC) >> 60);
			seq_printf(m, " Pg=%ld & ptes = %ld", page_size, cnt);
		}
		seq_puts(m, "\n");
	}
}

static void pgtable_walk_v1(struct seq_file *m, u64 *pde, int mode, int level,
			    u64 *path, int *index, int *printed)
{
	int i, start = 0, end = BIT_ULL((9));
	unsigned long pte_mask, cnt;
	unsigned long page_size;
	u64 *pte;

	if (iova_valid) {
		if (iova >= (1ULL << (mode * 9 + 12)))
			return;
		start = PM_LEVEL_INDEX(level, iova);
		end = start + 1;
	}

	for (i = start; i < end; i++) {
		pte  = &pde[i];

		if (!IOMMU_PTE_PRESENT(*pte))
			continue;
		if (PM_PTE_LEVEL(*pte) == PAGE_MODE_7_LEVEL) {
			page_size = PTE_PAGE_SIZE(*pte);
			cnt      = PAGE_SIZE_PTE_COUNT(page_size);
			pte_mask = ~((cnt << 3) - 1);
			pte     = (u64 *)(((unsigned long)pte) & pte_mask);
			index[level] = i;
			path[level] = *pte;
			printed[level] = 0;
			dump_pgtable_walk_v1(m, path, index, printed, mode, page_size,
					     cnt, level);
		} else if (PM_PTE_LEVEL(*pte) == PAGE_MODE_NONE) {
			index[level] = i;
			path[level] = *pte;
			printed[level] = 0;
			page_size = PTE_LEVEL_PAGE_SIZE(level);
			dump_pgtable_walk_v1(m, path, index, printed, mode, page_size,
					     1, level);
		} else {
			index[level] = i;
			path[level] = *pte;
			printed[level] = 0;
			pte        = IOMMU_PTE_PAGE(*pte);
			pgtable_walk_v1(m, pte, mode, level-1, path, index, printed);
		}
	}
}

static int iommu_pgtbl_show(struct seq_file *m, void *unused)
{
	struct amd_iommu_pci_seg *pci_seg;
	struct dev_table_entry *dev_table;
	struct amd_iommu *iommu;
	int printed[6] = { 1 };
	int index[6] = { 0 };
	u64 path[6] = { 0 };
	u16 seg, devid;
	u64 *root;
	int mode;

	if (amd_iommu_pgtable == AMD_IOMMU_V2) {
		seq_puts(m, "System is not booted in Iommu v1 page table mode\n");
		return 0;
	}

	if (sbdf < 0) {
		seq_puts(m, "Please provide valid device id input\n");
		return 0;
	}
	seg = PCI_SBDF_TO_SEGID(sbdf);
	devid = PCI_SBDF_TO_DEVID(sbdf);

	for_each_pci_segment(pci_seg) {
		if (pci_seg->id != seg)
			continue;
		break;
	}

	iommu = pci_seg->rlookup_table[devid];
	if (!iommu)
		return 0;

	dev_table = get_dev_table(iommu);
	if (!dev_table) {
		seq_puts(m, "Device table not found\n");
		return 0;
	}

	root = iommu_phys_to_virt((dev_table[devid].data[0]) & (((1ULL << 52) - 1) & ~0xfffULL));
	mode = (dev_table[devid].data[0] >> 9) & (BIT_ULL((3)) - 1);
	if(mode == 0) {
		seq_puts(m, "Translation disabled\n");
		return 0;
	}

	pgtable_walk_v1(m, root, mode, mode - 1, path, index, printed);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(iommu_pgtbl);

void amd_iommu_debugfs_setup(void)
{
	struct amd_iommu *iommu;
	char name[MAX_NAME_LEN + 1];

	amd_iommu_debugfs = debugfs_create_dir("amd", iommu_debugfs_dir);

	for_each_iommu(iommu) {
		snprintf(name, MAX_NAME_LEN, "iommu%02d", iommu->index);
		iommu->debugfs = debugfs_create_dir(name, amd_iommu_debugfs);

		debugfs_create_file("mmio", 0644, iommu->debugfs, iommu,
				    &iommu_mmio_fops);
		debugfs_create_file("mmio_dump", 0444, iommu->debugfs, iommu,
				    &iommu_mmio_dump_fops);
		debugfs_create_file("capability", 0644, iommu->debugfs, iommu,
				    &iommu_capability_fops);
		debugfs_create_file("capability_dump", 0444, iommu->debugfs,
				    iommu, &iommu_capability_dump_fops);
		debugfs_create_file("cmdbuf", 0444, iommu->debugfs, iommu,
				    &iommu_cmdbuf_fops);
	}
	debugfs_create_file("devid", 0644, amd_iommu_debugfs, NULL,
			    &devid_fops);
	debugfs_create_file("devtbl", 0444, amd_iommu_debugfs, NULL,
			    &iommu_devtbl_fops);
	debugfs_create_file("irqtbl", 0444, amd_iommu_debugfs, NULL,
			    &iommu_irqtbl_fops);
	debugfs_create_file("iova", 0644, amd_iommu_debugfs, NULL,
			    &iova_fops);
	debugfs_create_file("pgtbl", 0444, amd_iommu_debugfs, NULL,
			    &iommu_pgtbl_fops);
}
