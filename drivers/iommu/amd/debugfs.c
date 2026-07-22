// SPDX-License-Identifier: GPL-2.0
/*
 * AMD IOMMU driver
 *
 * Copyright (C) 2018 Advanced Micro Devices, Inc.
 *
 * Author: Gary R Hook <gary.hook@amd.com>
 */

#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/pci.h>

#include "amd_iommu.h"
#include "amd_viommu.h"
#include "../irq_remapping.h"

static struct dentry *amd_iommu_debugfs;

#define	MAX_NAME_LEN	20
#define	OFS_IN_SZ	8
#define	DEVID_IN_SZ	32
#define	GUEST_EVENT_IN_SZ	128
#define	RESET_VMMIO_IN_SZ	16

static int sbdf = -1;

static ssize_t iommu_mmio_write(struct file *filp, const char __user *ubuf,
				size_t cnt, loff_t *ppos)
{
	struct seq_file *m = filp->private_data;
	struct amd_iommu *iommu = m->private;
	int ret, dbg_mmio_offset = iommu->dbg_mmio_offset = -1;

	if (cnt > OFS_IN_SZ)
		return -EINVAL;

	ret = kstrtos32_from_user(ubuf, cnt, 0, &dbg_mmio_offset);
	if (ret)
		return ret;

	if (dbg_mmio_offset < 0 || dbg_mmio_offset >
			iommu->mmio_phys_end - sizeof(u64))
		return -EINVAL;

	iommu->dbg_mmio_offset = dbg_mmio_offset;
	return cnt;
}

static int iommu_mmio_show(struct seq_file *m, void *unused)
{
	struct amd_iommu *iommu = m->private;
	u64 value;
	int dbg_mmio_offset = iommu->dbg_mmio_offset;

	if (dbg_mmio_offset < 0 || dbg_mmio_offset >
			iommu->mmio_phys_end - sizeof(u64)) {
		seq_puts(m, "Please provide mmio register's offset\n");
		return 0;
	}

	value = readq(iommu->mmio_base + dbg_mmio_offset);
	seq_printf(m, "Offset:0x%x Value:0x%016llx\n", dbg_mmio_offset, value);

	return 0;
}
DEFINE_SHOW_STORE_ATTRIBUTE(iommu_mmio);

static ssize_t iommu_capability_write(struct file *filp, const char __user *ubuf,
				      size_t cnt, loff_t *ppos)
{
	struct seq_file *m = filp->private_data;
	struct amd_iommu *iommu = m->private;
	int ret, dbg_cap_offset = iommu->dbg_cap_offset = -1;

	if (cnt > OFS_IN_SZ)
		return -EINVAL;

	ret = kstrtos32_from_user(ubuf, cnt, 0, &dbg_cap_offset);
	if (ret)
		return ret;

	/* Capability register at offset 0x14 is the last IOMMU capability register. */
	if (dbg_cap_offset < 0 || dbg_cap_offset > 0x14)
		return -EINVAL;

	iommu->dbg_cap_offset = dbg_cap_offset;
	return cnt;
}

static int iommu_capability_show(struct seq_file *m, void *unused)
{
	struct amd_iommu *iommu = m->private;
	u32 value;
	int err, dbg_cap_offset = iommu->dbg_cap_offset;

	if (dbg_cap_offset < 0 || dbg_cap_offset > 0x14) {
		seq_puts(m, "Please provide capability register's offset in the range [0x00 - 0x14]\n");
		return 0;
	}

	err = pci_read_config_dword(iommu->dev, iommu->cap_ptr + dbg_cap_offset, &value);
	if (err) {
		seq_printf(m, "Not able to read capability register at 0x%x\n",
			   dbg_cap_offset);
		return 0;
	}

	seq_printf(m, "Offset:0x%x Value:0x%08x\n", dbg_cap_offset, value);

	return 0;
}
DEFINE_SHOW_STORE_ATTRIBUTE(iommu_capability);

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
		seq_printf(m, "%3d: %08x %08x %08x %08x\n", i, cmd->data[0],
			   cmd->data[1], cmd->data[2], cmd->data[3]);
	}
	raw_spin_unlock_irqrestore(&iommu->lock, flag);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(iommu_cmdbuf);

/*
 * Write any value to restart a halted command buffer. cmdbuf stays
 * read-only and still dumps the buffer.
 */
static ssize_t cmdbuf_reset_write(struct file *filp, const char __user *ubuf,
				  size_t cnt, loff_t *ppos)
{
	int ret;
	u32 input;
	struct seq_file *m = filp->private_data;
	struct amd_iommu *iommu = m->private;

	if (cnt > OFS_IN_SZ)
		return -EINVAL;

	ret = kstrtou32_from_user(ubuf, cnt, 0, &input);
	if (ret)
		return ret;

	amd_iommu_reset_cmd_buffer(iommu);
	return cnt;
}

static int cmdbuf_reset_show(struct seq_file *m, void *unused)
{
	return 0;
}
DEFINE_SHOW_STORE_ATTRIBUTE(cmdbuf_reset);

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
		sbdf = PCI_SEG_DEVID_TO_SBDF(seg, devid);
		kfree(srcid_ptr);
		return cnt;
	}

	kfree(srcid_ptr);
	return -EINVAL;
}

static int devid_show(struct seq_file *m, void *unused)
{
	u16 devid;
	int sbdf_shadow = sbdf;

	if (sbdf_shadow >= 0) {
		devid = PCI_SBDF_TO_DEVID(sbdf_shadow);
		seq_printf(m, "%04x:%02x:%02x.%x\n", PCI_SBDF_TO_SEGID(sbdf_shadow),
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
	seq_printf(m, "%04x:%02x:%02x.%x ", pci_seg->id, PCI_BUS_NUM(devid),
		   PCI_SLOT(devid), PCI_FUNC(devid));
	for (int i = 3; i >= 0; --i)
		seq_printf(m, "%016llx ", dev_table[devid].data[i]);
	seq_printf(m, "iommu%d\n", iommu->index);
}

static int iommu_devtbl_show(struct seq_file *m, void *unused)
{
	struct amd_iommu_pci_seg *pci_seg;
	u16 seg, devid;
	int sbdf_shadow = sbdf;

	if (sbdf_shadow < 0) {
		seq_puts(m, "Enter a valid device ID to 'devid' file\n");
		return 0;
	}
	seg = PCI_SBDF_TO_SEGID(sbdf_shadow);
	devid = PCI_SBDF_TO_DEVID(sbdf_shadow);

	for_each_pci_segment(pci_seg) {
		if (pci_seg->id != seg)
			continue;
		dump_dte(m, pci_seg, devid);
		break;
	}

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(iommu_devtbl);

static void dump_128_irte(struct seq_file *m, struct irq_remap_table *table, u16 int_tab_len)
{
	struct irte_ga *ptr, *irte;
	int index;

	for (index = 0; index < int_tab_len; index++) {
		ptr = (struct irte_ga *)table->table;
		irte = &ptr[index];

		if (AMD_IOMMU_GUEST_IR_VAPIC(amd_iommu_guest_ir) &&
		    !irte->lo.fields_vapic.valid)
			continue;
		else if (!irte->lo.fields_remap.valid)
			continue;
		seq_printf(m, "IRT[%04d] %016llx %016llx\n", index, irte->hi.val, irte->lo.val);
	}
}

static void dump_32_irte(struct seq_file *m, struct irq_remap_table *table, u16 int_tab_len)
{
	union irte *ptr, *irte;
	int index;

	for (index = 0; index < int_tab_len; index++) {
		ptr = (union irte *)table->table;
		irte = &ptr[index];

		if (!irte->fields.valid)
			continue;
		seq_printf(m, "IRT[%04d] %08x\n", index, irte->val);
	}
}

static void dump_irte(struct seq_file *m, u16 devid, struct amd_iommu_pci_seg *pci_seg)
{
	struct dev_table_entry *dev_table;
	struct irq_remap_table *table;
	struct amd_iommu *iommu;
	unsigned long flags;
	u16 int_tab_len;

	table = pci_seg->irq_lookup_table[devid];
	if (!table) {
		seq_printf(m, "IRQ lookup table not set for %04x:%02x:%02x:%x\n",
			   pci_seg->id, PCI_BUS_NUM(devid), PCI_SLOT(devid), PCI_FUNC(devid));
		return;
	}

	iommu = pci_seg->rlookup_table[devid];
	if (!iommu)
		return;

	dev_table = get_dev_table(iommu);
	if (!dev_table) {
		seq_puts(m, "Device table not found");
		return;
	}

	int_tab_len = dev_table[devid].data[2] & DTE_INTTABLEN_MASK;
	if (int_tab_len != DTE_INTTABLEN_512 && int_tab_len != DTE_INTTABLEN_2K) {
		seq_puts(m, "The device's DTE contains an invalid IRT length value.");
		return;
	}

	seq_printf(m, "DeviceId %04x:%02x:%02x.%x\n", pci_seg->id, PCI_BUS_NUM(devid),
		   PCI_SLOT(devid), PCI_FUNC(devid));

	raw_spin_lock_irqsave(&table->lock, flags);
	if (AMD_IOMMU_GUEST_IR_GA(amd_iommu_guest_ir))
		dump_128_irte(m, table, BIT(int_tab_len >> 1));
	else
		dump_32_irte(m, table, BIT(int_tab_len >> 1));
	seq_puts(m, "\n");
	raw_spin_unlock_irqrestore(&table->lock, flags);
}

static int iommu_irqtbl_show(struct seq_file *m, void *unused)
{
	struct amd_iommu_pci_seg *pci_seg;
	u16 devid, seg;
	int sbdf_shadow = sbdf;

	if (!irq_remapping_enabled) {
		seq_puts(m, "Interrupt remapping is disabled\n");
		return 0;
	}

	if (sbdf_shadow < 0) {
		seq_puts(m, "Enter a valid device ID to 'devid' file\n");
		return 0;
	}

	seg = PCI_SBDF_TO_SEGID(sbdf_shadow);
	devid = PCI_SBDF_TO_DEVID(sbdf_shadow);

	for_each_pci_segment(pci_seg) {
		if (pci_seg->id != seg)
			continue;
		dump_irte(m, devid, pci_seg);
		break;
	}

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(iommu_irqtbl);

#if IS_ENABLED(CONFIG_AMD_IOMMU_IOMMUFD)

/*
 * Parse seg:B:D.F, B:D.F, or a raw devid hex value.  Returns the PCI segment
 * and devid if the segment exists and the devid is within IVRS range.
 */
static int trans_devid_debugfs_parse_input(const char __user *ubuf, size_t cnt,
					   struct amd_iommu_pci_seg **pci_seg_out,
					   u16 *devid_out, bool *aliases_out)
{
	struct amd_iommu_pci_seg *pci_seg = NULL;
	char *srcid_ptr, *aliases_suffix;
	int seg = 0, bus, slot, func, i, ret;
	u16 devid;

	*aliases_out = false;

	if (cnt >= DEVID_IN_SZ)
		return -EINVAL;

	srcid_ptr = memdup_user_nul(ubuf, cnt);
	if (IS_ERR(srcid_ptr))
		return PTR_ERR(srcid_ptr);

	aliases_suffix = strstrip(srcid_ptr);
	if (strlen(aliases_suffix) > 8 &&
	    !strcmp(aliases_suffix + strlen(aliases_suffix) - 8, " aliases")) {
		aliases_suffix[strlen(aliases_suffix) - 8] = '\0';
		*aliases_out = true;
	}

	i = sscanf(aliases_suffix, "%x:%x:%x.%x", &seg, &bus, &slot, &func);
	if (i == 4) {
		devid = PCI_DEVID(bus, PCI_DEVFN(slot, func));
	} else {
		i = sscanf(aliases_suffix, "%x:%x.%x", &bus, &slot, &func);
		if (i == 3) {
			seg = 0;
			devid = PCI_DEVID(bus, PCI_DEVFN(slot, func));
		} else {
			seg = 0;
			ret = kstrtou16(aliases_suffix, 0, &devid);
			if (ret) {
				kfree(srcid_ptr);
				return -EINVAL;
			}
		}
	}

	for_each_pci_segment(pci_seg) {
		if (pci_seg->id != seg)
			continue;
		if (devid > pci_seg->last_bdf) {
			kfree(srcid_ptr);
			return -EINVAL;
		}
		*pci_seg_out = pci_seg;
		*devid_out = devid;
		kfree(srcid_ptr);
		return 0;
	}

	kfree(srcid_ptr);
	return -EINVAL;
}

static int trans_devid_pool_show(struct seq_file *m, void *unused)
{
	amd_iommu_trans_devid_debugfs_show_pool(m);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(trans_devid_pool);

static int trans_devid_viommus_show(struct seq_file *m, void *unused)
{
	amd_iommu_trans_devid_debugfs_show_viommus(m);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(trans_devid_viommus);

static ssize_t trans_devid_reserve_write(struct file *filp, const char __user *ubuf,
					 size_t cnt, loff_t *ppos)
{
	struct amd_iommu_pci_seg *pci_seg;
	struct amd_iommu *iommu;
	struct pci_dev *pdev;
	u16 devid;
	bool aliases;
	int ret;

	ret = trans_devid_debugfs_parse_input(ubuf, cnt, &pci_seg, &devid, &aliases);
	if (ret)
		return ret;

	if (!aliases) {
		ret = amd_iommu_trans_devid_debugfs_reserve(pci_seg, devid);
		if (ret)
			return ret;

		pr_info("AMD-Vi: debugfs reserved translate-device-id %#x (seg %#x)\n",
			devid, pci_seg->id);
		return cnt;
	}

	iommu = pci_seg->rlookup_table[devid];
	if (!iommu)
		return -ENODEV;

	pdev = pci_get_domain_bus_and_slot(pci_seg->id, PCI_BUS_NUM(devid),
					   PCI_DEVFN(PCI_SLOT(devid), PCI_FUNC(devid)));
	if (!pdev)
		return -ENODEV;

	ret = amd_iommu_trans_devid_debugfs_reserve_pci_aliases(iommu, &pdev->dev);
	pci_dev_put(pdev);
	if (ret)
		return ret;

	pr_info("AMD-Vi: debugfs reserved translate-device-id aliases for %#x (seg %#x)\n",
		devid, pci_seg->id);
	return cnt;
}

static const struct file_operations trans_devid_reserve_fops = {
	.write = trans_devid_reserve_write,
	.llseek = noop_llseek,
};

static void amd_iommu_trans_devid_debugfs_setup(struct dentry *parent)
{
	struct dentry *dir;

	dir = debugfs_create_dir("trans_devid", parent);
	debugfs_create_file("pool", 0444, dir, NULL, &trans_devid_pool_fops);
	debugfs_create_file("reserve", 0200, dir, NULL, &trans_devid_reserve_fops);
	debugfs_create_file("viommus", 0444, dir, NULL, &trans_devid_viommus_fops);
}

#endif /* CONFIG_AMD_IOMMU_IOMMUFD */

/*
 * INSERT GUEST EVENT
 *
 * Insert an IO_PAGE_FAULT event into the event log of guest <gid>.
 * The event payload is 16 bytes:
 *
 *	word0[15:0]	device id
 *	word0[19:16]	domain id, high nibble
 *	word1[15:0]	domain id, low half
 *	word1[27:16]	flags
 *	word1[31:28]	event code (EVENT_TYPE_IO_FAULT)
 *	word2/word3	faulting address
 *
 * Two input formats are accepted. The positional one covers the common case:
 *
 *	<gid>[:<address>[:<devid>]]
 *
 * and the keyword one reaches every field:
 *
 *	gid=<n> [addr=<a>] [devid=<d>] [domid=<d>] [flags=<f>] [cmd0=<v>]
 *	        [cmd1=<v>] [cmd2=<v>] [cmd3=<v>]
 *
 * Hardware does not validate the payload: it is queued as its own
 * command-buffer entry and copied into the guest log verbatim, so devid,
 * domid, address and flags are round-trip checks rather than fault triggers.
 *
 * <flags> defaults to EVENT_FLAG_I so the event reads as an interrupt request.
 * Clearing that bit makes the consumer treat it as a memory transaction and
 * hand it to report_iommu_fault(), which may swallow the log line entirely.
 *
 * cmd0..cmd3 are the reserved fields of the INSERT_GUEST_EVENT command
 * itself, which hardware does validate. cmd1 is masked to bits 27:16, the
 * reserved part of the word that also carries the gid and the opcode.
 * A well-formed command goes through amd_iommu_insert_guest_event().
 *
 * guest_event_fault takes the same input and calls the same helper with
 * fault set. That fills cmd[0] of INSERT_GUEST_EVENT with 0xdeadbeef, so
 * hardware logs GUEST_EVENT_FAULT instead of inserting the event.
 *
 * Unlike ILLEGAL_COMMAND_ERROR, nothing dereferences <address> on the way out,
 * so it is safe to use as a sequence number even against a guest's log.
 */
/* data[1]: gid [15:0], reserved [27:16], opcode [31:28] */
#define CMD_INSERT_GUEST_EVENT_RESV1_MASK	GENMASK(27, 16)
struct guest_event_input {
	u16 gid;
	u64 address;
	u32 devid;
	u32 domid;
	u32 flags;
	u32 cmd_resv[4];
};

static int guest_event_parse_positional(char *p, struct guest_event_input *in)
{
	char *tok;
	int ret;

	tok = strsep(&p, ":");
	ret = kstrtou16(tok, 0, &in->gid);
	if (ret)
		return ret;

	tok = strsep(&p, ":");
	if (tok && *tok) {
		ret = kstrtou64(tok, 0, &in->address);
		if (ret)
			return ret;
	}

	tok = strsep(&p, ":");
	if (tok && *tok) {
		ret = kstrtou32(tok, 0, &in->devid);
		if (ret)
			return ret;
	}

	return 0;
}

static int guest_event_parse_keywords(char *p, struct guest_event_input *in)
{
	bool have_gid = false;
	char *tok;

	while ((tok = strsep(&p, " \t,")) != NULL) {
		char *val;
		int ret;

		if (!*tok)
			continue;

		val = strchr(tok, '=');
		if (!val)
			return -EINVAL;
		*val++ = '\0';

		if (!strcmp(tok, "gid")) {
			ret = kstrtou16(val, 0, &in->gid);
			have_gid = true;
		} else if (!strcmp(tok, "addr")) {
			ret = kstrtou64(val, 0, &in->address);
		} else if (!strcmp(tok, "devid")) {
			ret = kstrtou32(val, 0, &in->devid);
		} else if (!strcmp(tok, "domid")) {
			ret = kstrtou32(val, 0, &in->domid);
		} else if (!strcmp(tok, "flags")) {
			ret = kstrtou32(val, 0, &in->flags);
		} else if (!strcmp(tok, "cmd0")) {
			ret = kstrtou32(val, 0, &in->cmd_resv[0]);
		} else if (!strcmp(tok, "cmd1")) {
			ret = kstrtou32(val, 0, &in->cmd_resv[1]);
		} else if (!strcmp(tok, "cmd2")) {
			ret = kstrtou32(val, 0, &in->cmd_resv[2]);
		} else if (!strcmp(tok, "cmd3")) {
			ret = kstrtou32(val, 0, &in->cmd_resv[3]);
		} else {
			return -EINVAL;
		}

		if (ret)
			return ret;
	}

	return have_gid ? 0 : -EINVAL;
}

static void guest_event_inject(struct amd_iommu *iommu,
			       const struct guest_event_input *in, bool fault)
{
	u32 event[4];
	u32 resv1 = in->cmd_resv[1] & CMD_INSERT_GUEST_EVENT_RESV1_MASK;
	u32 cmd0 = fault ? 0xdeadbeef : in->cmd_resv[0];
	struct iommu_cmd cmd;

	event[0] = ((in->devid << EVENT_DEVID_SHIFT) & EVENT_DEVID_MASK) |
		   (in->domid & EVENT_DOMID_MASK_HI);
	event[1] = (in->domid & EVENT_DOMID_MASK_LO) |
		   ((in->flags & EVENT_FLAGS_MASK) << EVENT_FLAGS_SHIFT) |
		   (EVENT_TYPE_IO_FAULT << EVENT_TYPE_SHIFT);
	event[2] = lower_32_bits(in->address);
	event[3] = upper_32_bits(in->address);

	if (!cmd0 && !resv1 && !in->cmd_resv[2] && !in->cmd_resv[3]) {
		amd_iommu_insert_guest_event(iommu, in->gid, event);
		return;
	}

	cmd.data[0] = cmd0;
	cmd.data[1] = in->gid | resv1 | (CMD_INSERT_GUEST_EVENT << 28);
	cmd.data[2] = in->cmd_resv[2];
	cmd.data[3] = in->cmd_resv[3];

	pr_debug("%s: gid=%#x, cmd:%#08x_%#08x_%#08x_%#08x, event:%#08x_%#08x_%#08x_%#08x\n",
		 __func__, in->gid, cmd.data[0], cmd.data[1], cmd.data[2],
		 cmd.data[3], event[0], event[1], event[2], event[3]);

	amd_iommu_queue_cmd_pair(iommu, &cmd, (struct iommu_cmd *)event);
}

static ssize_t guest_event_write_common(struct file *filp,
					const char __user *ubuf, size_t cnt,
					bool fault)
{
	struct guest_event_input in = { .flags = EVENT_FLAG_I };
	struct seq_file *m = filp->private_data;
	struct amd_iommu *iommu = m->private;
	char buf[GUEST_EVENT_IN_SZ], *p;
	int ret;

	if (cnt >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(buf, ubuf, cnt))
		return -EFAULT;
	buf[cnt] = '\0';
	p = strim(buf);

	ret = strchr(p, '=') ? guest_event_parse_keywords(p, &in)
			     : guest_event_parse_positional(p, &in);
	if (ret)
		return ret;

	guest_event_inject(iommu, &in, fault);
	return cnt;
}

static ssize_t guest_event_write(struct file *filp, const char __user *ubuf,
				 size_t cnt, loff_t *ppos)
{
	return guest_event_write_common(filp, ubuf, cnt, false);
}

static int guest_event_show(struct seq_file *m, void *unused)
{
	return 0;
}
DEFINE_SHOW_STORE_ATTRIBUTE(guest_event);

static ssize_t guest_event_fault_write(struct file *filp,
				       const char __user *ubuf, size_t cnt,
				       loff_t *ppos)
{
	return guest_event_write_common(filp, ubuf, cnt, true);
}

static int guest_event_fault_show(struct seq_file *m, void *unused)
{
	return 0;
}
DEFINE_SHOW_STORE_ATTRIBUTE(guest_event_fault);

/*
 * RESET VMMIO
 *
 * Write "<gid>" to issue a RESET_VMMIO command for that guest. It resets the
 * guest's MMIO registers, including the event log status word, so it clears a
 * latched EventOverflow and lets a stopped guest event log run again.
 *
 * This is the only way to recover an overflowed guest event log short of
 * tearing the vIOMMU down: neither amd_viommu_hw_queue_destroy() nor
 * amd_viommu_set_hw_queue() touches the guest status register, so a queue
 * re-allocation leaves EventOverflow latched and EventLogRun clear. The same
 * command already runs once per vIOMMU from amd_iommufd_viommu_alloc(), which
 * is why a fresh IOMMU_VIOMMU_ALLOC recovers and a fresh queue does not.
 */
static ssize_t reset_vmmio_write(struct file *filp, const char __user *ubuf,
				 size_t cnt, loff_t *ppos)
{
	struct seq_file *m = filp->private_data;
	struct amd_iommu *iommu = m->private;
	char buf[RESET_VMMIO_IN_SZ];
	u16 gid;
	int ret;

	if (cnt >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(buf, ubuf, cnt))
		return -EFAULT;
	buf[cnt] = '\0';

	ret = kstrtou16(strim(buf), 0, &gid);
	if (ret)
		return ret;

	ret = amd_iommu_reset_vmmio(iommu, gid);
	if (ret)
		return ret;

	return cnt;
}

static int reset_vmmio_show(struct seq_file *m, void *unused)
{
	return 0;
}
DEFINE_SHOW_STORE_ATTRIBUTE(reset_vmmio);

void amd_iommu_debugfs_setup(void)
{
	struct amd_iommu *iommu;
	char name[MAX_NAME_LEN + 1];

	amd_iommu_debugfs = debugfs_create_dir("amd", iommu_debugfs_dir);

	for_each_iommu(iommu) {
		iommu->dbg_mmio_offset = -1;
		iommu->dbg_cap_offset = -1;

		snprintf(name, MAX_NAME_LEN, "iommu%02d", iommu->index);
		iommu->debugfs = debugfs_create_dir(name, amd_iommu_debugfs);

		debugfs_create_file("mmio", 0644, iommu->debugfs, iommu,
				    &iommu_mmio_fops);
		debugfs_create_file("capability", 0644, iommu->debugfs, iommu,
				    &iommu_capability_fops);
		debugfs_create_file("cmdbuf", 0444, iommu->debugfs, iommu,
				    &iommu_cmdbuf_fops);
		debugfs_create_file("cmdbuf_reset", 0644, iommu->debugfs, iommu,
				    &cmdbuf_reset_fops);
		debugfs_create_file("guest_event", 0644, iommu->debugfs, iommu,
				    &guest_event_fops);
		debugfs_create_file("guest_event_fault", 0644, iommu->debugfs,
				    iommu, &guest_event_fault_fops);
		debugfs_create_file("reset_vmmio", 0644, iommu->debugfs, iommu,
				    &reset_vmmio_fops);
	}

	debugfs_create_file("devid", 0644, amd_iommu_debugfs, NULL,
			    &devid_fops);
	debugfs_create_file("devtbl", 0444, amd_iommu_debugfs, NULL,
			    &iommu_devtbl_fops);
	debugfs_create_file("irqtbl", 0444, amd_iommu_debugfs, NULL,
			    &iommu_irqtbl_fops);

#if IS_ENABLED(CONFIG_AMD_IOMMU_IOMMUFD)
	amd_iommu_trans_devid_debugfs_setup(amd_iommu_debugfs);
#endif
}
