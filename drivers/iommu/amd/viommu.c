// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt)     "AMD-Vi: " fmt
#define dev_fmt(fmt)    pr_fmt(fmt)

#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/iommu.h>
#include <linux/iommufd.h>
#include <linux/amd-iommu.h>
#include <uapi/linux/iommufd.h>

#include <asm/iommu.h>
#include <asm/set_memory.h>

#include "iommufd.h"
#include "amd_iommu.h"
#include "amd_iommu_types.h"
#include "amd_viommu.h"
#include "../iommu-pages.h"

static LIST_HEAD(ext_ir_attached_viommus);
static DEFINE_SPINLOCK(ext_ir_attached_lock);

void amd_viommu_attach_ext_ir_kvm(struct amd_iommu_viommu *aviommu,
				  struct kvm *kvm)
{
	unsigned long flags;

	spin_lock_irqsave(&ext_ir_attached_lock, flags);
	if (!aviommu->ext_ir_kvm) {
		aviommu->ext_ir_kvm = kvm;
		list_add(&aviommu->kvm_ext_ir_node, &ext_ir_attached_viommus);
	}
	spin_unlock_irqrestore(&ext_ir_attached_lock, flags);
}

static void amd_viommu_detach_ext_ir_kvm(struct amd_iommu_viommu *aviommu)
{
	unsigned long flags;

	spin_lock_irqsave(&ext_ir_attached_lock, flags);
	if (aviommu->ext_ir_kvm) {
		list_del_init(&aviommu->kvm_ext_ir_node);
		aviommu->ext_ir_kvm = NULL;
	}
	spin_unlock_irqrestore(&ext_ir_attached_lock, flags);
}

/*
 * Per-vIOMMU DevID / DomID tables share iommu->viommu_pdom:
 *   IOVA = base + gid * entry_size, gid in [1, VIOMMU_MAX_GID].
 * The 64GB gap between these bases is 0x10000 1MB DevID slots.
 * VIOMMU_MAX_GID is 0x7FFF, so a max-gid DevID window ends at
 * 0x1800000000 and cannot meet VIOMMU_DOMID_MAPPING_BASE.
 *
 * VIOMMU_MAX_GDEVID / VIOMMU_MAX_GDOMID are 16-bit guest DevID
 * and DomID table indices (hardware mapping-table width), not GID.
 */
#define VIOMMU_DEVID_MAPPING_BASE	0x1000000000ULL
#define VIOMMU_DEVID_MAPPING_ENTRY_SIZE	(1 << 20)

#define VIOMMU_MAX_GDOMID		0xFFFF
#define VIOMMU_DOMID_MAPPING_BASE	0x2000000000ULL
#define VIOMMU_DOMID_MAPPING_ENTRY_SIZE	(1 << 19)

static_assert(VIOMMU_DEVID_MAPPING_BASE +
	      (VIOMMU_MAX_GID + 1ULL) * VIOMMU_DEVID_MAPPING_ENTRY_SIZE <=
	      VIOMMU_DOMID_MAPPING_BASE);
static_assert(VIOMMU_DEVID_MAPPING_ENTRY_SIZE >=
	      (VIOMMU_MAX_GDEVID + 1ULL) * sizeof(u64));
static_assert(VIOMMU_DOMID_MAPPING_ENTRY_SIZE >=
	      (VIOMMU_MAX_GDOMID + 1ULL) * sizeof(u64));

#define VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL0_OFFSET	0x00
#define VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL1_OFFSET	0x08

#define EXT_INT_REMAP_TBL_L1_SIZE (PAGE_SIZE * 2)

static void __init amd_viommu_vf_vfcntl_unmap(struct amd_iommu *iommu)
{
	if (iommu->vfctrl_base) {
		iounmap(iommu->vfctrl_base);
		iommu->vfctrl_base = NULL;
	}
	if (iommu->vf_cntl_phys) {
		release_mem_region(iommu->vf_cntl_phys, VIOMMU_VF_CNTL_MMIO_MAP_SIZE);
		iommu->vf_cntl_phys = 0;
	}

	if (iommu->vf_base) {
		iounmap(iommu->vf_base);
		iommu->vf_base = NULL;
	}
	if (iommu->vf_base_phys) {
		release_mem_region(iommu->vf_base_phys, VIOMMU_VF_MMIO_MAP_SIZE);
		iommu->vf_base_phys = 0;
	}
}


static void viommu_free_self_dev_data(struct amd_iommu *iommu)
{
	struct iommu_dev_data *dev_data = iommu->viommu_dev_data;
	struct dev_table_entry new = {};

	if (!dev_data)
		return;

	amd_iommu_make_clear_dte(iommu, dev_data->devid, &new);
	amd_iommu_update_dte(iommu, dev_data, &new);
	amd_iommu_free_dev_data(iommu, dev_data);
	iommu->viommu_dev_data = NULL;
}

static int viommu_alloc_self_dev_data(struct amd_iommu *iommu)
{
	struct protection_domain *pdom = iommu->viommu_pdom;
	struct pt_iommu_amdv1_hw_info pt_info;
	struct iommu_dev_data *dev_data;
	struct dev_table_entry new = {};

	dev_data = amd_iommu_alloc_dev_data(iommu->devid);
	if (!dev_data) {
		pr_err("%s: Failed to allocate dev_data\n", __func__);
		return -ENOMEM;
	}
	/*
	 * Synthetic DTE for iommu->devid only: no struct device, so
	 * amd_iommu_update_dte() skips clone_aliases(), and not on
	 * pdom->dev_list (not an IOMMU-API attach).
	 */
	dev_data->dev = NULL;
	dev_data->domain = pdom;
	iommu->viommu_dev_data = dev_data;

	amd_iommu_make_clear_dte(iommu, iommu->devid, &new);
	pt_iommu_amdv1_hw_info(&pdom->amdv1, &pt_info);
	amd_iommu_set_dte_v1(dev_data, pdom, pdom->id, &pt_info, &new);
	amd_iommu_update_dte(iommu, dev_data, &new);
	return 0;
}

static void viommu_private_space_uninit(struct amd_iommu *iommu);
static void free_ext_int_remap_tbl(struct amd_iommu *iommu);

void __init amd_viommu_uninit(struct amd_iommu *iommu)
{
	iommu->flags &= ~AMD_IOMMU_FLAG_VIOMMU_EN;
	viommu_free_self_dev_data(iommu);
	free_ext_int_remap_tbl(iommu);
	viommu_private_space_uninit(iommu);
	amd_viommu_vf_vfcntl_unmap(iommu);
}

static int __init viommu_vf_vfcntl_init(struct amd_iommu *iommu)
{
	u32 lo, hi;
	u16 vsc;
	u64 vf_phys, vf_cntl_phys;

	vsc = pci_find_capability(iommu->dev, PCI_CAP_ID_VNDR);
	if (!vsc)
		return -ENODEV;

	pr_debug("device:%s, vsc offset:%04x\n",
		 pci_name(iommu->dev), vsc);

	/* Setting up VF and VF_CNTL MMIOs */
	pci_read_config_dword(iommu->dev, vsc + MMIO_VSC_VF_BAR_LO_OFFSET, &lo);
	pci_read_config_dword(iommu->dev, vsc + MMIO_VSC_VF_BAR_HI_OFFSET, &hi);
	vf_phys = hi;
	vf_phys = (vf_phys << 32) | lo;
	if (!(vf_phys & 1)) {
		pr_err(FW_BUG "vf_phys disabled\n");
		return -EINVAL;
	}
	vf_phys &= ~1ULL;
	if (!vf_phys) {
		pr_err(FW_BUG "vf_phys address is zero\n");
		return -EINVAL;
	}

	pci_read_config_dword(iommu->dev, vsc + MMIO_VSC_VF_CNTL_BAR_LO_OFFSET, &lo);
	pci_read_config_dword(iommu->dev, vsc + MMIO_VSC_VF_CNTL_BAR_HI_OFFSET, &hi);
	vf_cntl_phys = hi;
	vf_cntl_phys = (vf_cntl_phys << 32) | lo;
	if (!(vf_cntl_phys & 1)) {
		pr_err(FW_BUG "vf_cntl_phys disabled\n");
		return -EINVAL;
	}
	vf_cntl_phys &= ~1ULL;
	if (!vf_cntl_phys) {
		pr_err(FW_BUG "vf_cntl_phys address is zero\n");
		return -EINVAL;
	}

	/* Mapping 256MB of VF and 4MB of VF_CNTL BARs */
	iommu->vf_base = iommu_map_mmio_space(vf_phys, VIOMMU_VF_MMIO_MAP_SIZE);
	if (!iommu->vf_base) {
		pr_err("Can't reserve vf_base\n");
		goto err_out;
	}
	iommu->vf_base_phys = vf_phys;

	iommu->vfctrl_base = iommu_map_mmio_space(vf_cntl_phys, VIOMMU_VF_CNTL_MMIO_MAP_SIZE);
	if (!iommu->vfctrl_base) {
		pr_err("Can't reserve vfctrl_base\n");
		goto err_out;
	}
	iommu->vf_cntl_phys = vf_cntl_phys;

	pr_debug("%s: IOMMU device:%s, vf_base:%#llx, vfctrl_base:%#llx\n",
		 __func__, pci_name(iommu->dev), vf_phys, vf_cntl_phys);
	return 0;
err_out:
	amd_viommu_vf_vfcntl_unmap(iommu);
	return -ENOMEM;
}

/*
 * Restore WB and free @va. If WB restore fails, leak the pages so
 * UC-MINUS direct-map PTEs and the PAT memtype reservation are not
 * returned to the buddy allocator.
 */
static void viommu_priv_wb_free(void *va, size_t size)
{
	if (WARN_ON_ONCE(set_memory_wb((unsigned long)va,
				       size >> PAGE_SHIFT)))
		return;
	iommu_free_pages(va);
}

/*
 * Allocate backing pages, mark UC, and map at @iova in viommu_pdom.
 * *@out_va is NULL on any failure. @gfp is used for the backing
 * folio and iommu_map() page tables.
 */
static int viommu_priv_alloc_map(struct amd_iommu *iommu, u64 iova, size_t size,
				 gfp_t gfp, void **out_va)
{
	int ret;
	void *va;
	int nid = iommu && iommu->dev ? dev_to_node(&iommu->dev->dev) : NUMA_NO_NODE;

	*out_va = NULL;

	if (!iommu || !iommu->viommu_pdom)
		return -EINVAL;

	va = iommu_alloc_pages_node_sz(nid, gfp, size);
	if (!va)
		return -ENOMEM;

	/*
	 * IOMMU spec: backing storage must be UC. set_memory_uc()
	 * splits covering 2MB direct-map pages to 4K; set_memory_wb()
	 * does not re-coalesce them.
	 */
	ret = set_memory_uc((unsigned long)va, size >> PAGE_SHIFT);
	if (ret)
		goto err_uc;

	ret = iommu_map(&iommu->viommu_pdom->domain, iova,
			iommu_virt_to_phys(va), size,
			IOMMU_READ | IOMMU_WRITE, gfp);
	if (ret)
		goto err_uc;

	*out_va = va;
	return 0;

err_uc:
	viommu_priv_wb_free(va, size);
	return ret;
}

static bool viommu_cmdbuf_enabled(struct amd_iommu *iommu)
{
	if (!iommu->mmio_base)
		return false;
	return readq(iommu->mmio_base + MMIO_CONTROL_OFFSET) &
	       BIT_ULL(CONTROL_CMDBUF_EN);
}

/*
 * Unmap @iova if the command buffer is still enabled, restore WB, and
 * free @cpu_va. Skip IOTLB invalidation after disable_iommus().
 */
static void viommu_priv_unmap_free(struct amd_iommu *iommu, u64 iova, size_t size,
				   void *cpu_va)
{
	size_t unmapped;

	if (!cpu_va)
		return;
	if (!iommu || !iommu->viommu_pdom)
		return;

	if (viommu_cmdbuf_enabled(iommu)) {
		unmapped = iommu_unmap(&iommu->viommu_pdom->domain, iova, size);
		WARN_ON(unmapped != size);
	}

	viommu_priv_wb_free(cpu_va, size);
}

static void *alloc_private_subregion(struct amd_iommu *iommu, u64 base, size_t size)
{
	void *region = NULL;
	int ret;

	ret = viommu_priv_alloc_map(iommu, base, size, GFP_KERNEL, &region);
	if (ret)
		return NULL;

	pr_debug("%s: base=%#llx, size=%#lx, subregion=%#llx(%#llx)\n",
		 __func__, base, size, (unsigned long long)region, iommu_virt_to_phys(region));

	return region;
}

static void viommu_private_space_uninit(struct amd_iommu *iommu)
{
	int i;
	u64 base;
	struct protection_domain *pdom;
	struct iommu_domain *dom;

	pdom = iommu->viommu_pdom;
	if (!pdom)
		return;

	for (i = 0; i < VIOMMU_PRIV_SUBREGION_CNT; i++) {
		if (!iommu->viommu_priv_region[i])
			continue;
		base = VIOMMU_PRIV_REGION_BASE + (i * VIOMMU_PRIV_SUBREGION_SIZE);
		viommu_priv_unmap_free(iommu, base, VIOMMU_PRIV_SUBREGION_SIZE,
					     iommu->viommu_priv_region[i]);
		iommu->viommu_priv_region[i] = NULL;
	}

	dom = &pdom->domain;
	amd_iommu_pdom_unbind_iommu(iommu, pdom);
	amd_iommu_domain_free(dom);
	iommu->viommu_pdom = NULL;
}

static int viommu_private_space_init(struct amd_iommu *iommu)
{
	int i, ret;
	u64 base;
	struct iommu_domain *dom;
	struct protection_domain *pdom;
	struct pt_iommu_amdv1_hw_info pt_info;

	dom = amd_iommu_domain_alloc_paging_v1(&iommu->dev->dev, 0);
	if (IS_ERR(dom)) {
		pr_err("%s: Failed to initialize private space\n", __func__);
		return PTR_ERR(dom);
	}

	/*
	 * Skipped iommu_domain_init(). set_dte_entry() only programs
	 * v1 when type has __IOMMU_DOMAIN_PAGING.
	 */
	dom->type = IOMMU_DOMAIN_UNMANAGED;

	pdom = to_pdomain(dom);
	iommu->viommu_pdom = pdom;

	ret = amd_iommu_pdom_bind_iommu(iommu, pdom);
	if (ret) {
		amd_iommu_domain_free(dom);
		iommu->viommu_pdom = NULL;
		return ret;
	}

	/*
	 * Each private region requires to 8MB of memory to be allocated
	 * and mapped. Split the region into 4 x 2MB-subregion.
	 */
	for (i = 0; i < VIOMMU_PRIV_SUBREGION_CNT; i++) {
		base = VIOMMU_PRIV_REGION_BASE + (i * VIOMMU_PRIV_SUBREGION_SIZE);
		iommu->viommu_priv_region[i] = alloc_private_subregion(iommu, base,
								       VIOMMU_PRIV_SUBREGION_SIZE);
		if (!iommu->viommu_priv_region[i]) {
			pr_err("%s: Failed to allocate vIOMMU private subregion %d\n", __func__, i);
			viommu_private_space_uninit(iommu);
			return -ENOMEM;
		}
	}

	pt_iommu_amdv1_hw_info(&pdom->amdv1, &pt_info);
	pr_debug("%s: devid=%#x, pte_root=%#llx\n",
		 __func__, iommu->devid,
		 (unsigned long long)pt_info.host_pt_root);

	return 0;
}

/*
 * Returns VF MMIO BAR offset for the given guest ID which will be
 * mapped to guest vIOMMU 3rd 4K MMIO address
 */
u64 amd_viommu_get_vfmmio_addr(struct amd_iommu *iommu, u16 gid)
{
	if (WARN_ON(!iommu->vf_base_phys || gid > VIOMMU_MAX_GID))
		return 0;

	return iommu->vf_base_phys + gid * VIOMMU_VF_MMIO_ENTRY_SIZE;
}


static int alloc_ext_int_remap_tbl(struct amd_iommu *iommu)
{
	iommu->ext_ir_table = (void *) __get_free_pages(GFP_KERNEL | __GFP_ZERO,
							get_order(EXT_INT_REMAP_TBL_L1_SIZE));

	return iommu->ext_ir_table ? 0 : -ENOMEM;
}

static void free_ext_int_remap_tbl(struct amd_iommu *iommu)
{
	if (!iommu->ext_ir_table)
		return;

	free_pages((unsigned long)iommu->ext_ir_table,
		   get_order(EXT_INT_REMAP_TBL_L1_SIZE));
	iommu->ext_ir_table = NULL;
}

int __init amd_viommu_init(struct amd_iommu *iommu)
{
	int ret;

	ret = viommu_vf_vfcntl_init(iommu);
	if (ret)
		return ret;

	ret = viommu_private_space_init(iommu);
	if (ret)
		goto err;

	ret = alloc_ext_int_remap_tbl(iommu);
	if (ret)
		goto err;

	ret = viommu_alloc_self_dev_data(iommu);
	if (ret)
		goto err;

	amd_iommu_update_dte_ir(iommu, iommu->viommu_dev_data,
				iommu_virt_to_phys(iommu->ext_ir_table),
				DTE_EXT_INTTABLEN_L1);

	hash_init(iommu->ext_irte_hlist);
	spin_lock_init(&iommu->ext_irte_hlist_lock);

	iommu->flags |= AMD_IOMMU_FLAG_VIOMMU_EN;
	return 0;
err:
	amd_viommu_uninit(iommu);
	return ret;
}

static int __maybe_unused alloc_private_vm_region(struct amd_iommu *iommu, u64 **entry,
						 u64 base, size_t size, u16 gid)
{
	int ret;
	void *va = NULL;
	u64 addr = base + (gid * size);

	/* Charge the caller; boot IPA stays GFP_KERNEL. */
	ret = viommu_priv_alloc_map(iommu, addr, size, GFP_KERNEL_ACCOUNT, &va);
	if (ret) {
		*entry = NULL;
		return ret;
	}

	*entry = (u64 *)va;

	pr_debug("%s: entry=%#llx(%#llx), addr=%#llx, size=%#lx\n", __func__,
		 (unsigned long long)*entry, iommu_virt_to_phys(*entry), addr, size);

	return 0;
}

static void __maybe_unused free_private_vm_region(struct amd_iommu *iommu, u64 **entry,
						  u64 base, size_t size, u16 gid)
{
	u64 addr = base + (gid * size);

	if (!iommu || !iommu->viommu_pdom || !*entry)
		return;

	pr_debug("%s: entry=%#llx(%#llx), base=%#llx, addr=%#llx, size=%#lx\n",
		 __func__, (unsigned long long)*entry,
		 iommu_virt_to_phys(*entry), base, addr, size);

	viommu_priv_unmap_free(iommu, addr, size, *entry);

	*entry = NULL;
}

#define DEVID_ENTRY_GDEVID_MASK		GENMASK_ULL(61, 46)
#define DEVID_ENTRY_HDEVID_MASK		GENMASK_ULL(29, 14)
#define DEVID_ENTRY_WRITE		BIT_ULL(63)
#define DEVID_ENTRY_VALID		BIT_ULL(0)

#define VIOMMU_VFCTRL_PREFILL_RESCHED	256

/*
 * CONTROL0/CONTROL1 bit 63 (WRITE) is a doorbell: hardware copies one
 * entry into the IPA-backed table and clears WRITE when that DMA write
 * retires. This is not a command-buffer operation;
 * iommu_completion_wait() does not drain it. A readq() of CONTROL_EN
 * is also unrelated. Poll WRITE=0 before ringing a new doorbell and
 * after each write so the table update is retired before the caller
 * proceeds (DTE commit, unmap/free).
 */
static void vfctrl_wait_write_clear(struct amd_iommu *iommu, u16 gid,
				    unsigned int offset)
{
	u8 __iomem *reg = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid) + offset;
	int i;

	for (i = 0; i < LOOP_TIMEOUT; i++) {
		if (!(readq(reg) & DEVID_ENTRY_WRITE))
			return;
		udelay(1);
	}
	pr_err("%s: WRITE timeout gid=%#x offset=%#x val=%#llx\n",
	       __func__, gid, offset, readq(reg));
}

/*
 * Guest DevID table update via VFCTRL CONTROL0.
 */
static void set_device_mapping_unlocked(struct amd_iommu *iommu, u16 gid,
					u16 hdev_id, u16 gdev_id)
{
	u64 val;
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);

	val = FIELD_PREP(DEVID_ENTRY_GDEVID_MASK, gdev_id) |
	      FIELD_PREP(DEVID_ENTRY_HDEVID_MASK, hdev_id) |
	      DEVID_ENTRY_WRITE | DEVID_ENTRY_VALID;

	vfctrl_wait_write_clear(iommu, gid,
			VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL0_OFFSET);
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL0_OFFSET);
	vfctrl_wait_write_clear(iommu, gid,
			VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL0_OFFSET);
}

/*
 * Program the DevID via VFCTRL CONTROL0. Waits for WRITE to clear so
 * the IPA table DMA has retired before return. Serialized by
 * aviommu->vfctrl_lock: CONTROL0 is shared by all vDevices on this gid.
 */
void amd_viommu_set_device_mapping(struct amd_iommu_viommu *aviommu,
				   u16 hdev_id, u16 gdev_id)
{
	struct amd_iommu *iommu =
		container_of(aviommu->core.iommu_dev, struct amd_iommu, iommu);

	pr_debug("%s: iommu_devid=%#x, gid=%#x, hdev_id=%#x, gdev_id=%#x\n",
		 __func__, pci_dev_id(iommu->dev), aviommu->gid, hdev_id,
		 gdev_id);

	mutex_lock(&aviommu->vfctrl_lock);
	set_device_mapping_unlocked(iommu, aviommu->gid, hdev_id, gdev_id);
	mutex_unlock(&aviommu->vfctrl_lock);
}

#define DOMID_ENTRY_GDOMID_MASK	GENMASK_ULL(61, 46)
#define DOMID_ENTRY_HDOMID_MASK	GENMASK_ULL(29, 14)
#define DOMID_ENTRY_VALID		BIT_ULL(0)
#define DOMID_ENTRY_WRITE		BIT_ULL(63)

/*
 * Guest DomID table update via VFCTRL CONTROL1. Same WRITE-bit
 * doorbell as CONTROL0.
 */
static void domain_id_update_unlocked(struct amd_iommu *iommu, u16 gid,
				      u16 hdom_id, u16 gdom_id)
{
	u64 val;
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);

	val = FIELD_PREP(DOMID_ENTRY_GDOMID_MASK, gdom_id) |
	      FIELD_PREP(DOMID_ENTRY_HDOMID_MASK, hdom_id) |
	      DOMID_ENTRY_WRITE | DOMID_ENTRY_VALID;

	vfctrl_wait_write_clear(iommu, gid,
			VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL1_OFFSET);
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL1_OFFSET);
	vfctrl_wait_write_clear(iommu, gid,
			VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL1_OFFSET);
}

/*
 * Program a gdom_id -> hdom_id entry through VFCTRL CONTROL1.
 * Caller must hold aviommu->vfctrl_lock.
 */
void amd_viommu_domain_id_update_locked(struct amd_iommu_viommu *aviommu,
					u16 hdom_id, u16 gdom_id)
{
	struct amd_iommu *iommu =
		container_of(aviommu->core.iommu_dev, struct amd_iommu, iommu);

	lockdep_assert_held(&aviommu->vfctrl_lock);
	domain_id_update_unlocked(iommu, aviommu->gid, hdom_id, gdom_id);
}

void amd_viommu_domain_id_update(struct amd_iommu_viommu *aviommu,
				 u16 hdom_id, u16 gdom_id)
{
	mutex_lock(&aviommu->vfctrl_lock);
	amd_viommu_domain_id_update_locked(aviommu, hdom_id, gdom_id);
	mutex_unlock(&aviommu->vfctrl_lock);
}

static bool viommu_vfctrl_ready(struct amd_iommu *iommu)
{
	return iommu->vfctrl_base && viommu_cmdbuf_enabled(iommu);
}

/*
 * Drain outstanding CONTROL0/CONTROL1 table DMA before the IPA pages
 * are unmapped and freed. Do not rewrite 0..0xFFFF: vDevice destroy
 * and nested_domain_free already restored idle entries, and a full
 * walk would start 128K new DMA writes into pages about to be freed.
 *
 * Skip after disable_iommus(): CMDBUF_EN is already clear, matching
 * viommu_priv_unmap_free() which skips IOTLB invalidation.
 */
static void viommu_drain_mapping(struct amd_iommu *iommu,
				 struct amd_iommu_viommu *aviommu)
{
	u16 gid = aviommu->gid;

	if (!viommu_vfctrl_ready(iommu))
		return;

	mutex_lock(&aviommu->vfctrl_lock);
	vfctrl_wait_write_clear(iommu, gid,
			VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL0_OFFSET);
	vfctrl_wait_write_clear(iommu, gid,
			VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL1_OFFSET);
	mutex_unlock(&aviommu->vfctrl_lock);
}

static void viommu_prefill_resched(struct amd_iommu_viommu *aviommu, int i)
{
	lockdep_assert_held(&aviommu->vfctrl_lock);

	if ((i & (VIOMMU_VFCTRL_PREFILL_RESCHED - 1)) !=
	    VIOMMU_VFCTRL_PREFILL_RESCHED - 1)
		return;

	mutex_unlock(&aviommu->vfctrl_lock);
	cond_resched();
	mutex_lock(&aviommu->vfctrl_lock);
}

/*
 * Prefill every guest ID so hardware never sees an unknown mapping.
 * Map all gdom_id to the nest parent domain ID, and all gdev_id with
 * hdev_id 0. Cannot be scoped to IDs in use: none exist yet, and
 * INVALIDATE_IOMMU_ALL walks the HW table.
 *
 * Drop vfctrl_lock every VIOMMU_VFCTRL_PREFILL_RESCHED doorbells so
 * the 128K MMIO loop can yield. Safe on init: vDevice/nested attach
 * cannot run until viommu->ops is published after init_one().
 */
static void viommu_prefill_mapping(struct amd_iommu *iommu,
				   struct amd_iommu_viommu *aviommu)
{
	int i;
	u16 gid = aviommu->gid;

	if (!viommu_vfctrl_ready(iommu))
		return;

	mutex_lock(&aviommu->vfctrl_lock);
	if (aviommu->domid_table) {
		for (i = 0; i <= VIOMMU_MAX_GDOMID; i++) {
			domain_id_update_unlocked(iommu, gid,
						  aviommu->parent->id, i);
			viommu_prefill_resched(aviommu, i);
		}
	}

	if (aviommu->devid_table) {
		for (i = 0; i <= VIOMMU_MAX_GDEVID; i++) {
			set_device_mapping_unlocked(iommu, gid, 0, i);
			viommu_prefill_resched(aviommu, i);
		}
	}
	mutex_unlock(&aviommu->vfctrl_lock);
}

void amd_viommu_uninit_one(struct amd_iommu *iommu, struct amd_iommu_viommu *aviommu)
{
	pr_debug("%s: gid=%u\n", __func__, aviommu->gid);

	/*
	 * Wait until CONTROL0/CONTROL1 table DMA has retired before
	 * the backing pages are unmapped and freed.
	 */
	viommu_drain_mapping(iommu, aviommu);
	free_private_vm_region(iommu, &aviommu->devid_table,
			       VIOMMU_DEVID_MAPPING_BASE,
			       VIOMMU_DEVID_MAPPING_ENTRY_SIZE,
			       aviommu->gid);
	free_private_vm_region(iommu, &aviommu->domid_table,
			       VIOMMU_DOMID_MAPPING_BASE,
			       VIOMMU_DOMID_MAPPING_ENTRY_SIZE,
			       aviommu->gid);
}

int amd_viommu_init_one(struct amd_iommu *iommu, struct amd_iommu_viommu *viommu)
{
	int ret;

	INIT_LIST_HEAD(&viommu->kvm_ext_ir_node);

	ret = alloc_private_vm_region(iommu, &viommu->devid_table,
				      VIOMMU_DEVID_MAPPING_BASE,
				      VIOMMU_DEVID_MAPPING_ENTRY_SIZE,
				      viommu->gid);
	if (ret)
		goto err_out;

	ret = alloc_private_vm_region(iommu, &viommu->domid_table,
				      VIOMMU_DOMID_MAPPING_BASE,
				      VIOMMU_DOMID_MAPPING_ENTRY_SIZE,
				      viommu->gid);
	if (ret)
		goto err_out;

	viommu_prefill_mapping(iommu, viommu);

	return 0;
err_out:
	amd_viommu_uninit_one(iommu, viommu);
	return ret;
}

void amd_viommu_set_cmdbuf_flags(struct iommufd_hw_queue *hw_queue)
{
	u8 __iomem *vfctrl, *vf;
	u32 flags = hw_queue->flags;
	u64 val;
	struct iommufd_viommu *viommu = hw_queue->viommu;
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);
	struct amd_iommu *iommu = container_of(viommu->iommu_dev, struct amd_iommu, iommu);
	int gid = aviommu->gid;

	vf = VIOMMU_VF_MMIO_BASE(iommu, gid);
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);

	/* Clear fields in VFCTRL MMIO */
	val = readq(vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_COMMAND_CONTROL_OFFSET);
	val &= ~(GENMASK_ULL(51, 12) | GENMASK_ULL(9, 8) | GENMASK_ULL(3, 0));

	/* Set Command buffer base, length, enable, command wait enable */
	val |= FIELD_PREP(GENMASK_ULL(3, 0), hw_queue->length);
	val |= FIELD_PREP(GENMASK_ULL(51, 12), (hw_queue->base_addr >> 12));
	val |= FIELD_PREP(BIT_ULL_MASK(8), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_CMDBUF_EN));
	val |= FIELD_PREP(BIT_ULL_MASK(9), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_COMWAIT_EN));

	writeq(val, vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_COMMAND_CONTROL_OFFSET);

	pr_debug("%s: iommu_devid=%#x, gid=%#x, type=%#x, addr=%#llx, len=%#lx, flags=%#x, val=%#llx\n",
		 __func__, iommu->devid, gid, hw_queue->type,
		 hw_queue->base_addr, hw_queue->length, flags, val);
}

void amd_viommu_set_evtbuf_flags(struct iommufd_hw_queue *hw_queue)
{
	u8 __iomem *vfctrl, *vf;
	u32 flags = hw_queue->flags;
	u64 val;
	struct iommufd_viommu *viommu = hw_queue->viommu;
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);
	struct amd_iommu *iommu = container_of(viommu->iommu_dev, struct amd_iommu, iommu);
	int gid = aviommu->gid;

	vf = VIOMMU_VF_MMIO_BASE(iommu, gid);
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);

	/* Clear fields in VFCTRL MMIO */
	val = readq(vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_EVENT_CONTROL_OFFSET);
	val &= ~GENMASK_ULL(51, 0);

	/* Set Event buffer base and length */
	val |= FIELD_PREP(GENMASK_ULL(3, 0), hw_queue->length);
	val |= FIELD_PREP(GENMASK_ULL(51, 12), (hw_queue->base_addr >> 12));
	val |= FIELD_PREP(BIT_ULL_MASK(8), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_EVT_LOG_EN));
	val |= FIELD_PREP(BIT_ULL_MASK(9), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_EVT_INT_EN));
	writeq(val, vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_EVENT_CONTROL_OFFSET);

	pr_debug("%s: iommu_devid=%#x, gid=%#x, type=%#x, addr=%#llx, len=%#lx, flags=%#x, val=%#llx\n",
		 __func__, iommu->devid, gid, hw_queue->type,
		 hw_queue->base_addr, hw_queue->length, flags, val);
}

void amd_viommu_set_pprbuf_flags(struct iommufd_hw_queue *hw_queue)
{
	u8 __iomem *vfctrl, *vf;
	u32 flags = hw_queue->flags;
	u64 val;
	struct iommufd_viommu *viommu = hw_queue->viommu;
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);
	struct amd_iommu *iommu = container_of(viommu->iommu_dev, struct amd_iommu, iommu);
	int gid = aviommu->gid;

	vf = VIOMMU_VF_MMIO_BASE(iommu, gid);
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);

	/* Clear fields in VFCTRL MMIO */
	val = readq(vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_PPR_CONTROL_OFFSET);
	val &= ~GENMASK_ULL(55, 0);

	/* Set PPR buffer base and length */
	val |= FIELD_PREP(GENMASK_ULL(3, 0), hw_queue->length);
	val |= FIELD_PREP(GENMASK_ULL(55, 16), (hw_queue->base_addr >> 12));
	val |= FIELD_PREP(BIT_ULL_MASK(8), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_PPRLOG_EN));
	val |= FIELD_PREP(BIT_ULL_MASK(9), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_PPRINT_EN));
	val |= FIELD_PREP(BIT_ULL_MASK(10), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_PPR_EN));
	val |= FIELD_PREP(BIT_ULL_MASK(13), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_PPR_AUTO_RSP_EN));
	val |= FIELD_PREP(BIT_ULL_MASK(14), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_BLKSTOPMRK_EN));
	val |= FIELD_PREP(BIT_ULL_MASK(15), !!(flags & IOMMU_HW_QUEUE_FLAG_AMD_PPR_AUTO_RSP_AON));
	writeq(val, vfctrl + VIOMMU_VFCTRL_MMIO_GUEST_PPR_CONTROL_OFFSET);

	pr_debug("%s: iommu_devid=%#x, gid=%#x, type=%#x, addr=%#llx, len=%#lx, flags=%#x, val=%#llx\n",
		 __func__, iommu->devid, gid, hw_queue->type,
		 hw_queue->base_addr, hw_queue->length, flags, val);
}

/*****************************************************
 * Extended interrupt remapping support
 */
#define EXT_IR_ID(x, y)		(((x & 0x3) << 16) | (y & 0xFFFF))
#define EXT_IR_ID_2_TYPE(x)	((x >> 16) & 0x3)
#define EXT_IR_ID_2_L1(x)	((x >> 8) & 0x3FF)
#define EXT_IR_ID_2_L2(x)	(x & 0xFF)

static struct irte_ga *_get_ext_intremap_entry(struct amd_iommu *iommu, u32 ext_id)
{
	u64 *l1_entry, *l2_entry;
	struct irte_ga *l2_table;
	u32 l1_index = EXT_IR_ID_2_L1(ext_id);
	u32 l2_index = EXT_IR_ID_2_L2(ext_id);

	l1_entry = &iommu->ext_ir_table[l1_index];

	/* Check if the l1_entry is valid */
	if (*l1_entry & 1ULL) {
		l2_table = iommu_phys_to_virt(*l1_entry & 0x000FFFFFFFFFFFC0);
	} else {
		int size = get_irq_table_size(MAX_IRQS_PER_TABLE_512);

		l2_table = iommu_alloc_pages_node_sz(dev_to_node(&iommu->dev->dev),
						     GFP_KERNEL, size);
		if (!l2_table)
			return NULL;

		/* Setup the L1 entry */
		*l1_entry = iommu_virt_to_phys(l2_table) & 0x000FFFFFFFFFFFC0;
		*l1_entry |= (EXT_INTTABLEN_L2_VALUE << 2);
		*l1_entry |= 1ULL; /* Valid */
	}
	l2_entry = (u64*) &l2_table[l2_index];

	pr_debug("%s: type=%#x, ext_intremap_tbl=%#llx, l1_entry=%#llx(%#llx, %u), l2_entry=%#llx(%#llx, %u)\n",
		__func__, EXT_IR_ID_2_TYPE(ext_id),
		iommu_virt_to_phys(iommu->ext_ir_table),
		iommu_virt_to_phys(l1_entry), *l1_entry, l1_index,
		iommu_virt_to_phys(l2_entry), *l2_entry, l2_index);

	return &l2_table[l2_index];
}

static struct ext_irte *get_ext_intremap_entry(struct amd_iommu *iommu, u32 ext_id)
{
	unsigned long flags;
	struct ext_irte *tmp, *eirte = NULL;

	spin_lock_irqsave(&iommu->ext_irte_hlist_lock, flags);

	hash_for_each_possible(iommu->ext_irte_hlist, tmp, hnode, ext_id) {
		if (tmp->ext_id == ext_id) {
			eirte = tmp;
			break;
		}
	}

	if (eirte)
		goto out;

	/* Allocate new ext-irte */
	eirte = kzalloc(sizeof(*eirte), GFP_KERNEL);
	if (!eirte)
		goto out;

	eirte->entry_ptr = _get_ext_intremap_entry(iommu, ext_id);
	if (!eirte->entry_ptr)
		goto out_free_eirte;

	eirte->ext_id = ext_id;
	hash_add(iommu->ext_irte_hlist, &eirte->hnode, ext_id);
	goto out;

out_free_eirte:
	kfree(eirte);
	eirte = NULL;
out:
	spin_unlock_irqrestore(&iommu->ext_irte_hlist_lock, flags);
	return eirte;
}

int amd_viommu_set_ext_int_remap_entry(struct iommufd_viommu *viommu,
				       struct kvm *kvm,
				       enum ext_intremap_type type, u32 vcpu_id,
				       u8 vector)
{
	struct ext_irte *eirte;
	struct amd_ir_data *ir_data;
	struct amd_iommu_pi_data pi;
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);
	struct amd_iommu *iommu = container_of(viommu->iommu_dev, struct amd_iommu, iommu);
	u64 pa;
	u32 ga_tag;
	u32 ext_id = EXT_IR_ID(type, aviommu->gid);

	if (!svm_ops)
		return -ENODEV;

	if (svm_ops->prepare_ext_ir_rebind)
		svm_ops->prepare_ext_ir_rebind(kvm);

	ga_tag = svm_ops->get_ga_tag(kvm, vcpu_id);
	pa = svm_ops->get_apic_backing_page(kvm, vcpu_id);
	if (!ga_tag || !pa)
		return -EINVAL;

	eirte = get_ext_intremap_entry(iommu, ext_id);
	if (!eirte)
		return -ENOMEM;

	ir_data = &eirte->ir_data;
	ir_data->iommu = iommu;
	ir_data->is_ext = true;
	ir_data->ext_id = ext_id;
	ir_data->entry = &eirte->entry;

	/*
	 * Drop stale hardware programming left in the table when teardown did
	 * not fully clear the entry (e.g. after a prior QEMU session).
	 */
	if (eirte->entry_ptr->lo.fields_vapic.guest_mode)
		amd_iommu_reset_ext_irte(iommu, eirte);

	pr_debug("%s: type=%#x, vcpu_id=%#x, vector=%#x, backing_page=%#llx, ga_tag=%#x\n",
		 __func__, type, vcpu_id, vector, pa, ga_tag);

	/* This is normally setup during prepare */
	eirte->entry.lo.fields_vapic.valid = 1;

	/*
	 * Initialize ir_data, which will be used in
	 * amd_iommu_activate_guest_mode()
	 */
	ir_data->ga_root_ptr = (pa & 0xFFFFFFFFFFFFFULL) >> 12;
	ir_data->ga_tag = ga_tag;
	ir_data->ga_vector = vector;

	pi.ir_data = ir_data;
	pi.ga_tag = ga_tag;

	svm_ops->set_ext_ir_affinity(kvm, vcpu_id, &pi);

	return 0;
}

static struct ext_irte *find_ext_irte(struct amd_iommu *iommu, u32 ext_id)
{
	unsigned long flags;
	struct ext_irte *tmp, *eirte = NULL;

	spin_lock_irqsave(&iommu->ext_irte_hlist_lock, flags);
	hash_for_each_possible(iommu->ext_irte_hlist, tmp, hnode, ext_id) {
		if (tmp->ext_id == ext_id) {
			eirte = tmp;
			break;
		}
	}
	spin_unlock_irqrestore(&iommu->ext_irte_hlist_lock, flags);

	return eirte;
}

static void remove_ext_irte(struct amd_iommu *iommu,
				       struct ext_irte *eirte)
{
	unsigned long flags;

	amd_iommu_reset_ext_irte(iommu, eirte);

	spin_lock_irqsave(&iommu->ext_irte_hlist_lock, flags);
	hash_del(&eirte->hnode);
	spin_unlock_irqrestore(&iommu->ext_irte_hlist_lock, flags);

	kfree(eirte);
}

void amd_viommu_remove_ext_int_remap_hw(struct amd_iommu *iommu,
					struct amd_iommu_viommu *aviommu)
{
	static const enum ext_intremap_type types[] = {
		EXT_INTREMAP_EVENT,
		EXT_INTREMAP_PPR,
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(types); i++) {
		struct ext_irte *eirte;
		u32 ext_id = EXT_IR_ID(types[i], aviommu->gid);

		eirte = find_ext_irte(iommu, ext_id);
		if (!eirte)
			continue;

		remove_ext_irte(iommu, eirte);
	}
}
