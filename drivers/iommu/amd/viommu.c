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
#include <uapi/linux/iommufd.h>

#include <asm/iommu.h>
#include <asm/set_memory.h>

#include "iommufd.h"
#include "amd_iommu.h"
#include "amd_iommu_types.h"
#include "amd_viommu.h"
#include "../iommu-pages.h"

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


static bool viommu_cmdbuf_enabled(struct amd_iommu *iommu);

static void viommu_free_self_dev_data(struct amd_iommu *iommu)
{
	struct iommu_dev_data *dev_data = iommu->viommu_dev_data;
	struct dev_table_entry new = {};

	if (!dev_data)
		return;

	/*
	 * INV_DTE needs the command buffer. Skip it after
	 * disable_iommus() clears CONTROL_CMDBUF_EN. The init
	 * unwind still flushes while the buffer is enabled.
	 */
	if (viommu_cmdbuf_enabled(iommu)) {
		amd_iommu_make_clear_dte(iommu, dev_data->devid, &new);
		amd_iommu_update_dte(iommu, dev_data, &new);
	}
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
	 *
	 * init_iommu_one_late() reserves this devid. rlookup is NULL, so
	 * probe never runs, and alloc must not reuse the self DTE slot.
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

void __init amd_viommu_uninit(struct amd_iommu *iommu)
{
	iommu->flags &= ~AMD_IOMMU_FLAG_VIOMMU_EN;
	viommu_free_self_dev_data(iommu);
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

int __init amd_viommu_init(struct amd_iommu *iommu)
{
	int ret;

	ret = viommu_vf_vfcntl_init(iommu);
	if (ret)
		return ret;

	ret = viommu_private_space_init(iommu);
	if (ret)
		goto err;

	ret = viommu_alloc_self_dev_data(iommu);
	if (ret)
		goto err;

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
#define DEVID_ENTRY_QUEUEID_MASK	GENMASK_ULL(45, 30)
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
 *
 * TODO: The driver does not support QueueID yet,
 *       so current callers pass 0. This will be
 *       enhanced in the future.
 */
static void set_device_mapping_unlocked(struct amd_iommu *iommu, u16 gid,
					u16 hdev_id, u16 gdev_id, u16 queue_id)
{
	u64 val;
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);

	val = FIELD_PREP(DEVID_ENTRY_GDEVID_MASK, gdev_id) |
	      FIELD_PREP(DEVID_ENTRY_QUEUEID_MASK, queue_id) |
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
	set_device_mapping_unlocked(iommu, aviommu->gid, hdev_id, gdev_id, 0);
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
 * hdev_id 0 and QueueID 0. Cannot be scoped to IDs in use: none exist
 * yet, and INVALIDATE_IOMMU_ALL walks the HW table.
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
			set_device_mapping_unlocked(iommu, gid, 0, i, 0);
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

enum amd_viommu_hw_queue_slot {
	AMD_VIOMMU_HW_QUEUE_CMD,
	AMD_VIOMMU_HW_QUEUE_EVT,
	AMD_VIOMMU_HW_QUEUE_PPR,
};

struct amd_viommu_hw_queue_cfg {
	u64 offset;
	u64 base_mask;
	u64 enable_mask;
	u32 flags_mask;
	u8 base_shift;
};

static const struct amd_viommu_hw_queue_cfg amd_viommu_hw_queue_cfg[] = {
	[AMD_VIOMMU_HW_QUEUE_CMD] = {
		.offset = VIOMMU_VFCTRL_MMIO_GUEST_COMMAND_CONTROL_OFFSET,
		.base_mask = VIOMMU_VFCTRL_CMD_BASE_MASK,
		.enable_mask = VIOMMU_VFCTRL_CMD_EN_MASK,
		.flags_mask = AMD_HW_QUEUE_FLAGS_CMD,
		.base_shift = 12,
	},
	[AMD_VIOMMU_HW_QUEUE_EVT] = {
		.offset = VIOMMU_VFCTRL_MMIO_GUEST_EVENT_CONTROL_OFFSET,
		.base_mask = VIOMMU_VFCTRL_EVT_BASE_MASK,
		.enable_mask = VIOMMU_VFCTRL_EVT_EN_MASK,
		.flags_mask = AMD_HW_QUEUE_FLAGS_EVT,
		.base_shift = 12,
	},
	[AMD_VIOMMU_HW_QUEUE_PPR] = {
		.offset = VIOMMU_VFCTRL_MMIO_GUEST_PPR_CONTROL_OFFSET,
		.base_mask = VIOMMU_VFCTRL_PPR_BASE_MASK,
		.enable_mask = VIOMMU_VFCTRL_PPR_EN_MASK,
		.flags_mask = AMD_HW_QUEUE_FLAGS_PPR,
		.base_shift = 16,
	},
};

static int amd_viommu_hw_queue_slot(enum iommu_hw_queue_type type)
{
	switch (type) {
	case IOMMU_HW_QUEUE_TYPE_AMD_CMD:
		return AMD_VIOMMU_HW_QUEUE_CMD;
	case IOMMU_HW_QUEUE_TYPE_AMD_EVT:
		return AMD_VIOMMU_HW_QUEUE_EVT;
	case IOMMU_HW_QUEUE_TYPE_AMD_PPR:
		return AMD_VIOMMU_HW_QUEUE_PPR;
	default:
		return -EINVAL;
	}
}

static void amd_viommu_hw_queue_disable_wait(struct amd_iommu_viommu *aviommu,
					     const struct amd_viommu_hw_queue_cfg *cfg,
					     u8 __iomem *vfctrl)
{
	u64 val;
	int i;

	lockdep_assert_held(&aviommu->vfctrl_lock);

	val = readq(vfctrl + cfg->offset);
	val &= ~cfg->enable_mask;
	writeq(val, vfctrl + cfg->offset);

	for (i = 0; i < LOOP_TIMEOUT; i++) {
		val = readq(vfctrl + cfg->offset);
		if (!(val & cfg->enable_mask))
			return;
		udelay(1);
	}
	pr_err("%s: disable timeout gid=%#x offset=%#llx val=%#llx\n",
	       __func__, aviommu->gid, cfg->offset, val);
}

static void amd_viommu_hw_queue_destroy(struct iommufd_hw_queue *hw_queue)
{
	struct iommufd_viommu *viommu = hw_queue->viommu;
	struct amd_iommu_viommu *aviommu = container_of(viommu, struct amd_iommu_viommu, core);
	struct amd_iommu *iommu = container_of(viommu->iommu_dev, struct amd_iommu, iommu);
	const struct amd_viommu_hw_queue_cfg *cfg;
	u8 __iomem *vfctrl;
	int slot;
	u64 val;

	slot = amd_viommu_hw_queue_slot(hw_queue->type);
	if (WARN_ON_ONCE(slot < 0))
		return;

	cfg = &amd_viommu_hw_queue_cfg[slot];
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, aviommu->gid);

	mutex_lock(&aviommu->vfctrl_lock);
	if (aviommu->hw_queues[slot] == hw_queue) {
		amd_viommu_hw_queue_disable_wait(aviommu, cfg, vfctrl);
		val = readq(vfctrl + cfg->offset);
		val &= ~(cfg->base_mask | cfg->enable_mask | VIOMMU_VFCTRL_HWQ_LEN_MASK);
		writeq(val, vfctrl + cfg->offset);
		aviommu->hw_queues[slot] = NULL;
	}
	mutex_unlock(&aviommu->vfctrl_lock);
}

static int
amd_viommu_set_hw_queue(struct iommufd_hw_queue *hw_queue,
			enum amd_viommu_hw_queue_slot slot, u64 enable_bits)
{
	struct iommufd_viommu *viommu = hw_queue->viommu;
	struct amd_iommu_viommu *aviommu =
		container_of(viommu, struct amd_iommu_viommu, core);
	struct amd_iommu *iommu =
		container_of(viommu->iommu_dev, struct amd_iommu, iommu);
	const struct amd_viommu_hw_queue_cfg *cfg =
		&amd_viommu_hw_queue_cfg[slot];
	u8 __iomem *vfctrl;
	u8 length;
	u64 val;
	int ret = 0;

	if (hw_queue->flags & ~cfg->flags_mask)
		return -EINVAL;
	if (!enable_bits)
		return -EINVAL;
	if (!IS_ALIGNED(hw_queue->base_addr, SZ_4K))
		return -EINVAL;
	if (hw_queue->base_addr & ~GENMASK_ULL(51, 12))
		return -EINVAL;
	if (!is_power_of_2(hw_queue->length) ||
	    hw_queue->length < SZ_4K || hw_queue->length > SZ_512K)
		return -EINVAL;

	length = ilog2(hw_queue->length) - 4;
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, aviommu->gid);

	mutex_lock(&aviommu->vfctrl_lock);
	if (aviommu->hw_queues[slot]) {
		ret = -EEXIST;
		goto out_unlock;
	}

	val = readq(vfctrl + cfg->offset);
	val &= ~(cfg->base_mask | cfg->enable_mask | VIOMMU_VFCTRL_HWQ_LEN_MASK);
	val |= FIELD_PREP(VIOMMU_VFCTRL_HWQ_LEN_MASK, length);
	/*
	 * base_shift is the VFCTRL bit position that represents GPA bit 12.
	 * PPR starts at bit 16 because its enable fields occupy bits 8-15.
	 */
	val |= (hw_queue->base_addr << (cfg->base_shift - 12)) & cfg->base_mask;
	val |= enable_bits;
	writeq(val, vfctrl + cfg->offset);

	aviommu->hw_queues[slot] = hw_queue;
	hw_queue->destroy = amd_viommu_hw_queue_destroy;
out_unlock:
	mutex_unlock(&aviommu->vfctrl_lock);

	if (!ret)
		pr_debug("%s: iommu_devid=%#x, gid=%#x, type=%#x, addr=%#llx, len=%#lx, flags=%#x, val=%#llx\n",
			 __func__, iommu->devid, aviommu->gid, hw_queue->type,
			 hw_queue->base_addr, hw_queue->length,
			 hw_queue->flags, val);

	return ret;
}

int amd_viommu_set_cmdbuf_flags(struct iommufd_hw_queue *hw_queue)
{
	u32 flags = hw_queue->flags;
	u64 enable_bits = 0;

	if (flags & IOMMU_HW_QUEUE_FLAG_AMD_CMDBUF_EN)
		enable_bits |= BIT_ULL(8);
	if (flags & IOMMU_HW_QUEUE_FLAG_AMD_COMWAIT_EN)
		enable_bits |= BIT_ULL(9);

	return amd_viommu_set_hw_queue(hw_queue, AMD_VIOMMU_HW_QUEUE_CMD,
				       enable_bits);
}

int amd_viommu_set_evtbuf_flags(struct iommufd_hw_queue *hw_queue)
{
	u32 flags = hw_queue->flags;
	u64 enable_bits = 0;

	if (flags & IOMMU_HW_QUEUE_FLAG_AMD_EVT_LOG_EN)
		enable_bits |= BIT_ULL(8);
	if (flags & IOMMU_HW_QUEUE_FLAG_AMD_EVT_INT_EN)
		enable_bits |= BIT_ULL(9);

	return amd_viommu_set_hw_queue(hw_queue, AMD_VIOMMU_HW_QUEUE_EVT,
				       enable_bits);
}

int amd_viommu_set_pprbuf_flags(struct iommufd_hw_queue *hw_queue)
{
	u32 flags = hw_queue->flags;
	u64 enable_bits = 0;

	if (flags & IOMMU_HW_QUEUE_FLAG_AMD_PPRLOG_EN)
		enable_bits |= BIT_ULL(8);
	if (flags & IOMMU_HW_QUEUE_FLAG_AMD_PPRINT_EN)
		enable_bits |= BIT_ULL(9);
	if (flags & IOMMU_HW_QUEUE_FLAG_AMD_PPR_EN)
		enable_bits |= BIT_ULL(10);
	if (flags & IOMMU_HW_QUEUE_FLAG_AMD_PPR_AUTO_RSP_EN)
		enable_bits |= BIT_ULL(13);
	if (flags & IOMMU_HW_QUEUE_FLAG_AMD_BLKSTOPMRK_EN)
		enable_bits |= BIT_ULL(14);
	if (flags & IOMMU_HW_QUEUE_FLAG_AMD_PPR_AUTO_RSP_AON)
		enable_bits |= BIT_ULL(15);

	return amd_viommu_set_hw_queue(hw_queue, AMD_VIOMMU_HW_QUEUE_PPR,
				       enable_bits);
}

