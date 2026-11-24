// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copy a device DMA address to or from guest RAM.
 *
 * The pointer in the context table is a device DMA address. Stage-2 is
 * indexed by GPA. For a nested device the address is walked through the
 * guest DTE's GCR3 page tables (AMD v2 / x86-64 format). When that walk
 * has no present translation and the nest parent maps the address, the
 * address is already a GPA (identity DMA) and is used directly.
 *
 * Callers run from process context with the device still attached and
 * the group mutex not held.
 */

#define pr_fmt(fmt)	"AMD-Vi: " fmt

#include <linux/align.h>
#include <linux/amd-iommu.h>
#include <linux/bitfield.h>
#include <linux/highmem.h>
#include <linux/iommu.h>
#include <linux/mem_encrypt.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/overflow.h>
#include <linux/string.h>

#include "amd_iommu.h"

/* Guest page-table output address, matching the v2 format walker. */
#define GUEST_OA_MASK	GENMASK_ULL(51, 12)

struct guest_dma {
	struct protection_domain *domain;
	u32 pasid;
	u8 glx;
	bool nested;
	bool five_level;
	bool cr3_valid;
	u64 gcr3;
	u64 cr3;
};

static int access_hpa(phys_addr_t hpa, void *buf, size_t len, bool write)
{
	unsigned long pfn = hpa >> PAGE_SHIFT;
	size_t off = hpa & ~PAGE_MASK;
	struct page *page;
	void *kaddr;

	if (!len)
		return 0;
	if (off + len > PAGE_SIZE)
		return -EINVAL;
	if (!pfn_valid(pfn))
		return -EFAULT;

	page = pfn_to_page(pfn);
	kaddr = kmap_local_page(page);
	if (write)
		memcpy(kaddr + off, buf, len);
	else
		memcpy(buf, kaddr + off, len);
	kunmap_local(kaddr);
	return 0;
}

static int gpa_to_hpa(struct protection_domain *domain, u64 gpa,
		      phys_addr_t *hpa)
{
	phys_addr_t pa;

	if (!domain->domain.ops || !domain->domain.ops->iova_to_phys)
		return -EOPNOTSUPP;

	pa = iommu_iova_to_phys(&domain->domain, gpa);
	if (!pa)
		return -EFAULT;

	*hpa = __sme_clr(pa);
	return 0;
}

static int access_gpa(struct protection_domain *domain, u64 gpa, void *buf,
		      size_t len, bool write)
{
	while (len) {
		phys_addr_t hpa;
		size_t n, off;
		int ret;

		ret = gpa_to_hpa(domain, gpa, &hpa);
		if (ret)
			return ret;

		off = hpa & ~PAGE_MASK;
		n = min_t(size_t, len, PAGE_SIZE - off);
		n = min_t(size_t, n, PAGE_SIZE - (gpa & ~PAGE_MASK));
		ret = access_hpa(hpa, buf, n, write);
		if (ret)
			return ret;

		buf += n;
		gpa += n;
		len -= n;
	}
	return 0;
}

static int read_gpa(struct protection_domain *domain, u64 gpa, void *buf,
		    size_t len)
{
	return access_gpa(domain, gpa, buf, len, false);
}

static int read_gpa_u64(struct protection_domain *domain, u64 gpa, u64 *val)
{
	if (!IS_ALIGNED(gpa, sizeof(*val)))
		return -EINVAL;
	if ((gpa & ~PAGE_MASK) > PAGE_SIZE - sizeof(*val))
		return -EINVAL;
	return read_gpa(domain, gpa, val, sizeof(*val));
}

static int guest_dma_init(struct device *dev, u32 pasid, struct guest_dma *g)
{
	struct iommu_domain *dom;
	u64 d0, d1, d2;

	memset(g, 0, sizeof(*g));
	g->pasid = pasid;

	dom = iommu_get_domain_for_dev(dev);
	if (!dom)
		return -ENODEV;

	if (dom->type == IOMMU_DOMAIN_NESTED) {
		struct nested_domain *ndom;

		ndom = container_of(dom, struct nested_domain, domain);
		if (!ndom->viommu || !ndom->viommu->parent)
			return -EINVAL;

		/*
		 * Same split as set_dte_gcr3_table(): bits [14:12] live in
		 * DTE[0], bits [51:15] in DTE[1]. The value is a GPA.
		 */
		d0 = ndom->gdte.dte[0];
		d1 = ndom->gdte.dte[1];
		d2 = ndom->gdte.dte[2];
		if (!(d0 & DTE_FLAG_GV))
			return -EINVAL;

		g->glx = FIELD_GET(DTE_GLX, d0);
		if (g->glx > 2)
			return -EINVAL;

		g->gcr3 = (FIELD_GET(DTE_GCR3_14_12, d0) << 12) |
			  (FIELD_GET(DTE_GCR3_30_15, d1) << 15) |
			  (FIELD_GET(DTE_GCR3_51_31, d1) << 31);
		if (!g->gcr3)
			return -EINVAL;

		g->five_level = FIELD_GET(DTE_GPT_LEVEL_MASK, d2) ==
				GUEST_PGTABLE_5_LEVEL;
		g->domain = ndom->viommu->parent;
		g->nested = true;
		return 0;
	}

	if (!iommupt_from_domain(dom))
		return -EOPNOTSUPP;

	g->domain = to_pdomain(dom);
	return 0;
}

/* GCR3[pasid] -> GPA of the guest page-table root. */
static int gcr3_cr3(struct guest_dma *g, u64 *cr3)
{
	u64 table = g->gcr3;
	int level = g->glx;

	if (g->cr3_valid) {
		*cr3 = g->cr3;
		return 0;
	}

	while (true) {
		unsigned int idx = (g->pasid >> (9 * level)) & 0x1ff;
		u64 ent;
		int ret;

		ret = read_gpa_u64(g->domain, table + idx * sizeof(ent), &ent);
		if (ret)
			return ret;
		if (!(ent & GCR3_VALID))
			return -ENOENT;
		if (level == 0) {
			g->cr3 = ent & GUEST_OA_MASK;
			g->cr3_valid = true;
			*cr3 = g->cr3;
			return 0;
		}
		table = ent & GUEST_OA_MASK;
		level--;
	}
}

/*
 * Walk the guest's v2 page tables. Level 0 is a 4K page. A PS bit at
 * level 1 or 2 is a 2MB or 1GB leaf, matching the x86_64 format.
 */
static int guest_iova_to_gpa(struct guest_dma *g, dma_addr_t iova, u64 *gpa)
{
	int level = g->five_level ? 4 : 3;
	u64 table, cr3;
	int ret;

	ret = gcr3_cr3(g, &cr3);
	if (ret)
		return ret;

	table = cr3;
	for (; level >= 0; level--) {
		unsigned int shift = 12 + 9 * level;
		unsigned int idx = ((u64)iova >> shift) & 0x1ff;
		u64 pte, oa, off_mask;
		bool leaf;

		ret = read_gpa_u64(g->domain, table + idx * sizeof(pte), &pte);
		if (ret)
			return ret;
		if (!(pte & BIT_ULL(0)))
			return -ENOENT;

		oa = FIELD_GET(GUEST_OA_MASK, pte) << 12;
		leaf = level == 0 || (level <= 2 && (pte & BIT_ULL(7)));
		if (!leaf) {
			table = oa;
			continue;
		}

		off_mask = (1ULL << shift) - 1;
		*gpa = (oa & ~off_mask) | ((u64)iova & off_mask);
		return 0;
	}
	return -EFAULT;
}

/*
 * A nested DMA address is a guest IOVA when the guest page tables have a
 * present translation. Identity DMA programs the GPA itself: the walk
 * returns -ENOENT, and the address is a stage-2 IOVA when the nest
 * parent maps that page. An unmapped address stays -ENOENT so a missed
 * walk cannot use some other GPA.
 */
static int iova_to_domain_addr(struct guest_dma *g, dma_addr_t iova, u64 *addr)
{
	phys_addr_t hpa;
	int ret;

	if (!g->nested) {
		*addr = iova;
		return 0;
	}

	ret = guest_iova_to_gpa(g, iova, addr);
	if (ret != -ENOENT)
		return ret;

	ret = gpa_to_hpa(g->domain, iova, &hpa);
	if (ret == -EFAULT)
		return -ENOENT;
	if (ret)
		return ret;

	*addr = iova;
	return 0;
}

/**
 * amd_iommu_read_guest_dma - copy from a device DMA address
 * @dev: attached device
 * @pasid: GCR3 index. 0 is the kernel table used for non-PASID DMA
 * @iova: device DMA address. Guest IOVA when @dev is nested
 * @buf: destination
 * @len: bytes to copy
 *
 * Nested devices are translated through the guest page tables and read
 * through the stage-2 domain. An address with no present guest
 * translation is read as a GPA when stage-2 maps it. A paging domain
 * is read directly.
 */
int amd_iommu_read_guest_dma(struct device *dev, u32 pasid, dma_addr_t iova,
			     void *buf, size_t len)
{
	struct guest_dma g;
	dma_addr_t end;
	int ret;

	if (!len)
		return 0;
	if (!buf)
		return -EINVAL;
	if (check_add_overflow(iova, (dma_addr_t)len, &end))
		return -EOVERFLOW;

	ret = guest_dma_init(dev, pasid, &g);
	if (ret)
		return ret;

	while (len) {
		size_t n = min_t(size_t, len, PAGE_SIZE - (iova & ~PAGE_MASK));
		u64 addr;

		ret = iova_to_domain_addr(&g, iova, &addr);
		if (ret)
			return ret;
		ret = read_gpa(g.domain, addr, buf, n);
		if (ret)
			return ret;

		iova += n;
		buf += n;
		len -= n;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(amd_iommu_read_guest_dma);

/**
 * amd_iommu_write_guest_dma - copy to a device DMA address
 * @dev: attached device
 * @pasid: GCR3 index. 0 is the kernel table used for non-PASID DMA
 * @iova: device DMA address. Guest IOVA when @dev is nested
 * @buf: source
 * @len: bytes to copy
 *
 * Translation matches amd_iommu_read_guest_dma(). Used to put a
 * post-stop context-status block back into guest RAM on resume.
 */
int amd_iommu_write_guest_dma(struct device *dev, u32 pasid, dma_addr_t iova,
			      const void *buf, size_t len)
{
	struct guest_dma g;
	const u8 *src = buf;
	dma_addr_t end;
	int ret;

	if (!len)
		return 0;
	if (!buf)
		return -EINVAL;
	if (check_add_overflow(iova, (dma_addr_t)len, &end))
		return -EOVERFLOW;

	ret = guest_dma_init(dev, pasid, &g);
	if (ret)
		return ret;

	while (len) {
		size_t n = min_t(size_t, len, PAGE_SIZE - (iova & ~PAGE_MASK));
		u64 addr;

		ret = iova_to_domain_addr(&g, iova, &addr);
		if (ret)
			return ret;
		ret = access_gpa(g.domain, addr, (void *)src, n, true);
		if (ret)
			return ret;

		iova += n;
		src += n;
		len -= n;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(amd_iommu_write_guest_dma);
