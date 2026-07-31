// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES
 */
#include "iommufd_private.h"

void iommufd_viommu_destroy(struct iommufd_object *obj)
{
	struct iommufd_viommu *viommu =
		container_of(obj, struct iommufd_viommu, obj);

	if (viommu->ops && viommu->ops->destroy)
		viommu->ops->destroy(viommu);
	refcount_dec(&viommu->hwpt->common.obj.users);
	xa_destroy(&viommu->vdevs);
	mutex_destroy(&viommu->mig_lock);
}

/* All of the migration ops are needed for any of them to be usable */
bool iommufd_viommu_mig_supported(struct iommufd_viommu *viommu)
{
	return viommu->ops && viommu->ops->mig_get_size &&
	       viommu->ops->mig_prepare_save && viommu->ops->mig_save &&
	       viommu->ops->mig_restore && viommu->ops->mig_commit_restore &&
	       viommu->ops->mig_abort;
}

static bool iommufd_viommu_mig_may_enter(enum iommufd_viommu_mig_state cur,
					 enum iommufd_viommu_mig_state next)
{
	switch (next) {
	case IOMMUFD_VIOMMU_MIG_NONE:
		/* Abort resets from any state, including a completed one */
		return true;
	case IOMMUFD_VIOMMU_MIG_PREPARED:
		return cur == IOMMUFD_VIOMMU_MIG_NONE;
	case IOMMUFD_VIOMMU_MIG_SAVED:
		return cur == IOMMUFD_VIOMMU_MIG_PREPARED;
	case IOMMUFD_VIOMMU_MIG_RESTORING:
		return cur == IOMMUFD_VIOMMU_MIG_NONE;
	case IOMMUFD_VIOMMU_MIG_COMMITTED:
		return cur == IOMMUFD_VIOMMU_MIG_RESTORING;
	default:
		return false;
	}
}

/**
 * iommufd_viommu_mig_enter() - Advance the migration state machine
 * @viommu: vIOMMU to transition
 * @next: State to enter
 *
 * Migration spans several ioctls, and the later ones act on hardware using
 * state that an earlier one validated. Userspace cannot be trusted to issue
 * them in order, so each step declares the state it produces and is refused if
 * the vIOMMU is not in a state that step can legally follow. Refusing here is
 * what stops, for example, a queue being armed from a payload that was never
 * validated.
 *
 * Context: Caller must hold @viommu->mig_lock.
 * Return: 0 on success, -EINVAL if the transition is not legal.
 */
int iommufd_viommu_mig_enter(struct iommufd_viommu *viommu,
			     enum iommufd_viommu_mig_state next)
{
	lockdep_assert_held(&viommu->mig_lock);

	if (!iommufd_viommu_mig_may_enter(viommu->mig_state, next))
		return -EINVAL;

	viommu->mig_state = next;
	return 0;
}

int iommufd_viommu_alloc_ioctl(struct iommufd_ucmd *ucmd)
{
	struct iommu_viommu_alloc *cmd = ucmd->cmd;
	const struct iommu_user_data user_data = {
		.type = cmd->type,
		.uptr = u64_to_user_ptr(cmd->data_uptr),
		.len = cmd->data_len,
	};
	struct iommufd_hwpt_paging *hwpt_paging;
	struct iommufd_viommu *viommu;
	struct iommufd_device *idev;
	const struct iommu_ops *ops;
	size_t viommu_size;
	int rc;

	if (cmd->flags || cmd->type == IOMMU_VIOMMU_TYPE_DEFAULT)
		return -EOPNOTSUPP;

	idev = iommufd_get_device(ucmd, cmd->dev_id);
	if (IS_ERR(idev))
		return PTR_ERR(idev);

	ops = dev_iommu_ops(idev->dev);
	if (!ops->get_viommu_size || !ops->viommu_init) {
		rc = -EOPNOTSUPP;
		goto out_put_idev;
	}

	viommu_size = ops->get_viommu_size(idev->dev, cmd->type);
	if (!viommu_size) {
		rc = -EOPNOTSUPP;
		goto out_put_idev;
	}

	/*
	 * It is a driver bug for providing a viommu_size smaller than the core
	 * vIOMMU structure size
	 */
	if (WARN_ON_ONCE(viommu_size < sizeof(*viommu))) {
		rc = -EOPNOTSUPP;
		goto out_put_idev;
	}

	hwpt_paging = iommufd_get_hwpt_paging(ucmd, cmd->hwpt_id);
	if (IS_ERR(hwpt_paging)) {
		rc = PTR_ERR(hwpt_paging);
		goto out_put_idev;
	}

	if (!hwpt_paging->nest_parent) {
		rc = -EINVAL;
		goto out_put_hwpt;
	}

	viommu = (struct iommufd_viommu *)_iommufd_object_alloc_ucmd(
		ucmd, viommu_size, IOMMUFD_OBJ_VIOMMU);
	if (IS_ERR(viommu)) {
		rc = PTR_ERR(viommu);
		goto out_put_hwpt;
	}

	xa_init(&viommu->vdevs);
	mutex_init(&viommu->mig_lock);
	viommu->mig_state = IOMMUFD_VIOMMU_MIG_NONE;
	viommu->type = cmd->type;
	viommu->ictx = ucmd->ictx;
	viommu->hwpt = hwpt_paging;
	refcount_inc(&viommu->hwpt->common.obj.users);
	INIT_LIST_HEAD(&viommu->veventqs);
	init_rwsem(&viommu->veventqs_rwsem);
	/*
	 * It is the most likely case that a physical IOMMU is unpluggable. A
	 * pluggable IOMMU instance (if exists) is responsible for refcounting
	 * on its own.
	 */
	viommu->iommu_dev = __iommu_get_iommu_dev(idev->dev);

	rc = ops->viommu_init(viommu, hwpt_paging->common.domain,
			      user_data.len ? &user_data : NULL);
	if (rc)
		goto out_put_hwpt;

	/* It is a driver bug that viommu->ops isn't filled */
	if (WARN_ON_ONCE(!viommu->ops)) {
		rc = -EOPNOTSUPP;
		goto out_put_hwpt;
	}

	cmd->out_viommu_id = viommu->obj.id;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));

out_put_hwpt:
	iommufd_put_object(ucmd->ictx, &hwpt_paging->common.obj);
out_put_idev:
	iommufd_put_object(ucmd->ictx, &idev->obj);
	return rc;
}

void iommufd_vdevice_abort(struct iommufd_object *obj)
{
	struct iommufd_vdevice *vdev =
		container_of(obj, struct iommufd_vdevice, obj);
	struct iommufd_viommu *viommu = vdev->viommu;
	struct iommufd_device *idev = vdev->idev;

	lockdep_assert_held(&idev->igroup->lock);

	if (vdev->destroy)
		vdev->destroy(vdev);
	/* xa_cmpxchg is okay to fail if alloc failed xa_cmpxchg previously */
	xa_cmpxchg(&viommu->vdevs, vdev->virt_id, vdev, NULL, GFP_KERNEL);
	refcount_dec(&viommu->obj.users);
	idev->vdev = NULL;
}

void iommufd_vdevice_destroy(struct iommufd_object *obj)
{
	struct iommufd_vdevice *vdev =
		container_of(obj, struct iommufd_vdevice, obj);
	struct iommufd_device *idev = vdev->idev;
	struct iommufd_ctx *ictx = idev->ictx;

	mutex_lock(&idev->igroup->lock);
	iommufd_vdevice_abort(obj);
	mutex_unlock(&idev->igroup->lock);
	iommufd_put_object(ictx, &idev->obj);
}

int iommufd_vdevice_alloc_ioctl(struct iommufd_ucmd *ucmd)
{
	struct iommu_vdevice_alloc *cmd = ucmd->cmd;
	struct iommufd_vdevice *vdev, *curr;
	size_t vdev_size = sizeof(*vdev);
	struct iommufd_viommu *viommu;
	struct iommufd_device *idev;
	u64 virt_id = cmd->virt_id;
	int rc = 0;

	/* virt_id indexes an xarray */
	if (virt_id > ULONG_MAX)
		return -EINVAL;

	viommu = iommufd_get_viommu(ucmd, cmd->viommu_id);
	if (IS_ERR(viommu))
		return PTR_ERR(viommu);

	idev = iommufd_get_device(ucmd, cmd->dev_id);
	if (IS_ERR(idev)) {
		rc = PTR_ERR(idev);
		goto out_put_viommu;
	}

	if (viommu->iommu_dev != __iommu_get_iommu_dev(idev->dev)) {
		rc = -EINVAL;
		goto out_put_idev;
	}

	mutex_lock(&idev->igroup->lock);
	if (idev->destroying) {
		rc = -ENOENT;
		goto out_unlock_igroup;
	}

	if (idev->vdev) {
		rc = -EEXIST;
		goto out_unlock_igroup;
	}

	if (viommu->ops && viommu->ops->vdevice_size) {
		/*
		 * It is a driver bug for:
		 * - ops->vdevice_size smaller than the core structure size
		 * - not implementing a pairing ops->vdevice_init op
		 */
		if (WARN_ON_ONCE(viommu->ops->vdevice_size < vdev_size ||
				 !viommu->ops->vdevice_init)) {
			rc = -EOPNOTSUPP;
			goto out_put_idev;
		}
		vdev_size = viommu->ops->vdevice_size;
	}

	vdev = (struct iommufd_vdevice *)_iommufd_object_alloc(
		ucmd->ictx, vdev_size, IOMMUFD_OBJ_VDEVICE);
	if (IS_ERR(vdev)) {
		rc = PTR_ERR(vdev);
		goto out_unlock_igroup;
	}

	vdev->virt_id = virt_id;
	vdev->viommu = viommu;
	refcount_inc(&viommu->obj.users);
	/*
	 * A wait_cnt reference is held on the idev so long as we have the
	 * pointer. iommufd_device_pre_destroy() will revoke it before the
	 * idev real destruction.
	 */
	vdev->idev = idev;

	/*
	 * iommufd_device_destroy() delays until idev->vdev is NULL before
	 * freeing the idev, which only happens once the vdev is finished
	 * destruction.
	 */
	idev->vdev = vdev;

	curr = xa_cmpxchg(&viommu->vdevs, virt_id, NULL, vdev, GFP_KERNEL);
	if (curr) {
		rc = xa_err(curr) ?: -EEXIST;
		goto out_abort;
	}

	if (viommu->ops && viommu->ops->vdevice_init) {
		rc = viommu->ops->vdevice_init(vdev);
		if (rc)
			goto out_abort;
	}

	cmd->out_vdevice_id = vdev->obj.id;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_abort;
	iommufd_object_finalize(ucmd->ictx, &vdev->obj);
	goto out_unlock_igroup;

out_abort:
	iommufd_object_abort_and_destroy(ucmd->ictx, &vdev->obj);
out_unlock_igroup:
	mutex_unlock(&idev->igroup->lock);
out_put_idev:
	if (rc)
		iommufd_put_object(ucmd->ictx, &idev->obj);
out_put_viommu:
	iommufd_put_object(ucmd->ictx, &viommu->obj);
	return rc;
}

static void iommufd_hw_queue_destroy_access(struct iommufd_ctx *ictx,
					    struct iommufd_access *access,
					    u64 base_iova, size_t length)
{
	u64 aligned_iova = PAGE_ALIGN_DOWN(base_iova);
	u64 offset = base_iova - aligned_iova;

	iommufd_access_unpin_pages(access, aligned_iova,
				   PAGE_ALIGN(length + offset));
	iommufd_access_detach_internal(access);
	iommufd_access_destroy_internal(ictx, access);
}

void iommufd_hw_queue_destroy(struct iommufd_object *obj)
{
	struct iommufd_hw_queue *hw_queue =
		container_of(obj, struct iommufd_hw_queue, obj);

	if (hw_queue->destroy)
		hw_queue->destroy(hw_queue);
	if (hw_queue->access)
		iommufd_hw_queue_destroy_access(hw_queue->viommu->ictx,
						hw_queue->access,
						hw_queue->base_addr,
						hw_queue->length);
	if (hw_queue->viommu)
		refcount_dec(&hw_queue->viommu->obj.users);
}

/*
 * When the HW accesses the guest queue via physical addresses, the underlying
 * physical pages of the guest queue must be contiguous. Also, for the security
 * concern that IOMMUFD_CMD_IOAS_UNMAP could potentially remove the mappings of
 * the guest queue from the nesting parent iopt while the HW is still accessing
 * the guest queue memory physically, such a HW queue must require an access to
 * pin the underlying pages and prevent that from happening.
 */
static struct iommufd_access *
iommufd_hw_queue_alloc_phys(struct iommu_hw_queue_alloc *cmd,
			    struct iommufd_viommu *viommu, phys_addr_t *base_pa)
{
	u64 aligned_iova = PAGE_ALIGN_DOWN(cmd->nesting_parent_iova);
	u64 offset = cmd->nesting_parent_iova - aligned_iova;
	struct iommufd_access *access;
	struct page **pages;
	size_t max_npages;
	size_t length;
	size_t i;
	int rc;

	/* max_npages = DIV_ROUND_UP(offset + cmd->length, PAGE_SIZE) */
	if (check_add_overflow(offset, cmd->length, &length))
		return ERR_PTR(-ERANGE);
	if (check_add_overflow(length, PAGE_SIZE - 1, &length))
		return ERR_PTR(-ERANGE);
	max_npages = length / PAGE_SIZE;
	/* length needs to be page aligned too */
	length = max_npages * PAGE_SIZE;

	/*
	 * Use kvcalloc() to avoid memory fragmentation for a large page array.
	 * Set __GFP_NOWARN to avoid syzkaller blowups
	 */
	pages = kvzalloc_objs(*pages, max_npages, GFP_KERNEL | __GFP_NOWARN);
	if (!pages)
		return ERR_PTR(-ENOMEM);

	access = iommufd_access_create_internal(viommu->ictx);
	if (IS_ERR(access)) {
		rc = PTR_ERR(access);
		goto out_free;
	}

	rc = iommufd_access_attach_internal(access, viommu->hwpt->ioas);
	if (rc)
		goto out_destroy;

	rc = iommufd_access_pin_pages(access, aligned_iova, length, pages, 0);
	if (rc)
		goto out_detach;

	/* Validate if the underlying physical pages are contiguous */
	for (i = 1; i < max_npages; i++) {
		if (page_to_pfn(pages[i]) == page_to_pfn(pages[i - 1]) + 1)
			continue;
		rc = -EFAULT;
		goto out_unpin;
	}

	*base_pa = (page_to_pfn(pages[0]) << PAGE_SHIFT) + offset;
	kvfree(pages);
	return access;

out_unpin:
	iommufd_access_unpin_pages(access, aligned_iova, length);
out_detach:
	iommufd_access_detach_internal(access);
out_destroy:
	iommufd_access_destroy_internal(viommu->ictx, access);
out_free:
	kvfree(pages);
	return ERR_PTR(rc);
}

static int _iommufd_hw_queue_init(struct iommufd_ucmd *ucmd,
				  struct iommufd_viommu *viommu)
{
	struct iommu_hw_queue_alloc *cmd = ucmd->cmd;
	struct iommufd_hw_queue *hw_queue;
	struct iommufd_access *access = NULL;
	phys_addr_t base_pa = 0;
	size_t hw_queue_size;
	int rc;

	if (!viommu->ops->hw_queue_init_phys && !viommu->ops->hw_queue_init)
		return -EOPNOTSUPP;

	hw_queue_size = viommu->ops->get_hw_queue_size(viommu, cmd->type);
	if (!hw_queue_size)
		return -EOPNOTSUPP;

	/*
	 * It is a driver bug for providing a hw_queue_size smaller than the
	 * core HW queue structure size
	 */
	if (WARN_ON_ONCE(hw_queue_size < sizeof(*hw_queue)))
		return -EOPNOTSUPP;

	hw_queue = (struct iommufd_hw_queue *)_iommufd_object_alloc_ucmd(
		ucmd, hw_queue_size, IOMMUFD_OBJ_HW_QUEUE);
	if (IS_ERR(hw_queue))
		return PTR_ERR(hw_queue);

	if (viommu->ops->hw_queue_init_phys) {
		access = iommufd_hw_queue_alloc_phys(cmd, viommu, &base_pa);
		if (IS_ERR(access))
			return PTR_ERR(access);
	}

	hw_queue->viommu = viommu;
	refcount_inc(&viommu->obj.users);
	hw_queue->access = access;
	hw_queue->type = cmd->type;
	hw_queue->flags = cmd->flags;
	hw_queue->length = cmd->length;
	hw_queue->base_addr = cmd->nesting_parent_iova;

	if (viommu->ops->hw_queue_init_phys)
		rc = viommu->ops->hw_queue_init_phys(hw_queue, cmd->index,
						     base_pa);
	else if (viommu->ops->hw_queue_init)
		rc = viommu->ops->hw_queue_init(hw_queue, cmd->index);
	else
		return -EOPNOTSUPP;

	if (rc)
		return rc;

	cmd->out_hw_queue_id = hw_queue->obj.id;
	return 0;
}

int iommufd_hw_queue_alloc_ioctl(struct iommufd_ucmd *ucmd)
{
	struct iommu_hw_queue_alloc *cmd = ucmd->cmd;
	struct iommufd_viommu *viommu;
	u64 last;
	int rc;

	if (cmd->type == IOMMU_HW_QUEUE_TYPE_DEFAULT)
		return -EOPNOTSUPP;
	if (!cmd->length)
		return -EINVAL;
	if (check_add_overflow(cmd->nesting_parent_iova, cmd->length - 1,
			       &last))
		return -EOVERFLOW;

	viommu = iommufd_get_viommu(ucmd, cmd->viommu_id);
	if (IS_ERR(viommu))
		return PTR_ERR(viommu);

	if (!viommu->ops || !viommu->ops->get_hw_queue_size) {
		rc = -EOPNOTSUPP;
		goto out_put_viommu;
	}

	rc = _iommufd_hw_queue_init(ucmd, viommu);
	if (rc)
		goto out_put_viommu;

	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));

out_put_viommu:
	iommufd_put_object(ucmd->ictx, &viommu->obj);
	return rc;
}

int iommufd_viommu_ext_int_remap_ioctl(struct iommufd_ucmd *ucmd)
{
	int rc;
	struct iommu_viommu_ext_int_remap *cmd = ucmd->cmd;
	struct iommufd_viommu *viommu;

	if (cmd->flags)
		return -EINVAL;

	if (cmd->__reserved)
		return -EINVAL;

	if (cmd->vector & ~0xFFU)
		return -EINVAL;

	viommu = iommufd_get_viommu(ucmd, cmd->object_id);
	if (IS_ERR(viommu))
		return PTR_ERR(viommu);

	if (!viommu->ops->set_ext_int_remap) {
		rc = -EOPNOTSUPP;
		goto out_put_viommu;
	}

	rc = viommu->ops->set_ext_int_remap(viommu, cmd);
out_put_viommu:
	iommufd_put_object(ucmd->ictx, &viommu->obj);
	return rc;
}

/*
 * Give up on an in-progress migration and put the vIOMMU back the way it was.
 * Used both for an explicit abort and for any step that fails partway, so that
 * a failure can never leave a vIOMMU quiesced with nothing driving it forward.
 */
static void iommufd_viommu_mig_unwind(struct iommufd_viommu *viommu)
{
	lockdep_assert_held(&viommu->mig_lock);

	viommu->ops->mig_abort(viommu);
	/* NONE follows every state, so this transition cannot be refused */
	viommu->mig_state = IOMMUFD_VIOMMU_MIG_NONE;
}

/*
 * Sizing is a query about the current contents, not a step in the sequence, so
 * it is allowed in any state. The figure is only stable once the vIOMMU has
 * been quiesced; before that it is an estimate, and IOMMU_VIOMMU_MIG_OP_SAVE
 * reports the size actually written.
 */
static int iommufd_viommu_mig_get_size(struct iommufd_viommu *viommu,
				       struct iommu_viommu_mig_state *cmd)
{
	size_t size;
	int rc;

	rc = viommu->ops->mig_get_size(viommu, &size);
	if (rc)
		return rc;
	/* A driver that cannot say how much it needs cannot be saved */
	if (WARN_ON_ONCE(!size))
		return -EINVAL;
	if (size > IOMMUFD_VIOMMU_MIG_PAYLOAD_MAX)
		return -EOVERFLOW;

	cmd->hdr_len = sizeof(struct iommu_viommu_mig_header);
	cmd->data_len = size;
	return 0;
}

static int iommufd_viommu_mig_prepare_save(struct iommufd_viommu *viommu,
					   struct iommu_viommu_mig_state *cmd)
{
	int rc;

	rc = iommufd_viommu_mig_enter(viommu, IOMMUFD_VIOMMU_MIG_PREPARED);
	if (rc)
		return rc;

	rc = viommu->ops->mig_prepare_save(viommu, cmd->timeout_ms,
					   &cmd->out_status);
	if (rc)
		iommufd_viommu_mig_unwind(viommu);
	return rc;
}

static int iommufd_viommu_mig_save(struct iommufd_viommu *viommu,
				   struct iommu_viommu_mig_state *cmd)
{
	const size_t hdr_size = sizeof(struct iommu_viommu_mig_header);
	struct iommu_viommu_mig_header hdr = {};
	size_t payload_len;
	void *payload;
	int rc;

	/*
	 * Check the sequence before the buffers, so that a caller that has not
	 * quiesced the vIOMMU is told that rather than being sent off to fix a
	 * buffer size that was never the problem.
	 */
	if (!iommufd_viommu_mig_may_enter(viommu->mig_state,
					  IOMMUFD_VIOMMU_MIG_SAVED))
		return -EINVAL;

	rc = viommu->ops->mig_get_size(viommu, &payload_len);
	if (rc)
		return rc;
	if (WARN_ON_ONCE(!payload_len))
		return -EINVAL;
	if (payload_len > IOMMUFD_VIOMMU_MIG_PAYLOAD_MAX)
		return -EOVERFLOW;

	/*
	 * Report what the caller needs and leave the state alone. A buffer
	 * that is too small is a sizing mistake the caller can correct, and
	 * throwing away a quiesced vIOMMU over it would force a needless
	 * re-drain.
	 */
	if (cmd->hdr_len < hdr_size || cmd->data_len < payload_len) {
		cmd->hdr_len = hdr_size;
		cmd->data_len = payload_len;
		return -EMSGSIZE;
	}

	rc = iommufd_viommu_mig_enter(viommu, IOMMUFD_VIOMMU_MIG_SAVED);
	if (rc)
		return rc;

	payload = kvzalloc(payload_len, GFP_KERNEL | __GFP_NOWARN);
	if (!payload) {
		rc = -ENOMEM;
		goto out_unwind;
	}

	rc = viommu->ops->mig_save(viommu, &hdr, payload, payload_len);
	if (rc)
		goto out_free;

	/* It is a driver bug to report writing more than it was given */
	if (WARN_ON_ONCE(!hdr.payload_size || hdr.payload_size > payload_len)) {
		rc = -EINVAL;
		goto out_free;
	}

	/*
	 * The core owns the field it validates on restore, so that a payload
	 * cannot be replayed into a vIOMMU of a different type however the
	 * driver fills the rest of the header in.
	 */
	hdr.blob_type = viommu->type;

	if (copy_to_user(u64_to_user_ptr(cmd->hdr_uptr), &hdr, hdr_size) ||
	    copy_to_user(u64_to_user_ptr(cmd->data_uptr), payload,
			 hdr.payload_size)) {
		rc = -EFAULT;
		goto out_free;
	}

	cmd->hdr_len = hdr_size;
	cmd->data_len = hdr.payload_size;

out_free:
	kvfree(payload);
out_unwind:
	if (rc)
		iommufd_viommu_mig_unwind(viommu);
	return rc;
}

static int iommufd_viommu_mig_restore(struct iommufd_viommu *viommu,
				      struct iommu_viommu_mig_state *cmd)
{
	const size_t hdr_size = sizeof(struct iommu_viommu_mig_header);
	struct iommu_viommu_mig_header hdr;
	void *payload;
	int rc;

	/* Reject an out-of-sequence call before copying anything in */
	if (!iommufd_viommu_mig_may_enter(viommu->mig_state,
					  IOMMUFD_VIOMMU_MIG_RESTORING))
		return -EINVAL;

	if (cmd->hdr_len < hdr_size || !cmd->data_len)
		return -EINVAL;
	if (cmd->data_len > IOMMUFD_VIOMMU_MIG_PAYLOAD_MAX)
		return -EOVERFLOW;

	if (copy_from_user(&hdr, u64_to_user_ptr(cmd->hdr_uptr), hdr_size))
		return -EFAULT;

	/*
	 * Check what the core can check before the driver sees any of it: an
	 * unknown reserved field means a payload from a kernel that knows more
	 * than this one, and the type and size have to agree with what the
	 * caller is actually handing over.
	 */
	if (memchr_inv(hdr.__reserved, 0, sizeof(hdr.__reserved)))
		return -EOPNOTSUPP;
	/*
	 * A feature flag is not a section: it says the payload depends on the
	 * destination doing something, so one this kernel has never heard of
	 * cannot be skipped the way an unknown section can. None are defined
	 * yet, which makes any bit here a payload from a newer kernel.
	 */
	if (hdr.feature_flags)
		return -EOPNOTSUPP;
	if (hdr.blob_type != viommu->type)
		return -EINVAL;
	if (hdr.payload_size != cmd->data_len)
		return -EINVAL;

	rc = iommufd_viommu_mig_enter(viommu, IOMMUFD_VIOMMU_MIG_RESTORING);
	if (rc)
		return rc;

	payload = kvzalloc(cmd->data_len, GFP_KERNEL | __GFP_NOWARN);
	if (!payload) {
		rc = -ENOMEM;
		goto out_unwind;
	}

	if (copy_from_user(payload, u64_to_user_ptr(cmd->data_uptr),
			   cmd->data_len)) {
		rc = -EFAULT;
		goto out_free;
	}

	rc = viommu->ops->mig_restore(viommu, &hdr, payload, cmd->data_len);

out_free:
	kvfree(payload);
out_unwind:
	if (rc)
		iommufd_viommu_mig_unwind(viommu);
	return rc;
}

static int iommufd_viommu_mig_commit_restore(struct iommufd_viommu *viommu)
{
	int rc;

	rc = iommufd_viommu_mig_enter(viommu, IOMMUFD_VIOMMU_MIG_COMMITTED);
	if (rc)
		return rc;

	rc = viommu->ops->mig_commit_restore(viommu);
	if (rc)
		iommufd_viommu_mig_unwind(viommu);
	return rc;
}

int iommufd_viommu_mig_state_ioctl(struct iommufd_ucmd *ucmd)
{
	struct iommu_viommu_mig_state *cmd = ucmd->cmd;
	struct iommufd_viommu *viommu;
	int respond_rc;
	int rc;

	if (cmd->flags)
		return -EOPNOTSUPP;

	viommu = iommufd_get_viommu(ucmd, cmd->viommu_id);
	if (IS_ERR(viommu))
		return PTR_ERR(viommu);

	if (!iommufd_viommu_mig_supported(viommu)) {
		rc = -EOPNOTSUPP;
		goto out_put_viommu;
	}

	cmd->out_status = 0;

	mutex_lock(&viommu->mig_lock);
	switch (cmd->op) {
	case IOMMU_VIOMMU_MIG_OP_GET_SIZE:
		rc = iommufd_viommu_mig_get_size(viommu, cmd);
		break;
	case IOMMU_VIOMMU_MIG_OP_PREPARE_SAVE:
		rc = iommufd_viommu_mig_prepare_save(viommu, cmd);
		break;
	case IOMMU_VIOMMU_MIG_OP_SAVE:
		rc = iommufd_viommu_mig_save(viommu, cmd);
		break;
	case IOMMU_VIOMMU_MIG_OP_RESTORE:
		rc = iommufd_viommu_mig_restore(viommu, cmd);
		break;
	case IOMMU_VIOMMU_MIG_OP_COMMIT_RESTORE:
		rc = iommufd_viommu_mig_commit_restore(viommu);
		break;
	case IOMMU_VIOMMU_MIG_OP_ABORT:
		iommufd_viommu_mig_unwind(viommu);
		rc = 0;
		break;
	default:
		rc = -EOPNOTSUPP;
		break;
	}
	mutex_unlock(&viommu->mig_lock);

	if (rc && rc != -EMSGSIZE)
		goto out_put_viommu;

	/*
	 * Respond on -EMSGSIZE too: the required buffer size is in the
	 * response and the caller has no other way to learn it.
	 */
	respond_rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (respond_rc)
		rc = respond_rc;

out_put_viommu:
	iommufd_put_object(ucmd->ictx, &viommu->obj);
	return rc;
}
