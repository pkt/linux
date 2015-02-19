#include "vigs_mman.h"
#include "vigs_fence.h"
#include <ttm/ttm_placement.h>

/*
 * This is TTM-based memory manager for VIGS, it supports 4 memory placements:
 * CPU - This is for target-only memory, not shared with host, forced by TTM,
 * not used.
 * GPU - This is host-only memory, not shared with target.
 * VRAM - This gets allocated on "VRAM" PCI BAR, shared with host, used
 * for surface placement.
 * RAM - This gets allocated on "RAM" PCI BAR, shared with host, used for
 * execbuffer placement.
 *
 * Eviction is supported, so buffers can be moved between some placements.
 * Allowed movements:
 * VRAM -> GPU
 * GPU -> VRAM
 */

/*
 * Offsets for mmap will start at DRM_FILE_OFFSET
 */
#define DRM_FILE_OFFSET 0x100000000ULL
#define DRM_FILE_PAGE_OFFSET (DRM_FILE_OFFSET >> PAGE_SHIFT)

/*
 * DRM_GLOBAL_TTM_MEM init/release thunks
 * @{
 */

static int vigs_ttm_mem_global_init(struct drm_global_reference *ref)
{
    return ttm_mem_global_init(ref->object);
}

static void vigs_ttm_mem_global_release(struct drm_global_reference *ref)
{
    ttm_mem_global_release(ref->object);
}

/*
 * @}
 */

/*
 * Here we initialize mman::bo_global_ref and mman::mem_global_ref.
 * This is required in order to bring up TTM bo subsystem and TTM memory
 * subsystem if they aren't already up. The first one who
 * calls 'drm_global_item_ref' automatically initializes the specified
 * subsystem and the last one who calls 'drm_global_item_unref' automatically
 * brings down the specified subsystem.
 * @{
 */

static int vigs_mman_global_init(struct vigs_mman *mman)
{
    struct drm_global_reference *global_ref = NULL;
    int ret = 0;

    global_ref = &mman->mem_global_ref;
    global_ref->global_type = DRM_GLOBAL_TTM_MEM;
    global_ref->size = sizeof(struct ttm_mem_global);
    global_ref->init = &vigs_ttm_mem_global_init;
    global_ref->release = &vigs_ttm_mem_global_release;

    ret = drm_global_item_ref(global_ref);

    if (ret != 0) {
        DRM_ERROR("failed setting up TTM memory subsystem: %d\n", ret);
        return ret;
    }

    mman->bo_global_ref.mem_glob = mman->mem_global_ref.object;
    global_ref = &mman->bo_global_ref.ref;
    global_ref->global_type = DRM_GLOBAL_TTM_BO;
    global_ref->size = sizeof(struct ttm_bo_global);
    global_ref->init = &ttm_bo_global_init;
    global_ref->release = &ttm_bo_global_release;

    ret = drm_global_item_ref(global_ref);

    if (ret != 0) {
        DRM_ERROR("failed setting up TTM bo subsystem: %d\n", ret);
        drm_global_item_unref(&mman->mem_global_ref);
        return ret;
    }

    return 0;
}

static void vigs_mman_global_cleanup(struct vigs_mman *mman)
{
    drm_global_item_unref(&mman->bo_global_ref.ref);
    drm_global_item_unref(&mman->mem_global_ref);
}

/*
 * @}
 */

/*
 * TTM backend functions.
 * @{
 */

static int vigs_ttm_backend_bind(struct ttm_tt *tt,
                                 struct ttm_mem_reg *bo_mem)
{
    return 0;
}

static int vigs_ttm_backend_unbind(struct ttm_tt *tt)
{
    return 0;
}

static void vigs_ttm_backend_destroy(struct ttm_tt *tt)
{
    struct ttm_dma_tt *dma_tt = (void*)tt;

    ttm_dma_tt_fini(dma_tt);
    kfree(dma_tt);
}

static struct ttm_backend_func vigs_ttm_backend_func = {
    .bind = &vigs_ttm_backend_bind,
    .unbind = &vigs_ttm_backend_unbind,
    .destroy = &vigs_ttm_backend_destroy,
};

static struct ttm_tt *vigs_ttm_tt_create(struct ttm_bo_device *bo_dev,
                                         unsigned long size,
                                         uint32_t page_flags,
                                         struct page *dummy_read_page)
{
    struct ttm_dma_tt *dma_tt;
    int ret;

    dma_tt = kzalloc(sizeof(struct ttm_dma_tt), GFP_KERNEL);

    if (dma_tt == NULL) {
        DRM_ERROR("cannot allocate ttm_dma_tt: OOM\n");
        return NULL;
    }

    dma_tt->ttm.func = &vigs_ttm_backend_func;

    ret = ttm_dma_tt_init(dma_tt, bo_dev, size, page_flags,
                          dummy_read_page);

    if (ret != 0) {
        DRM_ERROR("ttm_dma_tt_init failed: %d\n", ret);
        kfree(dma_tt);
        return NULL;
    }

    return &dma_tt->ttm;
}

static int vigs_ttm_tt_populate(struct ttm_tt *tt)
{
    return 0;
}

static void vigs_ttm_tt_unpopulate(struct ttm_tt *tt)
{
}

/*
 * @}
 */

static int vigs_ttm_invalidate_caches(struct ttm_bo_device *bo_dev,
                                      uint32_t flags)
{
    return 0;
}

static int vigs_ttm_init_mem_type(struct ttm_bo_device *bo_dev,
                                  uint32_t type,
                                  struct ttm_mem_type_manager *man)
{
    switch (type) {
    case TTM_PL_SYSTEM:
        man->flags = TTM_MEMTYPE_FLAG_MAPPABLE;
        man->available_caching = TTM_PL_MASK_CACHING;
        man->default_caching = TTM_PL_FLAG_CACHED;
        break;
    case TTM_PL_TT:
        man->func = &ttm_bo_manager_func;
        man->gpu_offset = 0;
        man->flags = TTM_MEMTYPE_FLAG_MAPPABLE |
                     TTM_MEMTYPE_FLAG_CMA;
        man->available_caching = TTM_PL_MASK_CACHING;
        man->default_caching = TTM_PL_FLAG_CACHED;
        break;
    case TTM_PL_VRAM:
    case TTM_PL_PRIV0:
        man->func = &ttm_bo_manager_func;
        man->gpu_offset = 0;
        man->flags = TTM_MEMTYPE_FLAG_FIXED |
                     TTM_MEMTYPE_FLAG_MAPPABLE;
        man->available_caching = TTM_PL_MASK_CACHING;
        man->default_caching = TTM_PL_FLAG_CACHED;
        break;
    default:
        DRM_ERROR("unsupported memory type: %u\n", (unsigned)type);
        return -EINVAL;
    }
    return 0;
}

static const u32 evict_placements[1] =
{
    TTM_PL_FLAG_CACHED | TTM_PL_FLAG_TT | TTM_PL_FLAG_NO_EVICT
};

static const struct ttm_placement evict_placement =
{
    .fpfn = 0,
    .lpfn = 0,
    .num_placement = ARRAY_SIZE(evict_placements),
    .placement = evict_placements,
    .num_busy_placement = ARRAY_SIZE(evict_placements),
    .busy_placement = evict_placements
};

static void vigs_ttm_evict_flags(struct ttm_buffer_object *bo,
                                 struct ttm_placement *placement)
{
    BUG_ON(bo->mem.mem_type != TTM_PL_VRAM);

    *placement = evict_placement;
}

static int vigs_ttm_move(struct ttm_buffer_object *bo,
                         bool evict,
                         bool interruptible,
                         bool no_wait_gpu,
                         struct ttm_mem_reg *new_mem)
{
    struct vigs_mman *mman = bo_dev_to_vigs_mman(bo->bdev);
    struct ttm_mem_reg *old_mem = &bo->mem;

    if ((old_mem->mem_type == TTM_PL_VRAM) &&
        (new_mem->mem_type == TTM_PL_TT)) {
        mman->ops->vram_to_gpu(mman->user_data, bo);

        ttm_bo_mem_put(bo, old_mem);

        *old_mem = *new_mem;
        new_mem->mm_node = NULL;

        return 0;
    } else if ((old_mem->mem_type == TTM_PL_TT) &&
               (new_mem->mem_type == TTM_PL_VRAM)) {
        mman->ops->gpu_to_vram(mman->user_data, bo,
                               (new_mem->start << PAGE_SHIFT) +
                               bo->bdev->man[new_mem->mem_type].gpu_offset);

        ttm_bo_mem_put(bo, old_mem);

        *old_mem = *new_mem;
        new_mem->mm_node = NULL;

        return 0;
    } else {
        return ttm_bo_move_memcpy(bo, evict, no_wait_gpu, new_mem);
    }
}

static int vigs_ttm_verify_access(struct ttm_buffer_object *bo,
                                  struct file *filp)
{
    return 0;
}

static bool vigs_ttm_sync_obj_signaled(void *sync_obj)
{
    return vigs_fence_signaled((struct vigs_fence*)sync_obj);
}

static int vigs_ttm_sync_obj_wait(void *sync_obj,
                                  bool lazy,
                                  bool interruptible)
{
    return vigs_fence_wait((struct vigs_fence*)sync_obj, interruptible);
}

static int vigs_ttm_sync_obj_flush(void *sync_obj)
{
    return 0;
}

static void vigs_ttm_sync_obj_unref(void **sync_obj)
{
    struct vigs_fence* fence = *sync_obj;
    vigs_fence_unref(fence);
    *sync_obj = NULL;
}

static void *vigs_ttm_sync_obj_ref(void *sync_obj)
{
    vigs_fence_ref((struct vigs_fence*)sync_obj);
    return sync_obj;
}

static int vigs_ttm_fault_reserve_notify(struct ttm_buffer_object *bo)
{
    u32 placements[1];
    struct ttm_placement placement;
    int ret;

    if (bo->mem.mem_type != TTM_PL_TT) {
        /*
         * We're only interested in GPU memory page faults.
         */

        return 0;
    }

    /*
     * It's GPU memory page fault. Move this buffer into VRAM.
     */

    placements[0] = TTM_PL_FLAG_CACHED | TTM_PL_FLAG_VRAM;

    memset(&placement, 0, sizeof(placement));

    placement.placement = placements;
    placement.busy_placement = placements;
    placement.num_placement = 1;
    placement.num_busy_placement = 1;

    ret = ttm_bo_validate(bo, &placement, false, false);

    if (ret != 0) {
        DRM_ERROR("movement failed for 0x%llX\n",
                  drm_vma_node_offset_addr(&bo->vma_node));
        return ret;
    }

    return 0;
}

static int vigs_ttm_io_mem_reserve(struct ttm_bo_device *bo_dev,
                                   struct ttm_mem_reg *mem)
{
    struct ttm_mem_type_manager *man = &bo_dev->man[mem->mem_type];
    struct vigs_mman *mman = bo_dev_to_vigs_mman(bo_dev);

    mem->bus.addr = NULL;
    mem->bus.offset = 0;
    mem->bus.size = mem->num_pages << PAGE_SHIFT;
    mem->bus.base = 0;
    mem->bus.is_iomem = false;

    if (!(man->flags & TTM_MEMTYPE_FLAG_MAPPABLE)) {
        return -EINVAL;
    }

    switch (mem->mem_type) {
    case TTM_PL_SYSTEM:
    case TTM_PL_TT:
        break;
    case TTM_PL_VRAM:
        mem->bus.is_iomem = true;
        mem->bus.base = mman->vram_base;
        mem->bus.offset = mem->start << PAGE_SHIFT;
        break;
    case TTM_PL_PRIV0:
        mem->bus.is_iomem = true;
        mem->bus.base = mman->ram_base;
        mem->bus.offset = mem->start << PAGE_SHIFT;
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

static void vigs_ttm_io_mem_free(struct ttm_bo_device *bo_dev,
                                 struct ttm_mem_reg *mem)
{
}

static struct ttm_bo_driver vigs_ttm_bo_driver =
{
    .ttm_tt_create = &vigs_ttm_tt_create, /* Needed for ttm_bo_type_kernel and TTM_PL_TT */
    .ttm_tt_populate = &vigs_ttm_tt_populate, /* Needed for TTM_PL_TT */
    .ttm_tt_unpopulate = &vigs_ttm_tt_unpopulate, /* Needed for TTM_PL_TT */
    .invalidate_caches = &vigs_ttm_invalidate_caches,
    .init_mem_type = &vigs_ttm_init_mem_type,
    .evict_flags = &vigs_ttm_evict_flags,
    .move = &vigs_ttm_move,
    .verify_access = &vigs_ttm_verify_access,
    .sync_obj_signaled = vigs_ttm_sync_obj_signaled,
    .sync_obj_wait = vigs_ttm_sync_obj_wait,
    .sync_obj_flush = vigs_ttm_sync_obj_flush,
    .sync_obj_unref = vigs_ttm_sync_obj_unref,
    .sync_obj_ref = vigs_ttm_sync_obj_ref,
    .fault_reserve_notify = &vigs_ttm_fault_reserve_notify,
    .io_mem_reserve = &vigs_ttm_io_mem_reserve,
    .io_mem_free = &vigs_ttm_io_mem_free,
};

/*
 * VMA related.
 * @{
 */

static u32 vigs_vma_cache_index = 0;
static struct vm_operations_struct vigs_ttm_vm_ops;
static const struct vm_operations_struct *ttm_vm_ops = NULL;

/*
 * Represents per-VMA data.
 *
 * Since TTM already uses struct vm_area_struct::vm_private_data
 * we're forced to use some other way to add our own data
 * to VMA. Currently we use struct vm_area_struct::vm_ops for this.
 * Generally, TTM should be refactored to not use
 * struct vm_area_struct directly, but provide helper functions
 * instead so that user could store whatever he wants into
 * struct vm_area_struct::vm_private_data.
 */
struct vigs_mman_vma
{
    struct vm_operations_struct vm_ops;
    struct ttm_buffer_object *bo;
    struct kref kref;
    u8 data[1];
};

static void vigs_mman_vma_release(struct kref *kref)
{
    struct vigs_mman_vma *vigs_vma =
        container_of(kref, struct vigs_mman_vma, kref);
    struct ttm_buffer_object *bo = vigs_vma->bo;
    struct vigs_mman *mman = bo_dev_to_vigs_mman(bo->bdev);

    mman->ops->cleanup_vma(mman->user_data, &vigs_vma->data[0]);

    kmem_cache_free(mman->vma_cache, vigs_vma);
}

/*
 * @}
 */

int vigs_mman_create(resource_size_t vram_base,
                     resource_size_t vram_size,
                     resource_size_t ram_base,
                     resource_size_t ram_size,
                     uint32_t vma_data_size,
                     struct vigs_mman_ops *ops,
                     void *user_data,
                     struct vigs_mman **mman)
{
    int ret = 0;
    char vma_cache_name[100];
    unsigned long num_pages = 0;

    DRM_DEBUG_DRIVER("enter\n");

    BUG_ON(vma_data_size <= 0);

    *mman = kzalloc(sizeof(**mman), GFP_KERNEL);

    if (!*mman) {
        ret = -ENOMEM;
        goto fail1;
    }

    sprintf(vma_cache_name, "vigs_vma_cache%u", vigs_vma_cache_index++);

    (*mman)->vma_cache = kmem_cache_create(vma_cache_name,
                                           sizeof(struct vigs_mman_vma) +
                                           vma_data_size - 1,
                                           0, 0, NULL);

    if (!(*mman)->vma_cache) {
        ret = -ENOMEM;
        goto fail2;
    }

    ret = vigs_mman_global_init(*mman);

    if (ret != 0) {
        goto fail3;
    }

    (*mman)->vram_base = vram_base;
    (*mman)->ram_base = ram_base;
    (*mman)->ops = ops;
    (*mman)->user_data = user_data;

    ret = ttm_bo_device_init(&(*mman)->bo_dev,
                             (*mman)->bo_global_ref.ref.object,
                             &vigs_ttm_bo_driver,
                             DRM_FILE_PAGE_OFFSET,
                             0);
    if (ret != 0) {
        DRM_ERROR("failed initializing bo driver: %d\n", ret);
        goto fail4;
    }

    /*
     * Init GPU
     * @{
     */

    /*
     * For GPU we're only limited by host resources, let the target create
     * as many buffers as it likes.
     */
    ret = ttm_bo_init_mm(&(*mman)->bo_dev,
                         TTM_PL_TT,
                         (0xFFFFFFFFUL / PAGE_SIZE));
    if (ret != 0) {
        DRM_ERROR("failed initializing GPU mm\n");
        goto fail5;
    }

    /*
     * @}
     */

    /*
     * Init VRAM
     * @{
     */

    num_pages = vram_size / PAGE_SIZE;

    ret = ttm_bo_init_mm(&(*mman)->bo_dev,
                         TTM_PL_VRAM,
                         num_pages);
    if (ret != 0) {
        DRM_ERROR("failed initializing VRAM mm\n");
        goto fail6;
    }

    /*
     * @}
     */

    /*
     * Init RAM
     * @{
     */

    num_pages = ram_size / PAGE_SIZE;

    ret = ttm_bo_init_mm(&(*mman)->bo_dev,
                         TTM_PL_PRIV0,
                         num_pages);
    if (ret != 0) {
        DRM_ERROR("failed initializing RAM mm\n");
        goto fail7;
    }

    /*
     * @}
     */

    return 0;

fail7:
    ttm_bo_clean_mm(&(*mman)->bo_dev, TTM_PL_VRAM);
fail6:
    ttm_bo_clean_mm(&(*mman)->bo_dev, TTM_PL_TT);
fail5:
    ttm_bo_device_release(&(*mman)->bo_dev);
fail4:
    vigs_mman_global_cleanup(*mman);
fail3:
    kmem_cache_destroy((*mman)->vma_cache);
fail2:
    kfree(*mman);
fail1:
    *mman = NULL;

    return ret;
}

void vigs_mman_destroy(struct vigs_mman *mman)
{
    DRM_DEBUG_DRIVER("enter\n");

    ttm_bo_clean_mm(&mman->bo_dev, TTM_PL_PRIV0);
    ttm_bo_clean_mm(&mman->bo_dev, TTM_PL_VRAM);
    ttm_bo_clean_mm(&mman->bo_dev, TTM_PL_TT);
    ttm_bo_device_release(&mman->bo_dev);
    vigs_mman_global_cleanup(mman);
    kmem_cache_destroy(mman->vma_cache);

    kfree(mman);
}

static void vigs_ttm_open(struct vm_area_struct *vma)
{
    struct vigs_mman_vma *vigs_vma = (struct vigs_mman_vma*)vma->vm_ops;

    BUG_ON(vigs_vma->bo != (struct ttm_buffer_object*)vma->vm_private_data);

    ttm_vm_ops->open(vma);
    kref_get(&vigs_vma->kref);
}

static void vigs_ttm_close(struct vm_area_struct *vma)
{
    struct vigs_mman_vma *vigs_vma = (struct vigs_mman_vma*)vma->vm_ops;

    BUG_ON(vigs_vma->bo != (struct ttm_buffer_object*)vma->vm_private_data);

    vma->vm_ops = &vigs_ttm_vm_ops;

    kref_put(&vigs_vma->kref, &vigs_mman_vma_release);
    ttm_vm_ops->close(vma);
}

static int vigs_ttm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    struct ttm_buffer_object *bo = vma->vm_private_data;

    if (bo == NULL) {
        return VM_FAULT_NOPAGE;
    }

    return ttm_vm_ops->fault(vma, vmf);
}

int vigs_mman_mmap(struct vigs_mman *mman,
                   struct file *filp,
                   struct vm_area_struct *vma,
                   bool track_access)
{
    struct vigs_mman_vma *vigs_vma;
    int ret;
    struct ttm_buffer_object *bo;

    if (unlikely(vma->vm_pgoff < DRM_FILE_PAGE_OFFSET)) {
        return drm_mmap(filp, vma);
    }

    vigs_vma = kmem_cache_alloc(mman->vma_cache, GFP_KERNEL);

    if (!vigs_vma) {
        return -ENOMEM;
    }

    ret = ttm_bo_mmap(filp, vma, &mman->bo_dev);

    if (unlikely(ret != 0)) {
        kmem_cache_free(mman->vma_cache, vigs_vma);
        return ret;
    }

    if (unlikely(ttm_vm_ops == NULL)) {
        ttm_vm_ops = vma->vm_ops;
        vigs_ttm_vm_ops = *ttm_vm_ops;
        vigs_ttm_vm_ops.fault = &vigs_ttm_fault;
    }

    bo = vma->vm_private_data;

    vigs_vma->vm_ops = vigs_ttm_vm_ops;
    vigs_vma->bo = bo;
    vigs_vma->vm_ops.open = &vigs_ttm_open;
    vigs_vma->vm_ops.close = &vigs_ttm_close;
    kref_init(&vigs_vma->kref);
    mman->ops->init_vma(mman->user_data,
                        &vigs_vma->data[0],
                        bo,
                        track_access);

    vma->vm_ops = &vigs_vma->vm_ops;

    return 0;
}

int vigs_mman_access_vma(struct vigs_mman *mman,
                         unsigned long address,
                         vigs_mman_access_vma_func func,
                         void *user_data)
{
    struct mm_struct *mm = current->mm;
    struct vm_area_struct *vma;
    int ret;
    struct ttm_buffer_object *bo;
    struct vigs_mman_vma *vigs_vma;

    down_read(&mm->mmap_sem);

    vma = find_vma(mm, address);

    if (!vma ||
        !vma->vm_ops ||
        (vma->vm_ops->fault != &vigs_ttm_fault)) {
        ret = -ENOENT;
        goto out;
    }

    bo = vma->vm_private_data;

    BUG_ON(!bo);

    if (bo->bdev != &mman->bo_dev) {
        ret = -ENOENT;
        goto out;
    }

    vigs_vma = (struct vigs_mman_vma*)vma->vm_ops;

    ret = func(user_data, &vigs_vma->data[0]);

out:
    up_read(&mm->mmap_sem);

    return ret;
}
