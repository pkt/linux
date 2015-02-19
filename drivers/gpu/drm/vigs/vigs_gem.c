#include "vigs_gem.h"
#include "vigs_device.h"
#include "vigs_mman.h"
#include "vigs_surface.h"
#include "vigs_dp.h"
#include <drm/vigs_drm.h>
#include <ttm/ttm_placement.h>

static void vigs_gem_bo_destroy(struct ttm_buffer_object *bo)
{
    struct vigs_gem_object *vigs_gem = bo_to_vigs_gem(bo);

    if (vigs_gem->destroy) {
        vigs_gem->destroy(vigs_gem);
    }

    drm_gem_object_release(&vigs_gem->base);
    kfree(vigs_gem);
}

int vigs_gem_init(struct vigs_gem_object *vigs_gem,
                  struct vigs_device *vigs_dev,
                  enum ttm_object_type type,
                  unsigned long size,
                  bool kernel,
                  vigs_gem_destroy_func destroy)
{
    u32 placements[1];
    struct ttm_placement placement;
    enum ttm_bo_type bo_type;
    int ret = 0;

    size = roundup(size, PAGE_SIZE);

    if (size == 0) {
        kfree(vigs_gem);
        return -EINVAL;
    }

    if (type == VIGS_GEM_TYPE_SURFACE) {
        placements[0] =
            TTM_PL_FLAG_CACHED | TTM_PL_FLAG_TT | TTM_PL_FLAG_NO_EVICT;
    } else if (type == VIGS_GEM_TYPE_EXECBUFFER) {
        placements[0] =
            TTM_PL_FLAG_CACHED | TTM_PL_FLAG_PRIV0 | TTM_PL_FLAG_NO_EVICT;
    } else {
        kfree(vigs_gem);
        return -EINVAL;
    }

    memset(&placement, 0, sizeof(placement));

    placement.placement = placements;
    placement.busy_placement = placements;
    placement.num_placement = 1;
    placement.num_busy_placement = 1;

    if (kernel) {
        bo_type = ttm_bo_type_kernel;
    } else {
        bo_type = ttm_bo_type_device;
    }

    if (unlikely(vigs_dev->mman->bo_dev.dev_mapping == NULL)) {
        vigs_dev->mman->bo_dev.dev_mapping = vigs_dev->drm_dev->dev_mapping;
    }

    ret = drm_gem_object_init(vigs_dev->drm_dev, &vigs_gem->base, size);

    if (ret != 0) {
        kfree(vigs_gem);
        return ret;
    }

    ret = ttm_bo_init(&vigs_dev->mman->bo_dev, &vigs_gem->bo, size, bo_type,
                      &placement, 0,
                      false, NULL, 0, NULL,
                      &vigs_gem_bo_destroy);

    if (ret != 0) {
        return ret;
    }

    vigs_gem->type = type;
    vigs_gem->pin_count = 0;
    vigs_gem->destroy = destroy;

    DRM_DEBUG_DRIVER("GEM created (type = %u, off = 0x%llX, sz = %lu)\n",
                     type,
                     vigs_gem_mmap_offset(vigs_gem),
                     vigs_gem_size(vigs_gem));

    return 0;
}

void vigs_gem_cleanup(struct vigs_gem_object *vigs_gem)
{
    struct ttm_buffer_object *bo = &vigs_gem->bo;

    ttm_bo_unref(&bo);
}

int vigs_gem_pin(struct vigs_gem_object *vigs_gem)
{
    u32 placements[1];
    struct ttm_placement placement;
    int ret;

    if (vigs_gem->pin_count) {
        ++vigs_gem->pin_count;
        return 0;
    }

    if (vigs_gem->type == VIGS_GEM_TYPE_EXECBUFFER) {
        vigs_gem->pin_count = 1;

        return 0;
    }

    placements[0] =
        TTM_PL_FLAG_CACHED | TTM_PL_FLAG_VRAM | TTM_PL_FLAG_NO_EVICT;

    memset(&placement, 0, sizeof(placement));

    placement.placement = placements;
    placement.busy_placement = placements;
    placement.num_placement = 1;
    placement.num_busy_placement = 1;

    ret = ttm_bo_validate(&vigs_gem->bo, &placement, false, false);

    if (ret != 0) {
        DRM_ERROR("GEM pin failed (type = %u, off = 0x%llX, sz = %lu)\n",
                  vigs_gem->type,
                  vigs_gem_mmap_offset(vigs_gem),
                  vigs_gem_size(vigs_gem));
        return ret;
    }

    vigs_gem->pin_count = 1;

    DRM_DEBUG_DRIVER("GEM pinned (type = %u, off = 0x%llX, sz = %lu)\n",
                     vigs_gem->type,
                     vigs_gem_mmap_offset(vigs_gem),
                     vigs_gem_size(vigs_gem));

    return 0;
}

void vigs_gem_unpin(struct vigs_gem_object *vigs_gem)
{
    u32 placements[2];
    struct ttm_placement placement;
    int ret;

    BUG_ON(vigs_gem->pin_count == 0);

    if (--vigs_gem->pin_count > 0) {
        return;
    }

    if (vigs_gem->type == VIGS_GEM_TYPE_EXECBUFFER) {
        return;
    }

    vigs_gem_kunmap(vigs_gem);

    placements[0] =
        TTM_PL_FLAG_CACHED | TTM_PL_FLAG_VRAM;
    placements[1] =
        TTM_PL_FLAG_CACHED | TTM_PL_FLAG_TT | TTM_PL_FLAG_NO_EVICT;

    memset(&placement, 0, sizeof(placement));

    placement.placement = placements;
    placement.busy_placement = placements;
    placement.num_placement = 2;
    placement.num_busy_placement = 2;

    ret = ttm_bo_validate(&vigs_gem->bo, &placement, false, false);

    if (ret != 0) {
        DRM_ERROR("GEM unpin failed (type = %u, off = 0x%llX, sz = %lu)\n",
                  vigs_gem->type,
                  vigs_gem_mmap_offset(vigs_gem),
                  vigs_gem_size(vigs_gem));
    } else {
        DRM_DEBUG_DRIVER("GEM unpinned (type = %u, off = 0x%llX, sz = %lu)\n",
                         vigs_gem->type,
                         vigs_gem_mmap_offset(vigs_gem),
                         vigs_gem_size(vigs_gem));
    }
}

int vigs_gem_kmap(struct vigs_gem_object *vigs_gem)
{
    bool is_iomem;
    int ret;

    BUG_ON((vigs_gem->type == VIGS_GEM_TYPE_SURFACE) &&
           (vigs_gem->pin_count == 0));

    if (vigs_gem->kptr) {
        return 0;
    }

    ret = ttm_bo_kmap(&vigs_gem->bo,
                      0,
                      vigs_gem->bo.num_pages,
                      &vigs_gem->kmap);

    if (ret != 0) {
        return ret;
    }

    vigs_gem->kptr = ttm_kmap_obj_virtual(&vigs_gem->kmap, &is_iomem);

    DRM_DEBUG_DRIVER("GEM (type = %u, off = 0x%llX, sz = %lu) mapped to 0x%p\n",
                     vigs_gem->type,
                     vigs_gem_mmap_offset(vigs_gem),
                     vigs_gem_size(vigs_gem),
                     vigs_gem->kptr);

    return 0;
}

void vigs_gem_kunmap(struct vigs_gem_object *vigs_gem)
{
    if (vigs_gem->kptr == NULL) {
        return;
    }

    vigs_gem->kptr = NULL;

    ttm_bo_kunmap(&vigs_gem->kmap);

    DRM_DEBUG_DRIVER("GEM (type = %u, off = 0x%llX, sz = %lu) unmapped\n",
                     vigs_gem->type,
                     vigs_gem_mmap_offset(vigs_gem),
                     vigs_gem_size(vigs_gem));
}

int vigs_gem_in_vram(struct vigs_gem_object *vigs_gem)
{
    return vigs_gem->bo.mem.mem_type == TTM_PL_VRAM;
}

int vigs_gem_wait(struct vigs_gem_object *vigs_gem)
{
    int ret;

    spin_lock(&vigs_gem->bo.bdev->fence_lock);

    ret = ttm_bo_wait(&vigs_gem->bo, true, false, false);

    spin_unlock(&vigs_gem->bo.bdev->fence_lock);

    return ret;
}

void vigs_gem_free_object(struct drm_gem_object *gem)
{
    struct vigs_gem_object *vigs_gem = gem_to_vigs_gem(gem);

    if (vigs_gem->type == VIGS_GEM_TYPE_SURFACE) {
        struct vigs_device *vigs_dev = gem->dev->dev_private;

        vigs_dp_remove_surface(vigs_dev->dp,
                               vigs_gem_to_vigs_surface(vigs_gem));
    }

    vigs_gem_reserve(vigs_gem);

    vigs_gem_kunmap(vigs_gem);

    vigs_gem_unreserve(vigs_gem);

    vigs_gem->freed = true;

    DRM_DEBUG_DRIVER("GEM free (type = %u, off = 0x%llX, sz = %lu)\n",
                     vigs_gem->type,
                     vigs_gem_mmap_offset(vigs_gem),
                     vigs_gem_size(vigs_gem));

    vigs_gem_cleanup(vigs_gem);
}

int vigs_gem_init_object(struct drm_gem_object *gem)
{
    return 0;
}

int vigs_gem_open_object(struct drm_gem_object *gem,
                         struct drm_file *file_priv)
{
    return 0;
}

void vigs_gem_close_object(struct drm_gem_object *gem,
                           struct drm_file *file_priv)
{
}

int vigs_gem_map_ioctl(struct drm_device *drm_dev,
                       void *data,
                       struct drm_file *file_priv)
{
    struct vigs_device *vigs_dev = drm_dev->dev_private;
    struct drm_vigs_gem_map *args = data;
    struct drm_gem_object *gem;
    struct vigs_gem_object *vigs_gem;
    struct mm_struct *mm = current->mm;
    unsigned long address, unused;

    gem = drm_gem_object_lookup(drm_dev, file_priv, args->handle);

    if (gem == NULL) {
        return -ENOENT;
    }

    vigs_gem = gem_to_vigs_gem(gem);

    down_write(&mm->mmap_sem);

    /*
     * We can't use 'do_mmap' here (like in i915, exynos and others) because
     * 'do_mmap' takes an offset in bytes and our
     * offset is 64-bit (since it's TTM offset) and it can't fit into 32-bit
     * variable.
     */
    vigs_dev->track_gem_access = args->track_access;
    address = do_mmap_pgoff(file_priv->filp, 0, vigs_gem_size(vigs_gem),
                            PROT_READ | PROT_WRITE,
                            MAP_SHARED,
                            vigs_gem_mmap_offset(vigs_gem) >> PAGE_SHIFT,
                            &unused);
    vigs_dev->track_gem_access = false;

    up_write(&mm->mmap_sem);

    drm_gem_object_unreference_unlocked(gem);

    if (IS_ERR((void*)address)) {
        return PTR_ERR((void*)address);
    }

    args->address = address;

    return 0;
}

int vigs_gem_wait_ioctl(struct drm_device *drm_dev,
                        void *data,
                        struct drm_file *file_priv)
{
    struct drm_vigs_gem_wait *args = data;
    struct drm_gem_object *gem;
    struct vigs_gem_object *vigs_gem;
    int ret;

    gem = drm_gem_object_lookup(drm_dev, file_priv, args->handle);

    if (gem == NULL) {
        return -ENOENT;
    }

    vigs_gem = gem_to_vigs_gem(gem);

    vigs_gem_reserve(vigs_gem);

    ret = vigs_gem_wait(vigs_gem);

    vigs_gem_unreserve(vigs_gem);

    drm_gem_object_unreference_unlocked(gem);

    return ret;
}

int vigs_gem_dumb_create(struct drm_file *file_priv,
                         struct drm_device *drm_dev,
                         struct drm_mode_create_dumb *args)
{
    struct vigs_device *vigs_dev = drm_dev->dev_private;
    struct vigs_surface *sfc = NULL;
    uint32_t handle;
    int ret;

    if (args->bpp != 32) {
        DRM_ERROR("Only 32 bpp surfaces are supported for now\n");
        return -EINVAL;
    }

    args->pitch = args->width * ((args->bpp + 7) / 8);

    ret = vigs_surface_create(vigs_dev,
                              args->width,
                              args->height,
                              args->pitch,
                              vigsp_surface_bgrx8888,
                              true,
                              &sfc);

    if (ret != 0) {
        return ret;
    }

    args->size = vigs_gem_size(&sfc->gem);

    ret = drm_gem_handle_create(file_priv,
                                &sfc->gem.base,
                                &handle);

    drm_gem_object_unreference_unlocked(&sfc->gem.base);

    if (ret == 0) {
        args->handle = handle;
    }

    return 0;
}

int vigs_gem_dumb_destroy(struct drm_file *file_priv,
                          struct drm_device *drm_dev,
                          uint32_t handle)
{
    return drm_gem_handle_delete(file_priv, handle);
}

int vigs_gem_dumb_map_offset(struct drm_file *file_priv,
                             struct drm_device *drm_dev,
                             uint32_t handle, uint64_t *offset_p)
{
    struct drm_gem_object *gem;
    struct vigs_gem_object *vigs_gem;

    BUG_ON(!offset_p);

    gem = drm_gem_object_lookup(drm_dev, file_priv, handle);

    if (gem == NULL) {
        return -ENOENT;
    }

    vigs_gem = gem_to_vigs_gem(gem);

    *offset_p = vigs_gem_mmap_offset(vigs_gem);

    drm_gem_object_unreference_unlocked(gem);

    return 0;
}
