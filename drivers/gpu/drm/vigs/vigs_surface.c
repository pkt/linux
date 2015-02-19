#include "vigs_surface.h"
#include "vigs_device.h"
#include "vigs_comm.h"
#include "vigs_mman.h"
#include <drm/vigs_drm.h>

/*
 * Functions below MUST be accessed between
 * vigs_gem_reserve/vigs_gem_unreserve.
 * @{
 */

static u32 vigs_surface_saf(struct vigs_surface *sfc)
{
    u32 saf = 0;

    if (sfc->num_readers > 0) {
        saf |= DRM_VIGS_SAF_READ;
    }

    if (sfc->num_writers > 0) {
        saf |= DRM_VIGS_SAF_WRITE;
    }

    return saf;
}

static void vigs_surface_saf_changed(struct vigs_surface *sfc,
                                     u32 old_saf)
{
    u32 new_saf = vigs_surface_saf(sfc);

    if (old_saf == new_saf) {
        return;
    }

    /*
     * If we're in GPU and access is write-only then we can
     * obviously skip first VRAM update, since there's nothing
     * to read back yet. After first VRAM update, however, we must
     * read back every time since the clients must see their
     * changes.
     */

    sfc->skip_vram_update = !vigs_gem_in_vram(&sfc->gem) &&
                            (new_saf == DRM_VIGS_SAF_WRITE) &&
                            !(old_saf & DRM_VIGS_SAF_WRITE);
}

static void vigs_vma_data_end_access(struct vigs_vma_data *vma_data, bool sync)
{
    struct vigs_surface *sfc = vma_data->sfc;
    struct vigs_device *vigs_dev = sfc->gem.base.dev->dev_private;
    u32 old_saf = vigs_surface_saf(sfc);

    if (vma_data->saf & DRM_VIGS_SAF_READ) {
        --sfc->num_readers;
    }

    if ((vma_data->saf & DRM_VIGS_SAF_WRITE) == 0) {
        goto out;
    }

    if (sync) {
        /*
         * We have a sync, drop all pending
         * writers.
         */
        sfc->num_writers -= sfc->num_pending_writers;
        sfc->num_pending_writers = 0;
    }

    if (!vigs_gem_in_vram(&sfc->gem)) {
        --sfc->num_writers;
        goto out;
    }

    if (sync) {
        --sfc->num_writers;
        vigs_comm_update_gpu(vigs_dev->comm,
                             sfc->id,
                             sfc->width,
                             sfc->height,
                             vigs_gem_offset(&sfc->gem));
        sfc->is_gpu_dirty = false;
    } else {
        ++sfc->num_pending_writers;
    }

out:
    vma_data->saf = 0;

    vigs_surface_saf_changed(sfc, old_saf);
}

/*
 * @}
 */

void vigs_vma_data_init(struct vigs_vma_data *vma_data,
                        struct vigs_surface *sfc,
                        bool track_access)
{
    struct vigs_device *vigs_dev = sfc->gem.base.dev->dev_private;
    u32 old_saf;

    vma_data->sfc = sfc;
    vma_data->saf = 0;
    vma_data->track_access = track_access;

    if (track_access) {
        return;
    }

    /*
     * If we don't want to track access for this VMA
     * then register as both reader and writer.
     */

    vigs_gem_reserve(&sfc->gem);

    old_saf = vigs_surface_saf(sfc);

    ++sfc->num_writers;
    ++sfc->num_readers;

    if (vigs_gem_in_vram(&sfc->gem) && sfc->is_gpu_dirty) {
        vigs_comm_update_vram(vigs_dev->comm,
                              sfc->id,
                              vigs_gem_offset(&sfc->gem));
        sfc->is_gpu_dirty = false;
    }

    vma_data->saf = DRM_VIGS_SAF_READ | DRM_VIGS_SAF_WRITE;

    vigs_surface_saf_changed(sfc, old_saf);

    vigs_gem_unreserve(&sfc->gem);
}

void vigs_vma_data_cleanup(struct vigs_vma_data *vma_data)
{
    vigs_gem_reserve(&vma_data->sfc->gem);

    /*
     * On unmap we sync only when access tracking is enabled.
     * Otherwise, we pretend we're going to sync
     * some time later, but we never will.
     */
    vigs_vma_data_end_access(vma_data,
                             vma_data->track_access);

    vigs_gem_unreserve(&vma_data->sfc->gem);
}

static void vigs_surface_destroy(struct vigs_gem_object *gem)
{
    struct vigs_surface *sfc = vigs_gem_to_vigs_surface(gem);
    struct vigs_device *vigs_dev = gem->base.dev->dev_private;

    if (sfc->id) {
        vigs_comm_destroy_surface(vigs_dev->comm, sfc->id);

        vigs_device_remove_surface(vigs_dev, sfc->id);

        DRM_DEBUG_DRIVER("Surface destroyed (id = %u)\n", sfc->id);
    }
}

int vigs_surface_create(struct vigs_device *vigs_dev,
                        u32 width,
                        u32 height,
                        u32 stride,
                        vigsp_surface_format format,
                        bool scanout,
                        struct vigs_surface **sfc)
{
    int ret = 0;

    *sfc = kzalloc(sizeof(**sfc), GFP_KERNEL);

    if (!*sfc) {
        ret = -ENOMEM;
        goto fail1;
    }

    (*sfc)->width = width;
    (*sfc)->height = height;
    (*sfc)->stride = stride;
    (*sfc)->format = format;
    (*sfc)->scanout = scanout;

    ret = vigs_gem_init(&(*sfc)->gem,
                        vigs_dev,
                        VIGS_GEM_TYPE_SURFACE,
                        stride * height,
                        false,
                        &vigs_surface_destroy);

    if (ret != 0) {
        goto fail1;
    }

    ret = vigs_device_add_surface_unlocked(vigs_dev, *sfc, &(*sfc)->id);

    if (ret != 0) {
        goto fail2;
    }

    ret = vigs_comm_create_surface(vigs_dev->comm,
                                   width,
                                   height,
                                   stride,
                                   format,
                                   (*sfc)->id);

    if (ret != 0) {
        goto fail3;
    }

    return 0;

fail3:
    vigs_device_remove_surface_unlocked(vigs_dev, (*sfc)->id);
fail2:
    (*sfc)->id = 0;
    vigs_gem_cleanup(&(*sfc)->gem);
fail1:
    *sfc = NULL;

    return ret;
}

bool vigs_surface_need_vram_update(struct vigs_surface *sfc)
{
    u32 saf = vigs_surface_saf(sfc);
    bool skip_vram_update = sfc->skip_vram_update;

    sfc->skip_vram_update = false;

    return (saf != 0) && !skip_vram_update;
}

bool vigs_surface_need_gpu_update(struct vigs_surface *sfc)
{
    u32 old_saf = vigs_surface_saf(sfc);

    sfc->num_writers -= sfc->num_pending_writers;
    sfc->num_pending_writers = 0;

    vigs_surface_saf_changed(sfc, old_saf);

    return old_saf & DRM_VIGS_SAF_WRITE;
}

int vigs_surface_create_ioctl(struct drm_device *drm_dev,
                              void *data,
                              struct drm_file *file_priv)
{
    struct vigs_device *vigs_dev = drm_dev->dev_private;
    struct drm_vigs_create_surface *args = data;
    struct vigs_surface *sfc = NULL;
    uint32_t handle;
    int ret;

    ret = vigs_surface_create(vigs_dev,
                              args->width,
                              args->height,
                              args->stride,
                              args->format,
                              args->scanout,
                              &sfc);

    if (ret != 0) {
        return ret;
    }

    ret = drm_gem_handle_create(file_priv,
                                &sfc->gem.base,
                                &handle);

    drm_gem_object_unreference_unlocked(&sfc->gem.base);

    if (ret == 0) {
        args->handle = handle;
        args->size = vigs_gem_size(&sfc->gem);
        args->id = sfc->id;
    }

    return ret;
}

int vigs_surface_info_ioctl(struct drm_device *drm_dev,
                            void *data,
                            struct drm_file *file_priv)
{
    struct drm_vigs_surface_info *args = data;
    struct drm_gem_object *gem;
    struct vigs_gem_object *vigs_gem;
    struct vigs_surface *sfc;

    gem = drm_gem_object_lookup(drm_dev, file_priv, args->handle);

    if (gem == NULL) {
        return -ENOENT;
    }

    vigs_gem = gem_to_vigs_gem(gem);

    if (vigs_gem->type != VIGS_GEM_TYPE_SURFACE) {
        drm_gem_object_unreference_unlocked(gem);
        return -ENOENT;
    }

    sfc = vigs_gem_to_vigs_surface(vigs_gem);

    args->width = sfc->width;
    args->height = sfc->height;
    args->stride = sfc->stride;
    args->format = sfc->format;
    args->scanout = sfc->scanout;
    args->size = vigs_gem_size(vigs_gem);
    args->id = sfc->id;

    drm_gem_object_unreference_unlocked(gem);

    return 0;
}

int vigs_surface_set_gpu_dirty_ioctl(struct drm_device *drm_dev,
                                     void *data,
                                     struct drm_file *file_priv)
{
    struct drm_vigs_surface_set_gpu_dirty *args = data;
    struct drm_gem_object *gem;
    struct vigs_gem_object *vigs_gem;
    struct vigs_surface *sfc;

    gem = drm_gem_object_lookup(drm_dev, file_priv, args->handle);

    if (gem == NULL) {
        return -ENOENT;
    }

    vigs_gem = gem_to_vigs_gem(gem);

    if (vigs_gem->type != VIGS_GEM_TYPE_SURFACE) {
        drm_gem_object_unreference_unlocked(gem);
        return -ENOENT;
    }

    sfc = vigs_gem_to_vigs_surface(vigs_gem);

    vigs_gem_reserve(&sfc->gem);

    if (vigs_gem_in_vram(&sfc->gem)) {
        sfc->is_gpu_dirty = true;
    }

    vigs_gem_unreserve(&sfc->gem);

    drm_gem_object_unreference_unlocked(gem);

    return 0;
}

static int vigs_surface_start_access(void *user_data, void *vma_data_opaque)
{
    struct drm_vigs_surface_start_access *args = user_data;
    struct vigs_vma_data *vma_data = vma_data_opaque;
    struct vigs_surface *sfc = vma_data->sfc;
    struct vigs_device *vigs_dev;
    u32 old_saf;

    if (!sfc) {
        return -ENOENT;
    }

    if (!vma_data->track_access) {
        return 0;
    }

    vigs_dev = sfc->gem.base.dev->dev_private;

    if ((args->saf & ~DRM_VIGS_SAF_MASK) != 0) {
        return -EINVAL;
    }

    vigs_gem_reserve(&sfc->gem);

    old_saf = vigs_surface_saf(sfc);

    if (vma_data->saf & DRM_VIGS_SAF_READ) {
        --sfc->num_readers;
    }

    if (vma_data->saf & DRM_VIGS_SAF_WRITE) {
        --sfc->num_writers;
    }

    if (args->saf & DRM_VIGS_SAF_WRITE) {
        ++sfc->num_writers;
    }

    if (args->saf & DRM_VIGS_SAF_READ) {
        ++sfc->num_readers;

        if (vigs_gem_in_vram(&sfc->gem) && sfc->is_gpu_dirty) {
            vigs_comm_update_vram(vigs_dev->comm,
                                  sfc->id,
                                  vigs_gem_offset(&sfc->gem));
            sfc->is_gpu_dirty = false;
        }
    }

    vma_data->saf = args->saf;

    vigs_surface_saf_changed(sfc, old_saf);

    vigs_gem_unreserve(&sfc->gem);

    return 0;
}

int vigs_surface_start_access_ioctl(struct drm_device *drm_dev,
                                    void *data,
                                    struct drm_file *file_priv)
{
    struct vigs_device *vigs_dev = drm_dev->dev_private;
    struct drm_vigs_surface_start_access *args = data;

    return vigs_mman_access_vma(vigs_dev->mman,
                                args->address,
                                &vigs_surface_start_access,
                                args);
}

static int vigs_surface_end_access(void *user_data, void *vma_data_opaque)
{
    struct drm_vigs_surface_end_access *args = user_data;
    struct vigs_vma_data *vma_data = vma_data_opaque;
    struct vigs_surface *sfc = vma_data->sfc;

    if (!sfc) {
        return -ENOENT;
    }

    if (!vma_data->track_access) {
        return 0;
    }

    vigs_gem_reserve(&sfc->gem);

    vigs_vma_data_end_access(vma_data, args->sync);

    vigs_gem_unreserve(&sfc->gem);

    return 0;
}

int vigs_surface_end_access_ioctl(struct drm_device *drm_dev,
                                  void *data,
                                  struct drm_file *file_priv)
{
    struct vigs_device *vigs_dev = drm_dev->dev_private;
    struct drm_vigs_surface_end_access *args = data;

    return vigs_mman_access_vma(vigs_dev->mman,
                                args->address,
                                &vigs_surface_end_access,
                                args);
}
