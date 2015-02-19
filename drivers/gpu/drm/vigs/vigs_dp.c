#include "vigs_dp.h"
#include "vigs_surface.h"
#include "vigs_device.h"

int vigs_dp_create(struct vigs_device *vigs_dev,
                   struct vigs_dp **dp)
{
    int ret = 0;

    DRM_DEBUG_DRIVER("enter\n");

    *dp = kzalloc(sizeof(**dp), GFP_KERNEL);

    if (!*dp) {
        ret = -ENOMEM;
        goto fail1;
    }

    return 0;

fail1:
    *dp = NULL;

    return ret;
}

void vigs_dp_destroy(struct vigs_dp *dp)
{
    DRM_DEBUG_DRIVER("enter\n");

    kfree(dp);
}

void vigs_dp_remove_surface(struct vigs_dp *dp, struct vigs_surface *sfc)
{
    int i, j;

    for (i = 0; i < VIGS_MAX_PLANES; ++i) {
        for (j = 0; j < DRM_VIGS_NUM_DP_FB_BUF; ++j) {
            if (dp->planes[i].fb_bufs[j].y == sfc) {
                dp->planes[i].fb_bufs[j].y = NULL;
            }
            if (dp->planes[i].fb_bufs[j].c == sfc) {
                dp->planes[i].fb_bufs[j].c = NULL;
            }
        }
    }
}

int vigs_dp_surface_create_ioctl(struct drm_device *drm_dev,
                                 void *data,
                                 struct drm_file *file_priv)
{
    struct vigs_device *vigs_dev = drm_dev->dev_private;
    struct vigs_dp *dp = vigs_dev->dp;
    struct drm_vigs_dp_create_surface *args = data;
    struct vigs_surface *sfc = NULL;
    bool busy;
    uint32_t handle;
    int ret;

    if (args->dp_plane >= VIGS_MAX_PLANES) {
        DRM_ERROR("bad DP plane = %u\n", args->dp_plane);
        return -ENOMEM;
    }

    if (args->dp_fb_buf >= DRM_VIGS_NUM_DP_FB_BUF) {
        DRM_ERROR("bad DP fb buf = %u\n", args->dp_fb_buf);
        return -ENOMEM;
    }

    mutex_lock(&vigs_dev->drm_dev->struct_mutex);

    switch (args->dp_mem_flag) {
    case DRM_VIGS_DP_FB_Y:
        busy = dp->planes[args->dp_plane].fb_bufs[args->dp_fb_buf].y != NULL;
        break;
    case DRM_VIGS_DP_FB_C:
        busy = dp->planes[args->dp_plane].fb_bufs[args->dp_fb_buf].c != NULL;
        break;
    default:
        mutex_unlock(&vigs_dev->drm_dev->struct_mutex);
        DRM_ERROR("bad DP mem flag = %u\n", args->dp_mem_flag);
        return -ENOMEM;
    }

    mutex_unlock(&vigs_dev->drm_dev->struct_mutex);

    if (busy) {
        DRM_INFO("DP mem %u:%u:%u is busy\n", args->dp_plane,
                                              args->dp_fb_buf,
                                              args->dp_mem_flag);
        return -ENOMEM;
    }

    ret = vigs_surface_create(vigs_dev,
                              args->width,
                              args->height,
                              args->stride,
                              args->format,
                              false,
                              &sfc);

    if (ret != 0) {
        return ret;
    }

    /*
     * Check busy again since DP mem might
     * gotten busy while we were creating our surface.
     * If it's not busy then occupy it.
     */

    mutex_lock(&vigs_dev->drm_dev->struct_mutex);

    switch (args->dp_mem_flag) {
    case DRM_VIGS_DP_FB_Y:
        if (dp->planes[args->dp_plane].fb_bufs[args->dp_fb_buf].y) {
            busy = true;
        } else {
            dp->planes[args->dp_plane].fb_bufs[args->dp_fb_buf].y = sfc;
        }
        break;
    case DRM_VIGS_DP_FB_C:
        if (dp->planes[args->dp_plane].fb_bufs[args->dp_fb_buf].c) {
            busy = true;
        } else {
            dp->planes[args->dp_plane].fb_bufs[args->dp_fb_buf].c = sfc;
        }
        break;
    default:
        drm_gem_object_unreference(&sfc->gem.base);
        mutex_unlock(&vigs_dev->drm_dev->struct_mutex);
        BUG();
        return -ENOMEM;
    }

    mutex_unlock(&vigs_dev->drm_dev->struct_mutex);

    if (busy) {
        drm_gem_object_unreference_unlocked(&sfc->gem.base);

        DRM_INFO("DP mem %u:%u:%u is busy\n", args->dp_plane,
                                              args->dp_fb_buf,
                                              args->dp_mem_flag);
        return -ENOMEM;
    }

    ret = drm_gem_handle_create(file_priv,
                                &sfc->gem.base,
                                &handle);

    if (ret == 0) {
        args->handle = handle;
        args->size = vigs_gem_size(&sfc->gem);
        args->id = sfc->id;
    } else {
        /*
         * Don't bother setting DP mem slot to NULL here, DRM
         * will do this for us once the GEM is freed.
         */
    }

    drm_gem_object_unreference_unlocked(&sfc->gem.base);

    return ret;
}

int vigs_dp_surface_open_ioctl(struct drm_device *drm_dev,
                               void *data,
                               struct drm_file *file_priv)
{
    struct vigs_device *vigs_dev = drm_dev->dev_private;
    struct vigs_dp *dp = vigs_dev->dp;
    struct drm_vigs_dp_open_surface *args = data;
    struct vigs_surface *sfc = NULL;
    uint32_t handle;
    int ret;

    if (args->dp_plane >= VIGS_MAX_PLANES) {
        DRM_ERROR("bad DP plane = %u\n", args->dp_plane);
        return -ENOMEM;
    }

    if (args->dp_fb_buf >= DRM_VIGS_NUM_DP_FB_BUF) {
        DRM_ERROR("bad DP fb buf = %u\n", args->dp_fb_buf);
        return -ENOMEM;
    }

    mutex_lock(&vigs_dev->drm_dev->struct_mutex);

    switch (args->dp_mem_flag) {
    case DRM_VIGS_DP_FB_Y:
        sfc = dp->planes[args->dp_plane].fb_bufs[args->dp_fb_buf].y;
        break;
    case DRM_VIGS_DP_FB_C:
        sfc = dp->planes[args->dp_plane].fb_bufs[args->dp_fb_buf].c;
        break;
    default:
        mutex_unlock(&vigs_dev->drm_dev->struct_mutex);
        DRM_ERROR("bad DP mem flag = %u\n", args->dp_mem_flag);
        return -ENOMEM;
    }

    if (sfc) {
        drm_gem_object_reference(&sfc->gem.base);
    } else {
        mutex_unlock(&vigs_dev->drm_dev->struct_mutex);
        DRM_INFO("DP mem %u:%u:%u is empty\n", args->dp_plane,
                                               args->dp_fb_buf,
                                               args->dp_mem_flag);
        return -ENOMEM;
    }

    mutex_unlock(&vigs_dev->drm_dev->struct_mutex);

    ret = drm_gem_handle_create(file_priv,
                                &sfc->gem.base,
                                &handle);

    if (ret == 0) {
        args->handle = handle;
    }

    drm_gem_object_unreference_unlocked(&sfc->gem.base);

    return ret;
}
