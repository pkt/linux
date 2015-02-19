#include "vigs_plane.h"
#include "vigs_device.h"
#include "vigs_framebuffer.h"
#include "vigs_surface.h"
#include "vigs_comm.h"
#include <drm/vigs_drm.h>

static const uint32_t formats[] =
{
    DRM_FORMAT_XRGB8888,
    DRM_FORMAT_ARGB8888,
    DRM_FORMAT_NV21,
    fourcc_code('N', 'V', '4', '2'),
    DRM_FORMAT_NV61,
    DRM_FORMAT_YUV420
};

static int vigs_plane_update(struct drm_plane *plane,
                             struct drm_crtc *crtc,
                             struct drm_framebuffer *fb,
                             int crtc_x, int crtc_y,
                             unsigned int crtc_w,
                             unsigned int crtc_h,
                             uint32_t src_x, uint32_t src_y,
                             uint32_t src_w, uint32_t src_h)
{
    struct vigs_plane *vigs_plane = plane_to_vigs_plane(plane);
    struct vigs_device *vigs_dev = plane->dev->dev_private;
    struct vigs_framebuffer *vigs_fb = fb_to_vigs_fb(fb);
    int ret, i;
    uint32_t src_x_whole = src_x >> 16;
    uint32_t src_y_whole = src_y >> 16;
    uint32_t src_w_whole = src_w >> 16;
    uint32_t src_h_whole = src_h >> 16;
    vigsp_surface_id surface_ids[4] = { 0, 0, 0, 0 };
    vigsp_plane_format format;

    DRM_DEBUG_KMS("enter: crtc_x = %d, crtc_y = %d, crtc_w = %u, crtc_h = %u, src_x = %u, src_y = %u, src_w = %u, src_h = %u\n",
                  crtc_x, crtc_y, crtc_w, crtc_h, src_x, src_y, src_w, src_h);

    if (vigs_fb->surfaces[0]->scanout) {
        vigs_gem_reserve(&vigs_fb->surfaces[0]->gem);

        if (vigs_gem_in_vram(&vigs_fb->surfaces[0]->gem) &&
            vigs_surface_need_gpu_update(vigs_fb->surfaces[0])) {
            vigs_comm_update_gpu(vigs_dev->comm,
                                 vigs_fb->surfaces[0]->id,
                                 vigs_fb->surfaces[0]->width,
                                 vigs_fb->surfaces[0]->height,
                                 vigs_gem_offset(&vigs_fb->surfaces[0]->gem));
        }

        vigs_gem_unreserve(&vigs_fb->surfaces[0]->gem);
    }

    for (i = 0; i < 4; ++i) {
        if (vigs_fb->surfaces[i]) {
            surface_ids[i] = vigs_fb->surfaces[i]->id;
        }
    }

    switch (fb->pixel_format) {
    case DRM_FORMAT_XRGB8888:
        format = vigsp_plane_bgrx8888;
        break;
    case DRM_FORMAT_ARGB8888:
        format = vigsp_plane_bgra8888;
        break;
    case DRM_FORMAT_NV21:
        format = vigsp_plane_nv21;
        break;
    case fourcc_code('N', 'V', '4', '2'):
        format = vigsp_plane_nv42;
        break;
    case DRM_FORMAT_NV61:
        format = vigsp_plane_nv61;
        break;
    case DRM_FORMAT_YUV420:
        format = vigsp_plane_yuv420;
        break;
    default:
        BUG();
        format = vigsp_plane_bgrx8888;
        break;
    }

    ret = vigs_comm_set_plane(vigs_dev->comm,
                              vigs_plane->index,
                              fb->width,
                              fb->height,
                              format,
                              surface_ids,
                              src_x_whole,
                              src_y_whole,
                              src_w_whole,
                              src_h_whole,
                              crtc_x,
                              crtc_y,
                              crtc_w,
                              crtc_h,
                              vigs_plane->z_pos,
                              vigs_plane->hflip,
                              vigs_plane->vflip,
                              vigs_plane->rotation);

    if (ret == 0) {
        vigs_plane->src_x = src_x;
        vigs_plane->src_y = src_y;
        vigs_plane->src_w = src_w;
        vigs_plane->src_h = src_h;

        vigs_plane->crtc_x = crtc_x;
        vigs_plane->crtc_y = crtc_y;
        vigs_plane->crtc_w = crtc_w;
        vigs_plane->crtc_h = crtc_h;

        vigs_plane->enabled = true;
    }

    return ret;
}

static int vigs_plane_disable(struct drm_plane *plane)
{
    struct vigs_plane *vigs_plane = plane_to_vigs_plane(plane);
    struct vigs_device *vigs_dev = plane->dev->dev_private;
    int ret;
    vigsp_surface_id surface_ids[4] = { 0, 0, 0, 0 };

    DRM_DEBUG_KMS("enter\n");

    if (!vigs_plane->enabled) {
        return 0;
    }

    ret = vigs_comm_set_plane(vigs_dev->comm,
                              vigs_plane->index,
                              0,
                              0,
                              0,
                              surface_ids,
                              0,
                              0,
                              0,
                              0,
                              0,
                              0,
                              0,
                              0,
                              0,
                              0,
                              0,
                              0);

    if (ret == 0) {
        vigs_plane->src_x = 0;
        vigs_plane->src_y = 0;
        vigs_plane->src_w = 0;
        vigs_plane->src_h = 0;

        vigs_plane->crtc_x = 0;
        vigs_plane->crtc_y = 0;
        vigs_plane->crtc_w = 0;
        vigs_plane->crtc_h = 0;

        vigs_plane->enabled = false;
    }

    return ret;
}

static void vigs_plane_destroy(struct drm_plane *plane)
{
    struct vigs_plane *vigs_plane = plane_to_vigs_plane(plane);

    DRM_DEBUG_KMS("enter\n");

    vigs_plane_disable(plane);
    drm_plane_cleanup(plane);
    kfree(vigs_plane);
}

static const struct drm_plane_funcs vigs_plane_funcs =
{
    .update_plane = vigs_plane_update,
    .disable_plane = vigs_plane_disable,
    .destroy = vigs_plane_destroy,
};

int vigs_plane_init(struct vigs_device *vigs_dev, u32 index)
{
    struct vigs_plane *vigs_plane;
    int ret;

    DRM_DEBUG_KMS("enter\n");

    vigs_plane = kzalloc(sizeof(*vigs_plane), GFP_KERNEL);

    if (!vigs_plane) {
        return -ENOMEM;
    }

    vigs_plane->index = index;

    ret = drm_plane_init(vigs_dev->drm_dev,
                         &vigs_plane->base,
                         (1 << 0),
                         &vigs_plane_funcs,
                         formats,
                         ARRAY_SIZE(formats),
                         false);

    if (ret != 0) {
        return ret;
    }

    return 0;
}

int vigs_plane_set_zpos_ioctl(struct drm_device *drm_dev,
                              void *data,
                              struct drm_file *file_priv)
{
    struct drm_vigs_plane_set_zpos *args = data;
    struct drm_mode_object *obj;
    struct drm_plane *plane;
    struct vigs_plane *vigs_plane;
    int ret;

    drm_modeset_lock_all(drm_dev);

    obj = drm_mode_object_find(drm_dev,
                               args->plane_id,
                               DRM_MODE_OBJECT_PLANE);
    if (!obj) {
        ret = -EINVAL;
        goto out;
    }

    plane = obj_to_plane(obj);
    vigs_plane = plane_to_vigs_plane(plane);

    vigs_plane->z_pos = args->zpos;

    ret = 0;

out:
    drm_modeset_unlock_all(drm_dev);

    return ret;
}

int vigs_plane_set_transform_ioctl(struct drm_device *drm_dev,
                                   void *data,
                                   struct drm_file *file_priv)
{
    struct drm_vigs_plane_set_transform *args = data;
    struct drm_mode_object *obj;
    struct drm_plane *plane;
    struct vigs_plane *vigs_plane;
    int ret;

    drm_modeset_lock_all(drm_dev);

    obj = drm_mode_object_find(drm_dev,
                               args->plane_id,
                               DRM_MODE_OBJECT_PLANE);
    if (!obj) {
        ret = -EINVAL;
        goto out;
    }

    plane = obj_to_plane(obj);
    vigs_plane = plane_to_vigs_plane(plane);

    vigs_plane->hflip = args->hflip;
    vigs_plane->vflip = args->vflip;
    vigs_plane->rotation = args->rotation;

    ret = 0;

out:
    drm_modeset_unlock_all(drm_dev);

    return ret;
}
