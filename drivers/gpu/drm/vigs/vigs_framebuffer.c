#include "vigs_framebuffer.h"
#include "vigs_device.h"
#include "vigs_surface.h"
#include "vigs_fbdev.h"
#include "vigs_comm.h"
#include "drm_crtc_helper.h"
#include <drm/vigs_drm.h>

static void vigs_framebuffer_destroy(struct drm_framebuffer *fb)
{
    struct vigs_framebuffer *vigs_fb = fb_to_vigs_fb(fb);
    int i;

    DRM_DEBUG_KMS("enter\n");

    /*
     * First, we need to call 'drm_framebuffer_cleanup', this'll
     * automatically call 'vigs_crtc_disable' if needed, thus, notifying
     * the host that root surface is gone.
     */

    drm_framebuffer_cleanup(fb);

    /*
     * And we can finally free the GEMs.
     */

    for (i = 0; i < 4; ++i) {
        if (vigs_fb->surfaces[i]) {
            drm_gem_object_unreference_unlocked(&vigs_fb->surfaces[i]->gem.base);
        }
    }
    kfree(vigs_fb);
}

static int vigs_framebuffer_create_handle(struct drm_framebuffer *fb,
                                          struct drm_file *file_priv,
                                          unsigned int *handle)
{
    struct vigs_framebuffer *vigs_fb = fb_to_vigs_fb(fb);

    DRM_DEBUG_KMS("enter\n");

    return drm_gem_handle_create(file_priv, &vigs_fb->surfaces[0]->gem.base, handle);
}

static int vigs_framebuffer_dirty(struct drm_framebuffer *fb,
                                  struct drm_file *file_priv,
                                  unsigned flags, unsigned color,
                                  struct drm_clip_rect *clips,
                                  unsigned num_clips)
{
    DRM_DEBUG_KMS("enter\n");

    return 0;
}

static struct drm_framebuffer_funcs vigs_framebuffer_funcs =
{
    .destroy = vigs_framebuffer_destroy,
    .create_handle = vigs_framebuffer_create_handle,
    .dirty = vigs_framebuffer_dirty,
};

static struct drm_framebuffer *vigs_fb_create(struct drm_device *drm_dev,
                                              struct drm_file *file_priv,
                                              struct drm_mode_fb_cmd2 *mode_cmd)
{
    struct vigs_device *vigs_dev = drm_dev->dev_private;
    struct vigs_surface *surfaces[4];
    int ret, i;
    int num_planes = drm_format_num_planes(mode_cmd->pixel_format);
    struct vigs_framebuffer *vigs_fb;

    DRM_DEBUG_KMS("enter\n");

    for (i = 0; i < num_planes; ++i) {
        struct drm_gem_object *gem;
        struct vigs_gem_object *vigs_gem;

        gem = drm_gem_object_lookup(drm_dev, file_priv, mode_cmd->handles[i]);

        if (!gem) {
            DRM_ERROR("GEM lookup failed, handle = %u\n", mode_cmd->handles[i]);
            ret = -ENOENT;
            goto fail;
        }

        vigs_gem = gem_to_vigs_gem(gem);

        if (vigs_gem->type != VIGS_GEM_TYPE_SURFACE) {
            DRM_ERROR("GEM is not a surface, handle = %u\n", mode_cmd->handles[i]);
            drm_gem_object_unreference_unlocked(gem);
            ret = -ENOENT;
            goto fail;
        }

        surfaces[i] = vigs_gem_to_vigs_surface(vigs_gem);
    }

    vigs_fb = kzalloc(sizeof(*vigs_fb), GFP_KERNEL);

    if (!vigs_fb) {
        ret = -ENOMEM;
        goto fail;
    }

    vigs_fb->comm = vigs_dev->comm;

    for (i = 0; i < num_planes; ++i) {
        vigs_fb->surfaces[i] = surfaces[i];
    }

    ret = drm_framebuffer_init(vigs_dev->drm_dev,
                               &vigs_fb->base,
                               &vigs_framebuffer_funcs);

    if (ret != 0) {
        DRM_ERROR("unable to create the framebuffer: %d\n", ret);
        kfree(vigs_fb);
        goto fail;
    }

    drm_helper_mode_fill_fb_struct(&vigs_fb->base, mode_cmd);

    return &vigs_fb->base;

fail:
    for (i--; i >= 0; i--) {
        drm_gem_object_unreference_unlocked(&surfaces[i]->gem.base);
    }

    return ERR_PTR(ret);
}

static void vigs_output_poll_changed(struct drm_device *drm_dev)
{
    struct vigs_device *vigs_dev = drm_dev->dev_private;

    DRM_DEBUG_KMS("enter\n");

    if (vigs_dev->fbdev) {
        vigs_fbdev_output_poll_changed(vigs_dev->fbdev);
    }
}

static struct drm_mode_config_funcs vigs_mode_config_funcs =
{
    .fb_create = vigs_fb_create,
    .output_poll_changed = vigs_output_poll_changed
};

void vigs_framebuffer_config_init(struct vigs_device *vigs_dev)
{
    DRM_DEBUG_KMS("enter\n");

    vigs_dev->drm_dev->mode_config.min_width = 0;
    vigs_dev->drm_dev->mode_config.min_height = 0;

    vigs_dev->drm_dev->mode_config.max_width = 4096;
    vigs_dev->drm_dev->mode_config.max_height = 4096;

    vigs_dev->drm_dev->mode_config.funcs = &vigs_mode_config_funcs;
}

int vigs_framebuffer_create(struct vigs_device *vigs_dev,
                            struct drm_mode_fb_cmd2 *mode_cmd,
                            struct vigs_surface *fb_sfc,
                            struct vigs_framebuffer **vigs_fb)
{
    int ret = 0;

    DRM_DEBUG_KMS("enter\n");

    *vigs_fb = kzalloc(sizeof(**vigs_fb), GFP_KERNEL);

    if (!*vigs_fb) {
        ret = -ENOMEM;
        goto fail1;
    }

    if ((fb_sfc->width != mode_cmd->width) ||
        (fb_sfc->height != mode_cmd->height) ||
        (fb_sfc->stride != mode_cmd->pitches[0])) {
        DRM_DEBUG_KMS("surface format mismatch, sfc - (%u,%u,%u), mode - (%u,%u,%u)\n",
                      fb_sfc->width, fb_sfc->height, fb_sfc->stride,
                      mode_cmd->width, mode_cmd->height, mode_cmd->pitches[0]);
        ret = -EINVAL;
        goto fail2;
    }

    (*vigs_fb)->comm = vigs_dev->comm;
    (*vigs_fb)->surfaces[0] = fb_sfc;

    ret = drm_framebuffer_init(vigs_dev->drm_dev,
                               &(*vigs_fb)->base,
                               &vigs_framebuffer_funcs);

    if (ret != 0) {
        goto fail2;
    }

    drm_helper_mode_fill_fb_struct(&(*vigs_fb)->base, mode_cmd);

    drm_gem_object_reference(&fb_sfc->gem.base);

    return 0;

fail2:
    kfree(*vigs_fb);
fail1:
    *vigs_fb = NULL;

    return ret;
}

int vigs_framebuffer_pin(struct vigs_framebuffer *vigs_fb)
{
    int ret;

    vigs_gem_reserve(&vigs_fb->surfaces[0]->gem);

    ret = vigs_gem_pin(&vigs_fb->surfaces[0]->gem);

    vigs_gem_unreserve(&vigs_fb->surfaces[0]->gem);

    return ret;
}

void vigs_framebuffer_unpin(struct vigs_framebuffer *vigs_fb)
{
    vigs_gem_reserve(&vigs_fb->surfaces[0]->gem);

    vigs_gem_unpin(&vigs_fb->surfaces[0]->gem);

    vigs_gem_unreserve(&vigs_fb->surfaces[0]->gem);
}
