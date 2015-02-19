#include "vigs_crtc.h"
#include "vigs_device.h"
#include "vigs_framebuffer.h"
#include "vigs_surface.h"
#include "vigs_comm.h"
#include "vigs_fbdev.h"
#include "drm_crtc_helper.h"
#include <linux/console.h>

static int vigs_crtc_update(struct drm_crtc *crtc,
                            struct drm_framebuffer *old_fb)
{
    struct vigs_device *vigs_dev = crtc->dev->dev_private;
    struct vigs_framebuffer *vigs_old_fb = NULL;
    struct vigs_framebuffer *vigs_fb;
    int ret;

    /*
     * New framebuffer has been attached, notify the host that
     * root surface has been updated.
     */

    if (!crtc->fb) {
        DRM_ERROR("crtc->fb is NULL\n");
        return -EINVAL;
    }

    if (old_fb) {
        vigs_old_fb = fb_to_vigs_fb(old_fb);
    }

    vigs_fb = fb_to_vigs_fb(crtc->fb);

    if (vigs_fb->surfaces[0]->scanout) {
retry:
        ret = vigs_framebuffer_pin(vigs_fb);

        if (ret != 0) {
            /*
             * In condition of very intense GEM operations
             * and with small amount of VRAM memory it's possible that
             * GEM pin will be failing for some time, thus, framebuffer pin
             * will be failing. This is unavoidable with current TTM design,
             * thus, if someone is intensively
             * reserves/unreserves GEMs then ttm_bo_validate can fail even if there
             * is free space in a placement. Even worse, ttm_bo_validate fails with
             * ENOMEM so it's not possible to tell if it's a temporary failure due
             * to reserve/unreserve pressure or constant one due to memory shortage.
             * We assume here that it's temporary and retry framebuffer pin. This
             * is relatively safe since we only pin GEMs on pageflip and user
             * should have started the VM with VRAM size equal to at least 3 frames,
             * thus, 2 frame will always be free and we can always pin 1 frame.
             */
            cpu_relax();
            goto retry;
        }

        vigs_gem_reserve(&vigs_fb->surfaces[0]->gem);

        ret = vigs_comm_set_root_surface(vigs_dev->comm,
                                         vigs_fb->surfaces[0]->id,
                                         1,
                                         vigs_gem_offset(&vigs_fb->surfaces[0]->gem));

        vigs_gem_unreserve(&vigs_fb->surfaces[0]->gem);

        if (ret != 0) {
            vigs_framebuffer_unpin(vigs_fb);

            return ret;
        }
    } else {
        ret = vigs_comm_set_root_surface(vigs_dev->comm,
                                         vigs_fb->surfaces[0]->id,
                                         0,
                                         0);

        if (ret != 0) {
            return ret;
        }
    }

    if (vigs_old_fb && vigs_old_fb->surfaces[0]->scanout) {
        vigs_framebuffer_unpin(vigs_old_fb);
    }

    return 0;
}

static void vigs_crtc_destroy(struct drm_crtc *crtc)
{
    struct vigs_crtc *vigs_crtc = crtc_to_vigs_crtc(crtc);

    DRM_DEBUG_KMS("enter");

    drm_crtc_cleanup(crtc);

    kfree(vigs_crtc);
}

static void vigs_crtc_dpms(struct drm_crtc *crtc, int mode)
{
    struct vigs_device *vigs_dev = crtc->dev->dev_private;
    int blank, i;
    struct fb_event event;

    DRM_DEBUG_KMS("enter: in_dpms = %d, mode = %d\n",
                  vigs_dev->in_dpms,
                  mode);

    if (vigs_dev->in_dpms) {
        return;
    }

    switch (mode) {
    case DRM_MODE_DPMS_ON:
        blank = FB_BLANK_UNBLANK;
        break;
    case DRM_MODE_DPMS_STANDBY:
        blank = FB_BLANK_NORMAL;
        break;
    case DRM_MODE_DPMS_SUSPEND:
        blank = FB_BLANK_VSYNC_SUSPEND;
        break;
    case DRM_MODE_DPMS_OFF:
        blank = FB_BLANK_POWERDOWN;
        break;
    default:
        DRM_ERROR("unspecified mode %d\n", mode);
        return;
    }

    event.info = vigs_dev->fbdev->base.fbdev;
    event.data = &blank;

    /*
     * We can't just 'console_lock' here, since
     * this may result in deadlock:
     * fb func:
     * console_lock();
     * mutex_lock(&dev->mode_config.mutex);
     * DRM func:
     * mutex_lock(&dev->mode_config.mutex);
     * console_lock();
     *
     * So we just try to acquire it for 5 times with a delay
     * and then just skip.
     *
     * This code is here only because pm is currently done via
     * backlight which is bad, we need to make proper pm via
     * kernel support.
     */
    for (i = 0; i < 5; ++i) {
        if (console_trylock()) {
            /*
             * We must set in_dpms to true while walking
             * fb call chain because a callback inside the
             * call chain might do FB_BLANK on its own, i.e.
             * 'vigs_fbdev_dpms' might get called from here. To avoid
             * this we set in_dpms to true and 'vigs_fbdev_dpms'
             * checks this and returns.
             */
            vigs_dev->in_dpms = true;

            fb_notifier_call_chain(FB_EVENT_BLANK, &event);

            vigs_dev->in_dpms = false;

            console_unlock();
            return;
        }
        msleep(100);
        DRM_ERROR("unable to lock console, trying again\n");
    }

    DRM_ERROR("unable to lock console, skipping fb call chain\n");
}

static bool vigs_crtc_mode_fixup(struct drm_crtc *crtc,
                                 const struct drm_display_mode *mode,
                                 struct drm_display_mode *adjusted_mode)
{
    DRM_DEBUG_KMS("enter\n");

    return true;
}

static int vigs_crtc_mode_set_base(struct drm_crtc *crtc, int x, int y,
                                   struct drm_framebuffer *old_fb)
{
    DRM_DEBUG_KMS("enter: x = %d, y = %d\n", x, y);

    return vigs_crtc_update(crtc, old_fb);
}

static int vigs_crtc_mode_set(struct drm_crtc *crtc,
                              struct drm_display_mode *mode,
                              struct drm_display_mode *adjusted_mode,
                              int x, int y,
                              struct drm_framebuffer *old_fb)
{
    DRM_DEBUG_KMS("enter: x = %d, y = %d\n", x, y);

    return vigs_crtc_mode_set_base(crtc, x, y, old_fb);
}

static void vigs_crtc_prepare(struct drm_crtc *crtc)
{
    DRM_DEBUG_KMS("enter\n");
}

static void vigs_crtc_commit(struct drm_crtc *crtc)
{
    DRM_DEBUG_KMS("enter\n");
}

static void vigs_crtc_load_lut(struct drm_crtc *crtc)
{
}

static int vigs_crtc_cursor_set(struct drm_crtc *crtc,
                                struct drm_file *file_priv,
                                uint32_t handle,
                                uint32_t width,
                                uint32_t height)
{
    /*
     * Not supported.
     */

    return 0;
}

static int vigs_crtc_cursor_move(struct drm_crtc *crtc, int x, int y)
{
    /*
     * Not supported.
     */

    return 0;
}

static int vigs_crtc_page_flip(struct drm_crtc *crtc,
                               struct drm_framebuffer *fb,
                               struct drm_pending_vblank_event *event,
                               uint32_t page_flip_flags)
{
    unsigned long flags;
    struct vigs_device *vigs_dev = crtc->dev->dev_private;
    struct drm_framebuffer *old_fb = crtc->fb;
    int ret = -EINVAL;

    mutex_lock(&vigs_dev->drm_dev->struct_mutex);

    if (event) {
        event->pipe = 0;

        ret = drm_vblank_get(vigs_dev->drm_dev, 0);

        if (ret != 0) {
            DRM_ERROR("failed to acquire vblank counter\n");
            goto out;
        }

        spin_lock_irqsave(&vigs_dev->drm_dev->event_lock, flags);
        list_add_tail(&event->base.link,
                      &vigs_dev->pageflip_event_list);
        spin_unlock_irqrestore(&vigs_dev->drm_dev->event_lock, flags);

        crtc->fb = fb;
        ret = vigs_crtc_update(crtc, old_fb);
        if (ret != 0) {
            crtc->fb = old_fb;
            spin_lock_irqsave(&vigs_dev->drm_dev->event_lock, flags);
            if (atomic_read(&vigs_dev->drm_dev->vblank_refcount[0]) > 0) {
                /*
                 * Only do this if event wasn't already processed.
                 */
                drm_vblank_put(vigs_dev->drm_dev, 0);
                list_del(&event->base.link);
            }
            spin_unlock_irqrestore(&vigs_dev->drm_dev->event_lock, flags);
            goto out;
        }
    }

out:
    mutex_unlock(&vigs_dev->drm_dev->struct_mutex);

    return ret;
}

static void vigs_crtc_disable(struct drm_crtc *crtc)
{
    struct vigs_device *vigs_dev = crtc->dev->dev_private;
    struct vigs_framebuffer *vigs_fb;

    /*
     * Framebuffer has been detached, notify the host that
     * root surface is gone.
     */

    DRM_DEBUG_KMS("enter\n");

    if (!crtc->fb) {
        /*
         * No current framebuffer, no need to notify the host.
         */

        return;
    }

    vigs_fb = fb_to_vigs_fb(crtc->fb);

    vigs_comm_set_root_surface(vigs_dev->comm, 0, 0, 0);

    if (vigs_fb->surfaces[0]->scanout) {
        vigs_framebuffer_unpin(vigs_fb);
    }
}

static const struct drm_crtc_funcs vigs_crtc_funcs =
{
    .cursor_set = vigs_crtc_cursor_set,
    .cursor_move = vigs_crtc_cursor_move,
    .set_config = drm_crtc_helper_set_config,
    .page_flip = vigs_crtc_page_flip,
    .destroy = vigs_crtc_destroy,
};

static const struct drm_crtc_helper_funcs vigs_crtc_helper_funcs =
{
    .dpms = vigs_crtc_dpms,
    .mode_fixup = vigs_crtc_mode_fixup,
    .mode_set = vigs_crtc_mode_set,
    .mode_set_base = vigs_crtc_mode_set_base,
    .prepare = vigs_crtc_prepare,
    .commit = vigs_crtc_commit,
    .load_lut = vigs_crtc_load_lut,
    .disable = vigs_crtc_disable,
};

int vigs_crtc_init(struct vigs_device *vigs_dev)
{
    struct vigs_crtc *vigs_crtc;
    int ret;

    DRM_DEBUG_KMS("enter\n");

    vigs_crtc = kzalloc(sizeof(*vigs_crtc), GFP_KERNEL);

    if (!vigs_crtc) {
        return -ENOMEM;
    }

    ret = drm_crtc_init(vigs_dev->drm_dev,
                        &vigs_crtc->base,
                        &vigs_crtc_funcs);

    if (ret != 0) {
        kfree(vigs_crtc);
        return ret;
    }

    drm_crtc_helper_add(&vigs_crtc->base, &vigs_crtc_helper_funcs);

    return 0;
}
