#include "vigs_fbdev.h"
#include "vigs_device.h"
#include "vigs_surface.h"
#include "vigs_framebuffer.h"
#include "vigs_output.h"
#include "vigs_crtc.h"
#include "drm_crtc_helper.h"
#include <drm/vigs_drm.h>

/*
 * From drm_fb_helper.c, modified to work with 'regno' > 16.
 * @{
 */

static bool vigs_fbdev_helper_is_bound(struct drm_fb_helper *fb_helper)
{
    struct drm_device *dev = fb_helper->dev;
    struct drm_crtc *crtc;
    int bound = 0, crtcs_bound = 0;

    list_for_each_entry(crtc, &dev->mode_config.crtc_list, head) {
        if (crtc->fb) {
            crtcs_bound++;
        }

        if (crtc->fb == fb_helper->fb) {
            bound++;
        }
    }

    if (bound < crtcs_bound) {
        return false;
    }

    return true;
}

static int vigs_fbdev_setcolreg(struct drm_crtc *crtc, u16 red, u16 green,
                                u16 blue, u16 regno, struct fb_info *fbi)
{
    struct drm_fb_helper *fb_helper = fbi->par;
    struct drm_framebuffer *fb = fb_helper->fb;
    int pindex;

    if (fbi->fix.visual == FB_VISUAL_TRUECOLOR) {
        u32 *palette;
        u32 value;
        /* place color in psuedopalette */
        if (regno <= 16) {
            palette = (u32*)fbi->pseudo_palette;
            red >>= (16 - fbi->var.red.length);
            green >>= (16 - fbi->var.green.length);
            blue >>= (16 - fbi->var.blue.length);
            value = (red << fbi->var.red.offset) |
                    (green << fbi->var.green.offset) |
                    (blue << fbi->var.blue.offset);
            if (fbi->var.transp.length > 0) {
                u32 mask = (1 << fbi->var.transp.length) - 1;
                mask <<= fbi->var.transp.offset;
                value |= mask;
            }
            palette[regno] = value;
        }
        return 0;
    }

    /*
     * The driver really shouldn't advertise pseudo/directcolor
     * visuals if it can't deal with the palette.
     */
    if (WARN_ON(!fb_helper->funcs->gamma_set ||
                !fb_helper->funcs->gamma_get)) {
        return -EINVAL;
    }

    pindex = regno;

    if (fb->bits_per_pixel == 16) {
        pindex = regno << 3;

        if ((fb->depth == 16) && (regno > 63)) {
            return -EINVAL;
        }

        if ((fb->depth == 15) && (regno > 31)) {
            return -EINVAL;
        }

        if (fb->depth == 16) {
            u16 r, g, b;
            int i;

            if (regno < 32) {
                for (i = 0; i < 8; i++) {
                    fb_helper->funcs->gamma_set(crtc, red,
                        green, blue, pindex + i);
                }
            }

            fb_helper->funcs->gamma_get(crtc, &r,
                &g, &b,
                (pindex >> 1));

            for (i = 0; i < 4; i++) {
                fb_helper->funcs->gamma_set(crtc, r,
                    green, b,
                    (pindex >> 1) + i);
            }
        }
    }

    if (fb->depth != 16) {
        fb_helper->funcs->gamma_set(crtc, red, green, blue, pindex);
    }

    return 0;
}

static int vigs_fbdev_setcmap(struct fb_cmap *cmap, struct fb_info *fbi)
{
    struct drm_fb_helper *fb_helper = fbi->par;
    struct drm_device *dev = fb_helper->dev;
    struct drm_crtc_helper_funcs *crtc_funcs;
    u16 *red, *green, *blue, *transp;
    struct drm_crtc *crtc;
    int i, j, ret = 0;
    int start;

    drm_modeset_lock_all(dev);
    if (!vigs_fbdev_helper_is_bound(fb_helper)) {
        drm_modeset_unlock_all(dev);
        return -EBUSY;
    }

    for (i = 0; i < fb_helper->crtc_count; i++) {
        crtc = fb_helper->crtc_info[i].mode_set.crtc;
        crtc_funcs = crtc->helper_private;

        red = cmap->red;
        green = cmap->green;
        blue = cmap->blue;
        transp = cmap->transp;
        start = cmap->start;

        for (j = 0; j < cmap->len; j++) {
            u16 hred, hgreen, hblue, htransp = 0xffff;

            hred = *red++;
            hgreen = *green++;
            hblue = *blue++;

            if (transp) {
                htransp = *transp++;
            }

            ret = vigs_fbdev_setcolreg(crtc, hred, hgreen, hblue, start++, fbi);

            if (ret != 0) {
                goto out;
            }
        }

        if (crtc_funcs->load_lut) {
            crtc_funcs->load_lut(crtc);
        }
    }

 out:
    drm_modeset_unlock_all(dev);
    return ret;
}

/*
 * @}
 */

static int vigs_fbdev_set_par(struct fb_info *fbi)
{
    DRM_DEBUG_KMS("enter\n");

    return drm_fb_helper_set_par(fbi);
}

/*
 * This is 'drm_fb_helper_dpms' modified to set 'in_dpms'
 * flag inside drm_modeset_lock_all.
 */
static void vigs_fbdev_dpms(struct fb_info *fbi, int dpms_mode)
{
    struct drm_fb_helper *fb_helper = fbi->par;
    struct drm_device *dev = fb_helper->dev;
    struct vigs_device *vigs_dev = dev->dev_private;
    struct drm_crtc *crtc;
    struct vigs_crtc *vigs_crtc;
    struct drm_connector *connector;
    int i, j;

    /*
     * fbdev->blank can be called from irq context in case of a panic.
     * Since we already have our own special panic handler which will
     * restore the fbdev console mode completely, just bail out early.
     */
    if (oops_in_progress) {
        return;
    }

    if (vigs_dev->in_dpms) {
        /*
         * If this is called from 'vigs_crtc_dpms' then we just
         * return in order to not deadlock. Note that it's
         * correct to check this flag here without any locks
         * being held since 'fb_blank' callback is already called with
         * console lock being held and 'vigs_crtc_dpms' only sets in_dpms
         * inside the console lock.
         */
        return;
    }

    /*
     * For each CRTC in this fb, turn the connectors on/off.
     */
    drm_modeset_lock_all(dev);
    if (!vigs_fbdev_helper_is_bound(fb_helper)) {
        drm_modeset_unlock_all(dev);
        return;
    }

    for (i = 0; i < fb_helper->crtc_count; i++) {
        crtc = fb_helper->crtc_info[i].mode_set.crtc;
        vigs_crtc = crtc_to_vigs_crtc(crtc);

        if (!crtc->enabled) {
            continue;
        }

        vigs_dev->in_dpms = true;

        /* Walk the connectors & encoders on this fb turning them on/off */
        for (j = 0; j < fb_helper->connector_count; j++) {
            connector = fb_helper->connector_info[j]->connector;
            connector->funcs->dpms(connector, dpms_mode);
            drm_object_property_set_value(&connector->base,
                dev->mode_config.dpms_property, dpms_mode);
        }

        vigs_dev->in_dpms = false;
    }

    drm_modeset_unlock_all(dev);
}

/*
 * This is 'drm_fb_helper_blank' modified to use
 * 'vigs_fbdev_dpms'.
 */
static int vigs_fbdev_blank(int blank, struct fb_info *fbi)
{
    switch (blank) {
    /* Display: On; HSync: On, VSync: On */
    case FB_BLANK_UNBLANK:
        vigs_fbdev_dpms(fbi, DRM_MODE_DPMS_ON);
        break;
    /* Display: Off; HSync: On, VSync: On */
    case FB_BLANK_NORMAL:
        vigs_fbdev_dpms(fbi, DRM_MODE_DPMS_STANDBY);
        break;
    /* Display: Off; HSync: Off, VSync: On */
    case FB_BLANK_HSYNC_SUSPEND:
        vigs_fbdev_dpms(fbi, DRM_MODE_DPMS_STANDBY);
        break;
    /* Display: Off; HSync: On, VSync: Off */
    case FB_BLANK_VSYNC_SUSPEND:
        vigs_fbdev_dpms(fbi, DRM_MODE_DPMS_SUSPEND);
        break;
    /* Display: Off; HSync: Off, VSync: Off */
    case FB_BLANK_POWERDOWN:
        vigs_fbdev_dpms(fbi, DRM_MODE_DPMS_OFF);
        break;
    }

    return 0;
}

static struct fb_ops vigs_fbdev_ops =
{
    .owner = THIS_MODULE,
    .fb_fillrect = cfb_fillrect,
    .fb_copyarea = cfb_copyarea,
    .fb_imageblit = cfb_imageblit,
    .fb_check_var = drm_fb_helper_check_var,
    .fb_set_par = vigs_fbdev_set_par,
    .fb_blank = vigs_fbdev_blank,
    .fb_pan_display = drm_fb_helper_pan_display,
    .fb_setcmap = vigs_fbdev_setcmap,
    .fb_debug_enter = drm_fb_helper_debug_enter,
    .fb_debug_leave = drm_fb_helper_debug_leave,
};

static int vigs_fbdev_probe_once(struct drm_fb_helper *helper,
                                 struct drm_fb_helper_surface_size *sizes)
{
    struct vigs_fbdev *vigs_fbdev = fbdev_to_vigs_fbdev(helper);
    struct vigs_device *vigs_dev = helper->dev->dev_private;
    struct vigs_surface *fb_sfc;
    struct vigs_framebuffer *vigs_fb;
    struct fb_info *fbi;
    struct drm_mode_fb_cmd2 mode_cmd = { 0 };
    vigsp_surface_format format;
    unsigned long offset;
    int dpi;
    int ret;
    struct drm_connector *connector;

    DRM_DEBUG_KMS("%dx%dx%d\n",
                  sizes->surface_width,
                  sizes->surface_height,
                  sizes->surface_bpp);

    mode_cmd.width = sizes->surface_width;
    mode_cmd.height = sizes->surface_height;
    mode_cmd.pitches[0] = sizes->surface_width * (sizes->surface_bpp >> 3);
    mode_cmd.pixel_format = drm_mode_legacy_fb_format(sizes->surface_bpp,
                                                      sizes->surface_depth);

    switch (mode_cmd.pixel_format) {
    case DRM_FORMAT_XRGB8888:
        format = vigsp_surface_bgrx8888;
        break;
    case DRM_FORMAT_ARGB8888:
        format = vigsp_surface_bgra8888;
        break;
    default:
        DRM_DEBUG_KMS("unsupported pixel format: %u\n", mode_cmd.pixel_format);
        ret = -EINVAL;
        goto fail1;
    }

    fbi = framebuffer_alloc(0, &vigs_dev->pci_dev->dev);

    if (!fbi) {
        DRM_ERROR("failed to allocate fb info\n");
        ret = -ENOMEM;
        goto fail1;
    }

    ret = vigs_surface_create(vigs_dev,
                              mode_cmd.width,
                              mode_cmd.height,
                              mode_cmd.pitches[0],
                              format,
                              true,
                              &fb_sfc);

    if (ret != 0) {
        goto fail2;
    }

    ret = vigs_framebuffer_create(vigs_dev,
                                  &mode_cmd,
                                  fb_sfc,
                                  &vigs_fb);

    drm_gem_object_unreference_unlocked(&fb_sfc->gem.base);

    if (ret != 0) {
        goto fail2;
    }

    helper->fb = &vigs_fb->base;
    helper->fbdev = fbi;

    fbi->par = helper;
    fbi->flags = FBINFO_DEFAULT | FBINFO_CAN_FORCE_OUTPUT;
    fbi->fbops = &vigs_fbdev_ops;

    ret = fb_alloc_cmap(&fbi->cmap, 256, 0);

    if (ret != 0) {
        DRM_ERROR("failed to allocate cmap\n");
        goto fail3;
    }

    /*
     * This is a hack to make fbdev work without calling
     * 'vigs_framebuffer_pin'. VRAM is precious resource and we
     * don't want to give it away to fbdev just to show
     * that "kernel loading" thing. Here we assume that
     * GEM zero is always located at offset 0 in VRAM and just map
     * it and give it to fbdev. If later, when X starts for example,
     * one will attempt to write to /dev/fb0 then he'll probably
     * write to some GEM's memory, but we don't care.
     */
    vigs_fbdev->kptr = ioremap(vigs_dev->vram_base,
                               vigs_gem_size(&fb_sfc->gem));

    if (!vigs_fbdev->kptr) {
        goto fail4;
    }

    strcpy(fbi->fix.id, "VIGS");

    drm_fb_helper_fill_fix(fbi, vigs_fb->base.pitches[0], vigs_fb->base.depth);
    drm_fb_helper_fill_var(fbi, helper, vigs_fb->base.width, vigs_fb->base.height);

    /*
     * Setup DPI.
     * @{
     */

    dpi = vigs_output_get_dpi();
    fbi->var.height = vigs_output_get_phys_height(dpi, fbi->var.yres);
    fbi->var.width = vigs_output_get_phys_width(dpi, fbi->var.xres);

    /*
     * Walk all connectors and set display_info.
     */

    list_for_each_entry(connector, &vigs_dev->drm_dev->mode_config.connector_list, head) {
        connector->display_info.width_mm = fbi->var.width;
        connector->display_info.height_mm = fbi->var.height;
    }

    /*
     * @}
     */

    /*
     * TODO: Play around with xoffset/yoffset, make sure this code works.
     */

    offset = fbi->var.xoffset * (vigs_fb->base.bits_per_pixel >> 3);
    offset += fbi->var.yoffset * vigs_fb->base.pitches[0];

    /*
     * TODO: "vram_base + ..." - not nice, make a function for this.
     */
    fbi->fix.smem_start = vigs_dev->vram_base +
                          0 +
                          offset;
    fbi->screen_base = vigs_fbdev->kptr + offset;
    fbi->screen_size = fbi->fix.smem_len = vigs_fb->base.width *
                                           vigs_fb->base.height *
                                           (vigs_fb->base.bits_per_pixel >> 3);

    return 0;

fail4:
    fb_dealloc_cmap(&fbi->cmap);
fail3:
    helper->fb = NULL;
    helper->fbdev = NULL;
fail2:
    framebuffer_release(fbi);
fail1:

    return ret;
}

static int vigs_fbdev_probe(struct drm_fb_helper *helper,
                            struct drm_fb_helper_surface_size *sizes)
{
    int ret = 0;

    DRM_DEBUG_KMS("enter\n");

    /*
     * With !helper->fb, it means that this function is called first time
     * and after that, the helper->fb would be used as clone mode.
     */

    if (!helper->fb) {
        ret = vigs_fbdev_probe_once(helper, sizes);

        if (ret >= 0) {
            ret = 1;
        }
    }

    return ret;
}

static struct drm_fb_helper_funcs vigs_fbdev_funcs =
{
    .fb_probe = vigs_fbdev_probe,
};

int vigs_fbdev_create(struct vigs_device *vigs_dev,
                      struct vigs_fbdev **vigs_fbdev)
{
    int ret = 0;

    DRM_DEBUG_KMS("enter\n");

    *vigs_fbdev = kzalloc(sizeof(**vigs_fbdev), GFP_KERNEL);

    if (!*vigs_fbdev) {
        ret = -ENOMEM;
        goto fail1;
    }

    (*vigs_fbdev)->base.funcs = &vigs_fbdev_funcs;

    ret = drm_fb_helper_init(vigs_dev->drm_dev,
                             &(*vigs_fbdev)->base,
                             1, 1);

    if (ret != 0) {
        DRM_ERROR("unable to init fb_helper: %d\n", ret);
        goto fail2;
    }

    drm_fb_helper_single_add_all_connectors(&(*vigs_fbdev)->base);
    drm_fb_helper_initial_config(&(*vigs_fbdev)->base, 32);

    return 0;

fail2:
    kfree(*vigs_fbdev);
fail1:
    *vigs_fbdev = NULL;

    return ret;
}

void vigs_fbdev_destroy(struct vigs_fbdev *vigs_fbdev)
{
    struct fb_info *fbi = vigs_fbdev->base.fbdev;
    struct drm_framebuffer *fb;

    DRM_DEBUG_KMS("enter\n");

    if (fbi) {
        unregister_framebuffer(fbi);
        fb_dealloc_cmap(&fbi->cmap);
        framebuffer_release(fbi);
    }

    fb = vigs_fbdev->base.fb;

    drm_fb_helper_fini(&vigs_fbdev->base);

    if (vigs_fbdev->kptr) {
        iounmap(vigs_fbdev->kptr);
    }

    drm_framebuffer_unregister_private(fb);
    drm_framebuffer_remove(fb);

    kfree(vigs_fbdev);
}

void vigs_fbdev_output_poll_changed(struct vigs_fbdev *vigs_fbdev)
{
    DRM_DEBUG_KMS("enter\n");

    drm_fb_helper_hotplug_event(&vigs_fbdev->base);
}

void vigs_fbdev_restore_mode(struct vigs_fbdev *vigs_fbdev)
{
    DRM_DEBUG_KMS("enter\n");

    drm_modeset_lock_all(vigs_fbdev->base.dev);
    drm_fb_helper_restore_fbdev_mode(&vigs_fbdev->base);
    drm_modeset_unlock_all(vigs_fbdev->base.dev);
}
