#ifndef _VIGS_FRAMEBUFFER_H_
#define _VIGS_FRAMEBUFFER_H_

#include "drmP.h"
#include "vigs_protocol.h"

struct vigs_device;
struct vigs_comm;
struct vigs_surface;

struct vigs_framebuffer
{
    struct drm_framebuffer base;

    /*
     * Cached from 'vigs_device' for speed.
     */
    struct vigs_comm *comm;

    struct vigs_surface *surfaces[4];
};

static inline struct vigs_framebuffer *fb_to_vigs_fb(struct drm_framebuffer *fb)
{
    return container_of(fb, struct vigs_framebuffer, base);
}

void vigs_framebuffer_config_init(struct vigs_device *vigs_dev);

/*
 * Creates a framebuffer object.
 * Note that it also gets a reference to 'fb_gem' (in case of success), so
 * don't forget to unreference it in the calling code.
 */
int vigs_framebuffer_create(struct vigs_device *vigs_dev,
                            struct drm_mode_fb_cmd2 *mode_cmd,
                            struct vigs_surface *fb_sfc,
                            struct vigs_framebuffer **vigs_fb);

int vigs_framebuffer_pin(struct vigs_framebuffer *vigs_fb);
void vigs_framebuffer_unpin(struct vigs_framebuffer *vigs_fb);

#endif
