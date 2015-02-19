#ifndef _VIGS_CRTC_H_
#define _VIGS_CRTC_H_

#include "drmP.h"

struct vigs_device;

struct vigs_crtc
{
    struct drm_crtc base;
};

static inline struct vigs_crtc *crtc_to_vigs_crtc(struct drm_crtc *crtc)
{
    return container_of(crtc, struct vigs_crtc, base);
}

int vigs_crtc_init(struct vigs_device *vigs_dev);

#endif
