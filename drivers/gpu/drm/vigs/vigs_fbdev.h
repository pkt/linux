#ifndef _VIGS_FBDEV_H_
#define _VIGS_FBDEV_H_

#include "drmP.h"
#include "drm_fb_helper.h"

struct vigs_device;

struct vigs_fbdev
{
    struct drm_fb_helper base;

    void __iomem *kptr;
};

static inline struct vigs_fbdev *fbdev_to_vigs_fbdev(struct drm_fb_helper *fbdev)
{
    return container_of(fbdev, struct vigs_fbdev, base);
}

int vigs_fbdev_create(struct vigs_device *vigs_dev,
                      struct vigs_fbdev **vigs_fbdev);

void vigs_fbdev_destroy(struct vigs_fbdev *vigs_fbdev);

void vigs_fbdev_output_poll_changed(struct vigs_fbdev *vigs_fbdev);

void vigs_fbdev_restore_mode(struct vigs_fbdev *vigs_fbdev);

#endif
