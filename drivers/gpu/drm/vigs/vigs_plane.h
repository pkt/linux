#ifndef _VIGS_PLANE_H_
#define _VIGS_PLANE_H_

#include "drmP.h"

struct vigs_device;

struct vigs_plane
{
    struct drm_plane base;

    u32 index;

    unsigned int src_x;
    unsigned int src_y;
    unsigned int src_w;
    unsigned int src_h;

    int crtc_x;
    int crtc_y;
    unsigned int crtc_w;
    unsigned int crtc_h;

    int z_pos;
    int hflip;
    int vflip;
    int rotation;

    bool enabled;
};

static inline struct vigs_plane *plane_to_vigs_plane(struct drm_plane *plane)
{
    return container_of(plane, struct vigs_plane, base);
}

int vigs_plane_init(struct vigs_device *vigs_dev, u32 index);

/*
 * IOCTLs
 * @{
 */

int vigs_plane_set_zpos_ioctl(struct drm_device *drm_dev,
                              void *data,
                              struct drm_file *file_priv);

int vigs_plane_set_transform_ioctl(struct drm_device *drm_dev,
                                   void *data,
                                   struct drm_file *file_priv);

/*
 * @}
 */

#endif
