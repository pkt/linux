#ifndef _VIGS_DP_H_
#define _VIGS_DP_H_

#include "drmP.h"
#include "vigs_protocol.h"
#include <drm/vigs_drm.h>

struct vigs_device;
struct vigs_surface;

struct vigs_dp_fb_buf
{
    /*
     * These are weak pointers, no reference is kept
     * for them. When surface is destroyed they're
     * automatically reset to NULL. Must be
     * accessed only with drm_device::struct_mutex held.
     * @{
     */

    struct vigs_surface *y;
    struct vigs_surface *c;

    /*
     * @}
     */
};

struct vigs_dp_plane
{
    struct vigs_dp_fb_buf fb_bufs[DRM_VIGS_NUM_DP_FB_BUF];
};

struct vigs_dp
{
    struct vigs_dp_plane planes[VIGS_MAX_PLANES];
};

int vigs_dp_create(struct vigs_device *vigs_dev,
                   struct vigs_dp **dp);

void vigs_dp_destroy(struct vigs_dp *dp);

/*
 * Must be called with drm_device::struct_mutex held.
 * @{
 */

void vigs_dp_remove_surface(struct vigs_dp *dp, struct vigs_surface *sfc);

/*
 * @}
 */

/*
 * IOCTLs
 * @{
 */

int vigs_dp_surface_create_ioctl(struct drm_device *drm_dev,
                                 void *data,
                                 struct drm_file *file_priv);

int vigs_dp_surface_open_ioctl(struct drm_device *drm_dev,
                               void *data,
                               struct drm_file *file_priv);

/*
 * @}
 */

#endif
