#ifndef _VIGS_COMM_H_
#define _VIGS_COMM_H_

#include <linux/types.h>
#include <linux/mutex.h>
#include "vigs_protocol.h"

struct drm_device;
struct drm_file;
struct vigs_device;
struct vigs_execbuffer;
struct vigs_fence;

struct vigs_comm
{
    struct vigs_device *vigs_dev;

    /*
     * From vigs_device::io_map::handle for speed.
     */
    void __iomem *io_ptr;

    /*
     * For synchronizing all calls.
     */
    struct mutex mutex;

    /*
     * For internal use.
     */
    struct vigs_execbuffer *execbuffer;
};

int vigs_comm_create(struct vigs_device *vigs_dev,
                     struct vigs_comm **comm);

void vigs_comm_destroy(struct vigs_comm *comm);

void vigs_comm_exec(struct vigs_comm *comm,
                    struct vigs_execbuffer *execbuffer);

int vigs_comm_reset(struct vigs_comm *comm);

int vigs_comm_create_surface(struct vigs_comm *comm,
                             u32 width,
                             u32 height,
                             u32 stride,
                             vigsp_surface_format format,
                             vigsp_surface_id id);

int vigs_comm_destroy_surface(struct vigs_comm *comm, vigsp_surface_id id);

int vigs_comm_set_root_surface(struct vigs_comm *comm,
                               vigsp_surface_id id,
                               bool scanout,
                               vigsp_offset offset);

int vigs_comm_update_vram(struct vigs_comm *comm,
                          vigsp_surface_id id,
                          vigsp_offset offset);

int vigs_comm_update_gpu(struct vigs_comm *comm,
                         vigsp_surface_id id,
                         u32 width,
                         u32 height,
                         vigsp_offset offset);

int vigs_comm_set_plane(struct vigs_comm *comm,
                        u32 plane,
                        u32 width,
                        u32 height,
                        vigsp_plane_format format,
                        vigsp_surface_id surfaces[4],
                        unsigned int src_x,
                        unsigned int src_y,
                        unsigned int src_w,
                        unsigned int src_h,
                        int dst_x,
                        int dst_y,
                        unsigned int dst_w,
                        unsigned int dst_h,
                        int z_pos,
                        int hflip,
                        int vflip,
                        int rotation);

int vigs_comm_fence(struct vigs_comm *comm, struct vigs_fence *fence);

/*
 * IOCTLs
 * @{
 */

int vigs_comm_get_protocol_version_ioctl(struct drm_device *drm_dev,
                                         void *data,
                                         struct drm_file *file_priv);

/*
 * @}
 */

#endif
