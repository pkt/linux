#ifndef _VIGS_EXECBUFFER_H_
#define _VIGS_EXECBUFFER_H_

#include "drmP.h"
#include "vigs_gem.h"
#include "vigs_protocol.h"
#include <ttm/ttm_execbuf_util.h>

struct vigs_fence;

struct vigs_validate_buffer
{
    struct ttm_validate_buffer base;

    vigsp_cmd cmd;

    int which;

    void *data;
};

struct vigs_execbuffer
{
    /*
     * Must be first member!
     */
    struct vigs_gem_object gem;
};

static inline struct vigs_execbuffer *vigs_gem_to_vigs_execbuffer(struct vigs_gem_object *vigs_gem)
{
    return container_of(vigs_gem, struct vigs_execbuffer, gem);
}

int vigs_execbuffer_create(struct vigs_device *vigs_dev,
                           unsigned long size,
                           bool kernel,
                           struct vigs_execbuffer **execbuffer);

int vigs_execbuffer_validate_buffers(struct vigs_execbuffer *execbuffer,
                                     struct list_head* list,
                                     struct vigs_validate_buffer **buffers,
                                     int *num_buffers,
                                     bool *sync);

void vigs_execbuffer_process_buffers(struct vigs_execbuffer *execbuffer,
                                     struct vigs_validate_buffer *buffers,
                                     int num_buffers,
                                     bool *sync);

void vigs_execbuffer_fence(struct vigs_execbuffer *execbuffer,
                           struct vigs_fence *fence);

void vigs_execbuffer_clear_validations(struct vigs_execbuffer *execbuffer,
                                       struct vigs_validate_buffer *buffers,
                                       int num_buffers);

/*
 * IOCTLs
 * @{
 */

int vigs_execbuffer_create_ioctl(struct drm_device *drm_dev,
                                 void *data,
                                 struct drm_file *file_priv);

int vigs_execbuffer_exec_ioctl(struct drm_device *drm_dev,
                               void *data,
                               struct drm_file *file_priv);

/*
 * @}
 */

#endif
