#include "vigs_execbuffer.h"
#include "vigs_device.h"
#include "vigs_surface.h"
#include "vigs_comm.h"
#include "vigs_fence.h"
#include <drm/vigs_drm.h>

union vigs_request
{
    struct vigsp_cmd_update_vram_request *update_vram;
    struct vigsp_cmd_update_gpu_request *update_gpu;
    struct vigsp_cmd_copy_request *copy;
    struct vigsp_cmd_solid_fill_request *solid_fill;
    struct vigsp_cmd_ga_copy_request *ga_copy;
    void *data;
};

static int vigs_execbuffer_validate_buffer(struct vigs_device *vigs_dev,
                                           struct vigs_validate_buffer *buffer,
                                           struct list_head* list,
                                           vigsp_surface_id sfc_id,
                                           vigsp_cmd cmd,
                                           int which,
                                           void *data)
{
    struct vigs_surface *sfc = vigs_device_reference_surface(vigs_dev, sfc_id);
    struct vigs_validate_buffer *tmp;

    if (!sfc) {
        DRM_ERROR("Surface %u not found\n", sfc_id);
        return -EINVAL;
    }

    buffer->base.bo = &sfc->gem.bo;
    buffer->cmd = cmd;
    buffer->which = which;
    buffer->data = data;

    list_for_each_entry(tmp, list, base.head) {
        if (tmp->base.bo == buffer->base.bo) {
            /*
             * Already on the list, we're done.
             */
            return 0;
        }
    }

    list_add_tail(&buffer->base.head, list);

    return 0;
}

static void vigs_execbuffer_clear_validation(struct vigs_validate_buffer *buffer)
{
    struct vigs_gem_object *gem = bo_to_vigs_gem(buffer->base.bo);

    drm_gem_object_unreference(&gem->base);
}

static void vigs_execbuffer_destroy(struct vigs_gem_object *gem)
{
}

int vigs_execbuffer_create(struct vigs_device *vigs_dev,
                           unsigned long size,
                           bool kernel,
                           struct vigs_execbuffer **execbuffer)
{
    int ret = 0;

    *execbuffer = kzalloc(sizeof(**execbuffer), GFP_KERNEL);

    if (!*execbuffer) {
        ret = -ENOMEM;
        goto fail1;
    }

    ret = vigs_gem_init(&(*execbuffer)->gem,
                        vigs_dev,
                        VIGS_GEM_TYPE_EXECBUFFER,
                        size,
                        kernel,
                        &vigs_execbuffer_destroy);

    if (ret != 0) {
        goto fail1;
    }

    return 0;

fail1:
    *execbuffer = NULL;

    return ret;
}

int vigs_execbuffer_validate_buffers(struct vigs_execbuffer *execbuffer,
                                     struct list_head* list,
                                     struct vigs_validate_buffer **buffers,
                                     int *num_buffers,
                                     bool *sync)
{
    struct vigs_device *vigs_dev = execbuffer->gem.base.dev->dev_private;
    void *data = execbuffer->gem.kptr;
    u32 data_size = vigs_gem_size(&execbuffer->gem);
    struct vigsp_cmd_batch_header *batch_header = data;
    struct vigsp_cmd_request_header *request_header =
        (struct vigsp_cmd_request_header*)(batch_header + 1);
    union vigs_request request;
    int num_commands = 0, ret = 0;

    *num_buffers = 0;
    *sync = false;

    /*
     * GEM is always at least PAGE_SIZE long, so don't check
     * if batch header is out of bounds.
     */

    while ((void*)request_header <
           ((void*)(batch_header + 1) + batch_header->size)) {
        if (((void*)(request_header) + sizeof(*request_header)) >
            (data + data_size)) {
            DRM_ERROR("request header outside of GEM\n");
            ret = -EINVAL;
            goto fail1;
        }

        if (((void*)(request_header + 1) + request_header->size) >
            (data + data_size)) {
            DRM_ERROR("request data outside of GEM\n");
            ret = -EINVAL;
            goto fail1;
        }

        request.data = (request_header + 1);

        switch (request_header->cmd) {
        case vigsp_cmd_update_vram:
        case vigsp_cmd_update_gpu:
            *sync = true;
            *num_buffers += 1;
            break;
        case vigsp_cmd_copy:
            *num_buffers += 2;
            break;
        case vigsp_cmd_solid_fill:
            *num_buffers += 1;
            break;
        case vigsp_cmd_ga_copy:
            *num_buffers += 2;
            break;
        default:
            break;
        }

        request_header =
            (struct vigsp_cmd_request_header*)(request.data +
                                               request_header->size);

        ++num_commands;
    }

    *buffers = kmalloc(*num_buffers * sizeof(**buffers), GFP_KERNEL);

    if (!*buffers) {
        ret = -ENOMEM;
        goto fail1;
    }

    request_header = (struct vigsp_cmd_request_header*)(batch_header + 1);

    mutex_lock(&vigs_dev->drm_dev->struct_mutex);

    *num_buffers = 0;

    while (--num_commands >= 0) {
        request.data = (request_header + 1);

        switch (request_header->cmd) {
        case vigsp_cmd_update_vram:
            ret = vigs_execbuffer_validate_buffer(vigs_dev,
                                                  &(*buffers)[*num_buffers],
                                                  list,
                                                  request.update_vram->sfc_id,
                                                  request_header->cmd,
                                                  0,
                                                  request.data);

            if (ret != 0) {
                goto fail2;
            }

            ++*num_buffers;

            break;
        case vigsp_cmd_update_gpu:
            ret = vigs_execbuffer_validate_buffer(vigs_dev,
                                                  &(*buffers)[*num_buffers],
                                                  list,
                                                  request.update_gpu->sfc_id,
                                                  request_header->cmd,
                                                  0,
                                                  request.data);

            if (ret != 0) {
                goto fail2;
            }

            ++*num_buffers;

            break;
        case vigsp_cmd_copy:
            ret = vigs_execbuffer_validate_buffer(vigs_dev,
                                                  &(*buffers)[*num_buffers],
                                                  list,
                                                  request.copy->src_id,
                                                  request_header->cmd,
                                                  0,
                                                  request.data);

            if (ret != 0) {
                goto fail2;
            }

            ++*num_buffers;

            ret = vigs_execbuffer_validate_buffer(vigs_dev,
                                                  &(*buffers)[*num_buffers],
                                                  list,
                                                  request.copy->dst_id,
                                                  request_header->cmd,
                                                  1,
                                                  request.data);

            if (ret != 0) {
                goto fail2;
            }

            ++*num_buffers;

            break;
        case vigsp_cmd_solid_fill:
            ret = vigs_execbuffer_validate_buffer(vigs_dev,
                                                  &(*buffers)[*num_buffers],
                                                  list,
                                                  request.solid_fill->sfc_id,
                                                  request_header->cmd,
                                                  0,
                                                  request.data);

            if (ret != 0) {
                goto fail2;
            }

            ++*num_buffers;

            break;
        case vigsp_cmd_ga_copy:
            ret = vigs_execbuffer_validate_buffer(vigs_dev,
                                                  &(*buffers)[*num_buffers],
                                                  list,
                                                  request.ga_copy->src_id,
                                                  request_header->cmd,
                                                  0,
                                                  request.data);

            if (ret != 0) {
                goto fail2;
            }

            ++*num_buffers;

            ret = vigs_execbuffer_validate_buffer(vigs_dev,
                                                  &(*buffers)[*num_buffers],
                                                  list,
                                                  request.ga_copy->dst_id,
                                                  request_header->cmd,
                                                  1,
                                                  request.data);

            if (ret != 0) {
                goto fail2;
            }

            ++*num_buffers;

            break;
        default:
            break;
        }

        request_header =
            (struct vigsp_cmd_request_header*)(request.data +
                                               request_header->size);
    }

    mutex_unlock(&vigs_dev->drm_dev->struct_mutex);

    return 0;

fail2:
    while (--*num_buffers >= 0) {
        vigs_execbuffer_clear_validation(&(*buffers)[*num_buffers]);
    }
    mutex_unlock(&vigs_dev->drm_dev->struct_mutex);
    kfree(*buffers);
fail1:
    *buffers = NULL;

    return ret;
}

void vigs_execbuffer_process_buffers(struct vigs_execbuffer *execbuffer,
                                     struct vigs_validate_buffer *buffers,
                                     int num_buffers,
                                     bool *sync)
{
    union vigs_request request;
    struct vigs_gem_object *gem;
    struct vigs_surface *sfc;
    int i;

    for (i = 0; i < num_buffers; ++i) {
        request.data = buffers[i].data;
        gem = bo_to_vigs_gem(buffers[i].base.bo);
        sfc = vigs_gem_to_vigs_surface(gem);

        switch (buffers[i].cmd) {
        case vigsp_cmd_update_vram:
            if (vigs_gem_in_vram(&sfc->gem)) {
                if (vigs_surface_need_vram_update(sfc)) {
                    request.update_vram->offset = vigs_gem_offset(&sfc->gem);
                    sfc->is_gpu_dirty = false;
                } else {
                    DRM_DEBUG_DRIVER("Surface %u doesn't need to be updated, ignoring update_vram\n",
                                     request.update_vram->sfc_id);
                    request.update_vram->sfc_id = 0;
                }
            } else {
                DRM_DEBUG_DRIVER("Surface %u not in VRAM, ignoring update_vram\n",
                                 request.update_vram->sfc_id);
                request.update_vram->sfc_id = 0;
            }
            break;
        case vigsp_cmd_update_gpu:
            if (vigs_gem_in_vram(&sfc->gem)) {
                if (vigs_surface_need_gpu_update(sfc)) {
                    request.update_gpu->offset = vigs_gem_offset(&sfc->gem);
                    sfc->is_gpu_dirty = false;
                } else {
                    DRM_DEBUG_DRIVER("Surface %u doesn't need to be updated, ignoring update_gpu\n",
                                     request.update_gpu->sfc_id);
                    request.update_gpu->sfc_id = 0;
                }
            } else {
                DRM_DEBUG_DRIVER("Surface %u not in VRAM, ignoring update_gpu\n",
                                 request.update_gpu->sfc_id);
                request.update_gpu->sfc_id = 0;
            }
            break;
        case vigsp_cmd_copy:
            if (buffers[i].which && vigs_gem_in_vram(&sfc->gem)) {
                sfc->is_gpu_dirty = true;
            }
            break;
        case vigsp_cmd_solid_fill:
            if (vigs_gem_in_vram(&sfc->gem)) {
                sfc->is_gpu_dirty = true;
            }
            break;
        case vigsp_cmd_ga_copy:
            if (buffers[i].which && vigs_gem_in_vram(&sfc->gem)) {
                sfc->is_gpu_dirty = true;
            } else if (buffers[i].which == 0) {
                if (vigs_gem_in_vram(&sfc->gem)) {
                    request.ga_copy->src_scanout = true;
                    request.ga_copy->src_offset = vigs_gem_offset(&sfc->gem);
                    *sync = true;
                } else {
                    request.ga_copy->src_scanout = false;
                    request.ga_copy->src_offset = 0;
                }
            }
            break;
        default:
            break;
        }
    }
}

void vigs_execbuffer_fence(struct vigs_execbuffer *execbuffer,
                           struct vigs_fence *fence)
{
    struct vigsp_cmd_batch_header *batch_header = execbuffer->gem.kptr;

    batch_header->fence_seq = fence->seq;
}

void vigs_execbuffer_clear_validations(struct vigs_execbuffer *execbuffer,
                                       struct vigs_validate_buffer *buffers,
                                       int num_buffers)
{
    struct vigs_device *vigs_dev = execbuffer->gem.base.dev->dev_private;
    int i;

    mutex_lock(&vigs_dev->drm_dev->struct_mutex);

    for (i = 0; i < num_buffers; ++i) {
        vigs_execbuffer_clear_validation(&buffers[i]);
    }

    mutex_unlock(&vigs_dev->drm_dev->struct_mutex);

    kfree(buffers);
}

int vigs_execbuffer_create_ioctl(struct drm_device *drm_dev,
                                 void *data,
                                 struct drm_file *file_priv)
{
    struct vigs_device *vigs_dev = drm_dev->dev_private;
    struct drm_vigs_create_execbuffer *args = data;
    struct vigs_execbuffer *execbuffer = NULL;
    uint32_t handle;
    int ret;

    ret = vigs_execbuffer_create(vigs_dev,
                                 args->size,
                                 false,
                                 &execbuffer);

    if (ret != 0) {
        return ret;
    }

    ret = drm_gem_handle_create(file_priv,
                                &execbuffer->gem.base,
                                &handle);

    drm_gem_object_unreference_unlocked(&execbuffer->gem.base);

    if (ret == 0) {
        args->size = vigs_gem_size(&execbuffer->gem);
        args->handle = handle;
    }

    return ret;
}

int vigs_execbuffer_exec_ioctl(struct drm_device *drm_dev,
                               void *data,
                               struct drm_file *file_priv)
{
    struct vigs_device *vigs_dev = drm_dev->dev_private;
    struct drm_vigs_exec *args = data;
    struct drm_gem_object *gem;
    struct vigs_gem_object *vigs_gem;
    struct vigs_execbuffer *execbuffer;
    struct ww_acquire_ctx ticket;
    struct list_head list;
    struct vigs_validate_buffer *buffers;
    int num_buffers = 0;
    struct vigs_fence *fence = NULL;
    bool sync = false;
    int ret = 0;

    INIT_LIST_HEAD(&list);

    gem = drm_gem_object_lookup(drm_dev, file_priv, args->handle);

    if (gem == NULL) {
        ret = -ENOENT;
        goto out1;
    }

    vigs_gem = gem_to_vigs_gem(gem);

    if (vigs_gem->type != VIGS_GEM_TYPE_EXECBUFFER) {
        ret = -ENOENT;
        goto out2;
    }

    execbuffer = vigs_gem_to_vigs_execbuffer(vigs_gem);

    vigs_gem_reserve(vigs_gem);

    /*
     * Never unmap for optimization, but we got to be careful,
     * worst case scenario is when whole RAM BAR is mapped into kernel.
     */
    ret = vigs_gem_kmap(vigs_gem);

    if (ret != 0) {
        vigs_gem_unreserve(vigs_gem);
        goto out2;
    }

    vigs_gem_unreserve(vigs_gem);

    ret = vigs_execbuffer_validate_buffers(execbuffer,
                                           &list,
                                           &buffers,
                                           &num_buffers,
                                           &sync);

    if (ret != 0) {
        goto out2;
    }

    if (list_empty(&list)) {
        vigs_comm_exec(vigs_dev->comm, execbuffer);
    } else {
        ret = ttm_eu_reserve_buffers(&ticket, &list);

        if (ret != 0) {
            goto out3;
        }

        ret = vigs_fence_create(vigs_dev->fenceman, &fence);

        if (ret != 0) {
            ttm_eu_backoff_reservation(&ticket, &list);
            goto out3;
        }

        vigs_execbuffer_process_buffers(execbuffer, buffers, num_buffers, &sync);

        vigs_execbuffer_fence(execbuffer, fence);

        vigs_comm_exec(vigs_dev->comm, execbuffer);

        ttm_eu_fence_buffer_objects(&ticket, &list, fence);

        if (sync) {
            vigs_fence_wait(fence, false);
        }

        vigs_fence_unref(fence);
    }

out3:
    vigs_execbuffer_clear_validations(execbuffer, buffers, num_buffers);
out2:
    drm_gem_object_unreference_unlocked(gem);
out1:
    return ret;
}
