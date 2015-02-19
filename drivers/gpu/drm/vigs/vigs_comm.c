#include "vigs_comm.h"
#include "vigs_device.h"
#include "vigs_execbuffer.h"
#include "vigs_regs.h"
#include "vigs_fence.h"
#include <drm/vigs_drm.h>

static int vigs_comm_alloc(struct vigs_comm *comm,
                           unsigned long size,
                           void **ptr)
{
    int ret;

    if (!comm->execbuffer ||
        (vigs_gem_size(&comm->execbuffer->gem) < size)) {
        if (comm->execbuffer) {
            drm_gem_object_unreference_unlocked(&comm->execbuffer->gem.base);
            comm->execbuffer = NULL;
        }

        ret = vigs_execbuffer_create(comm->vigs_dev,
                                     size,
                                     true,
                                     &comm->execbuffer);

        if (ret != 0) {
            DRM_ERROR("unable to create execbuffer\n");
            return ret;
        }

        vigs_gem_reserve(&comm->execbuffer->gem);

        ret = vigs_gem_kmap(&comm->execbuffer->gem);

        vigs_gem_unreserve(&comm->execbuffer->gem);

        if (ret != 0) {
            DRM_ERROR("unable to kmap execbuffer\n");

            drm_gem_object_unreference_unlocked(&comm->execbuffer->gem.base);
            comm->execbuffer = NULL;

            return ret;
        }
    }

    *ptr = comm->execbuffer->gem.kptr;

    return 0;
}

static int vigs_comm_prepare(struct vigs_comm *comm,
                             vigsp_cmd cmd,
                             unsigned long request_size,
                             void **request)
{
    int ret;
    void *ptr;
    struct vigsp_cmd_batch_header *batch_header;
    struct vigsp_cmd_request_header *request_header;

    ret = vigs_comm_alloc(comm,
                          sizeof(*batch_header) +
                          sizeof(*request_header) +
                          request_size,
                          &ptr);

    if (ret != 0) {
        return ret;
    }

    batch_header = ptr;
    request_header = (struct vigsp_cmd_request_header*)(batch_header + 1);

    batch_header->fence_seq = 0;
    batch_header->size = sizeof(*request_header) + request_size;

    request_header->cmd = cmd;
    request_header->size = request_size;

    if (request) {
        *request = (request_header + 1);
    }

    return 0;
}

static void vigs_comm_exec_internal(struct vigs_comm *comm,
                                    struct vigs_execbuffer *execbuffer)
{
    writel(vigs_gem_offset(&execbuffer->gem), comm->io_ptr + VIGS_REG_EXEC);
}

static int vigs_comm_init(struct vigs_comm *comm)
{
    int ret;
    struct vigsp_cmd_init_request *request;

    ret = vigs_comm_prepare(comm,
                            vigsp_cmd_init,
                            sizeof(*request),
                            (void**)&request);

    if (ret != 0) {
        return ret;
    }

    request->client_version = VIGS_PROTOCOL_VERSION;
    request->server_version = 0;

    vigs_comm_exec_internal(comm, comm->execbuffer);

    if (request->server_version != VIGS_PROTOCOL_VERSION) {
        DRM_ERROR("protocol version mismatch, expected %u, actual %u\n",
                  VIGS_PROTOCOL_VERSION,
                  request->server_version);
        return -ENODEV;
    }

    return 0;
}

static void vigs_comm_exit(struct vigs_comm *comm)
{
    int ret;

    ret = vigs_comm_prepare(comm, vigsp_cmd_exit, 0, NULL);

    if (ret != 0) {
        return;
    }

    vigs_comm_exec_internal(comm, comm->execbuffer);
}

int vigs_comm_create(struct vigs_device *vigs_dev,
                     struct vigs_comm **comm)
{
    int ret = 0;

    DRM_DEBUG_DRIVER("enter\n");

    *comm = kzalloc(sizeof(**comm), GFP_KERNEL);

    if (!*comm) {
        ret = -ENOMEM;
        goto fail1;
    }

    (*comm)->vigs_dev = vigs_dev;
    (*comm)->io_ptr = vigs_dev->io_map->handle;

    ret = vigs_comm_init(*comm);

    if (ret != 0) {
        goto fail2;
    }

    mutex_init(&(*comm)->mutex);

    return 0;

fail2:
    if ((*comm)->execbuffer) {
        drm_gem_object_unreference_unlocked(&(*comm)->execbuffer->gem.base);
    }
    kfree(*comm);
fail1:
    *comm = NULL;

    return ret;
}

void vigs_comm_destroy(struct vigs_comm *comm)
{
    DRM_DEBUG_DRIVER("enter\n");

    mutex_destroy(&comm->mutex);
    vigs_comm_exit(comm);
    if (comm->execbuffer) {
        drm_gem_object_unreference_unlocked(&comm->execbuffer->gem.base);
    }
    kfree(comm);
}

void vigs_comm_exec(struct vigs_comm *comm,
                    struct vigs_execbuffer *execbuffer)
{
    vigs_comm_exec_internal(comm, execbuffer);
}

int vigs_comm_reset(struct vigs_comm *comm)
{
    int ret;

    mutex_lock(&comm->mutex);

    ret = vigs_comm_prepare(comm, vigsp_cmd_reset, 0, NULL);

    if (ret == 0) {
        vigs_comm_exec_internal(comm, comm->execbuffer);
    }

    mutex_unlock(&comm->mutex);

    return ret;
}

int vigs_comm_create_surface(struct vigs_comm *comm,
                             u32 width,
                             u32 height,
                             u32 stride,
                             vigsp_surface_format format,
                             vigsp_surface_id id)
{
    int ret;
    struct vigsp_cmd_create_surface_request *request;

    DRM_DEBUG_DRIVER("width = %u, height = %u, stride = %u, fmt = %d, id = %u\n",
                     width,
                     height,
                     stride,
                     format,
                     id);

    mutex_lock(&comm->mutex);

    ret = vigs_comm_prepare(comm,
                            vigsp_cmd_create_surface,
                            sizeof(*request),
                            (void**)&request);

    if (ret == 0) {
        request->width = width;
        request->height = height;
        request->stride = stride;
        request->format = format;
        request->id = id;

        vigs_comm_exec_internal(comm, comm->execbuffer);
    }

    mutex_unlock(&comm->mutex);

    return ret;
}

int vigs_comm_destroy_surface(struct vigs_comm *comm, vigsp_surface_id id)
{
    int ret;
    struct vigsp_cmd_destroy_surface_request *request;

    DRM_DEBUG_DRIVER("id = %u\n", id);

    mutex_lock(&comm->mutex);

    ret = vigs_comm_prepare(comm,
                            vigsp_cmd_destroy_surface,
                            sizeof(*request),
                            (void**)&request);

    if (ret == 0) {
        request->id = id;

        vigs_comm_exec_internal(comm, comm->execbuffer);
    }

    mutex_unlock(&comm->mutex);

    return ret;
}

int vigs_comm_set_root_surface(struct vigs_comm *comm,
                               vigsp_surface_id id,
                               bool scanout,
                               vigsp_offset offset)
{
    int ret;
    struct vigs_fence *fence = NULL;
    struct vigsp_cmd_set_root_surface_request *request;

    DRM_DEBUG_DRIVER("id = %u, scanout = %d, offset = %u\n",
                     id, scanout, offset);

    if (scanout) {
        /*
         * We only need to fence this if surface is
         * scanout, this is in order not to display garbage
         * on page flip.
         */

        ret = vigs_fence_create(comm->vigs_dev->fenceman, &fence);

        if (ret != 0) {
            return ret;
        }
    }

    mutex_lock(&comm->mutex);

    ret = vigs_comm_prepare(comm,
                            vigsp_cmd_set_root_surface,
                            sizeof(*request),
                            (void**)&request);

    if (ret == 0) {
        request->id = id;
        request->scanout = scanout;
        request->offset = offset;

        if (fence) {
            vigs_execbuffer_fence(comm->execbuffer, fence);
        }

        vigs_comm_exec_internal(comm, comm->execbuffer);
    }

    mutex_unlock(&comm->mutex);

    if ((ret == 0) && fence) {
        vigs_fence_wait(fence, false);
    }

    vigs_fence_unref(fence);

    return ret;
}

int vigs_comm_update_vram(struct vigs_comm *comm,
                          vigsp_surface_id id,
                          vigsp_offset offset)
{
    int ret;
    struct vigs_fence *fence;
    struct vigsp_cmd_update_vram_request *request;

    DRM_DEBUG_DRIVER("id = %u, offset = %u\n", id, offset);

    ret = vigs_fence_create(comm->vigs_dev->fenceman, &fence);

    if (ret != 0) {
        return ret;
    }

    mutex_lock(&comm->mutex);

    ret = vigs_comm_prepare(comm,
                            vigsp_cmd_update_vram,
                            sizeof(*request),
                            (void**)&request);

    if (ret == 0) {
        request->sfc_id = id;
        request->offset = offset;

        vigs_execbuffer_fence(comm->execbuffer, fence);

        vigs_comm_exec_internal(comm, comm->execbuffer);
    }

    mutex_unlock(&comm->mutex);

    if (ret == 0) {
        vigs_fence_wait(fence, false);
    }

    vigs_fence_unref(fence);

    return ret;
}

int vigs_comm_update_gpu(struct vigs_comm *comm,
                         vigsp_surface_id id,
                         u32 width,
                         u32 height,
                         vigsp_offset offset)
{
    int ret;
    struct vigs_fence *fence;
    struct vigsp_cmd_update_gpu_request *request;

    DRM_DEBUG_DRIVER("id = %u, offset = %u\n", id, offset);

    ret = vigs_fence_create(comm->vigs_dev->fenceman, &fence);

    if (ret != 0) {
        return ret;
    }

    mutex_lock(&comm->mutex);

    ret = vigs_comm_prepare(comm,
                            vigsp_cmd_update_gpu,
                            sizeof(*request) + sizeof(struct vigsp_rect),
                            (void**)&request);

    if (ret == 0) {
        request->sfc_id = id;
        request->offset = offset;
        request->num_entries = 1;
        request->entries[0].pos.x = 0;
        request->entries[0].pos.y = 0;
        request->entries[0].size.w = width;
        request->entries[0].size.h = height;

        vigs_execbuffer_fence(comm->execbuffer, fence);

        vigs_comm_exec_internal(comm, comm->execbuffer);
    }

    mutex_unlock(&comm->mutex);

    if (ret == 0) {
        vigs_fence_wait(fence, false);
    }

    vigs_fence_unref(fence);

    return ret;
}

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
                        int rotation)
{
    int ret;
    struct vigsp_cmd_set_plane_request *request;

    DRM_DEBUG_DRIVER("plane = %u, src_x = %u, src_y = %u, src_w = %u, src_h = %u, dst_x = %d, dst_y = %d, dst_w = %u, dst_h = %u, z_pos = %d, hflip = %d, vflip = %d, rotation = %d\n",
                     plane, src_x, src_y, src_w, src_h,
                     dst_x, dst_y, dst_w, dst_h, z_pos, hflip, vflip,
                     rotation);

    mutex_lock(&comm->mutex);

    ret = vigs_comm_prepare(comm,
                            vigsp_cmd_set_plane,
                            sizeof(*request),
                            (void**)&request);

    if (ret == 0) {
        request->plane = plane;
        request->width = width;
        request->height = height;
        request->format = format;
        memcpy(request->surfaces, surfaces, sizeof(request->surfaces));
        request->src_rect.pos.x = src_x;
        request->src_rect.pos.y = src_y;
        request->src_rect.size.w = src_w;
        request->src_rect.size.h = src_h;
        request->dst_x = dst_x;
        request->dst_y = dst_y;
        request->dst_size.w = dst_w;
        request->dst_size.h = dst_h;
        request->z_pos = z_pos;
        request->hflip = hflip;
        request->vflip = vflip;
        request->rotation = rotation;

        vigs_comm_exec_internal(comm, comm->execbuffer);
    }

    mutex_unlock(&comm->mutex);

    return ret;
}

int vigs_comm_fence(struct vigs_comm *comm, struct vigs_fence *fence)
{
    struct vigsp_cmd_batch_header *batch_header;
    int ret;

    DRM_DEBUG_DRIVER("seq = %u\n", fence->seq);

    mutex_lock(&comm->mutex);

    ret = vigs_comm_alloc(comm,
                          sizeof(*batch_header),
                          (void**)&batch_header);

    if (ret != 0) {
        mutex_unlock(&comm->mutex);

        return ret;
    }

    batch_header->fence_seq = 0;
    batch_header->size = 0;

    vigs_execbuffer_fence(comm->execbuffer, fence);

    vigs_comm_exec_internal(comm, comm->execbuffer);

    mutex_unlock(&comm->mutex);

    return 0;
}

int vigs_comm_get_protocol_version_ioctl(struct drm_device *drm_dev,
                                         void *data,
                                         struct drm_file *file_priv)
{
    struct drm_vigs_get_protocol_version *args = data;

    args->version = VIGS_PROTOCOL_VERSION;

    return 0;
}
