#include "vigs_fence.h"
#include "vigs_fenceman.h"
#include "vigs_file.h"
#include "vigs_device.h"
#include "vigs_comm.h"
#include <drm/vigs_drm.h>

static void vigs_fence_cleanup(struct vigs_fence *fence)
{
}

static void vigs_fence_destroy(struct vigs_fence *fence)
{
    vigs_fence_cleanup(fence);
    kfree(fence);
}

static void vigs_user_fence_destroy(struct vigs_fence *fence)
{
    struct vigs_user_fence *user_fence = vigs_fence_to_vigs_user_fence(fence);

    vigs_fence_cleanup(&user_fence->fence);
    ttm_base_object_kfree(user_fence, base);
}

static void vigs_fence_release_locked(struct kref *kref)
{
    struct vigs_fence *fence = kref_to_vigs_fence(kref);

    DRM_DEBUG_DRIVER("Fence destroyed (seq = %u, signaled = %u)\n",
                     fence->seq,
                     fence->signaled);

    list_del_init(&fence->list);
    fence->destroy(fence);
}

static void vigs_user_fence_refcount_release(struct ttm_base_object **base)
{
    struct ttm_base_object *tmp = *base;
    struct vigs_user_fence *user_fence = base_to_vigs_user_fence(tmp);

    vigs_fence_unref(&user_fence->fence);
    *base = NULL;
}

static void vigs_fence_init(struct vigs_fence *fence,
                            struct vigs_fenceman *fenceman,
                            void (*destroy)(struct vigs_fence*))
{
    unsigned long flags;

    kref_init(&fence->kref);
    INIT_LIST_HEAD(&fence->list);
    fence->fenceman = fenceman;
    fence->signaled = false;
    init_waitqueue_head(&fence->wait);
    fence->destroy = destroy;

    spin_lock_irqsave(&fenceman->lock, flags);

    fence->seq = vigs_fence_seq_next(fenceman->seq);
    fenceman->seq = fence->seq;

    list_add_tail(&fence->list, &fenceman->fence_list);

    spin_unlock_irqrestore(&fenceman->lock, flags);

    DRM_DEBUG_DRIVER("Fence created (seq = %u)\n", fence->seq);
}

int vigs_fence_create(struct vigs_fenceman *fenceman,
                      struct vigs_fence **fence)
{
    int ret = 0;

    *fence = kzalloc(sizeof(**fence), GFP_KERNEL);

    if (!*fence) {
        ret = -ENOMEM;
        goto fail1;
    }

    vigs_fence_init(*fence, fenceman, &vigs_fence_destroy);

    return 0;

fail1:
    *fence = NULL;

    return ret;
}

int vigs_user_fence_create(struct vigs_fenceman *fenceman,
                           struct drm_file *file_priv,
                           struct vigs_user_fence **user_fence,
                           uint32_t *handle)
{
    struct vigs_file *vigs_file = file_priv->driver_priv;
    int ret = 0;

    *user_fence = kzalloc(sizeof(**user_fence), GFP_KERNEL);

    if (!*user_fence) {
        ret = -ENOMEM;
        goto fail1;
    }

    vigs_fence_init(&(*user_fence)->fence, fenceman, &vigs_user_fence_destroy);

    ret = ttm_base_object_init(vigs_file->obj_file,
                               &(*user_fence)->base, false,
                               VIGS_FENCE_TYPE,
                               &vigs_user_fence_refcount_release,
                               NULL);

    if (ret != 0) {
        goto fail2;
    }

    /*
     * For ttm_base_object.
     */
    vigs_fence_ref(&(*user_fence)->fence);

    *handle = (*user_fence)->base.hash.key;

    return 0;

fail2:
    vigs_fence_cleanup(&(*user_fence)->fence);
    kfree(*user_fence);
fail1:
    *user_fence = NULL;

    return ret;
}

int vigs_fence_wait(struct vigs_fence *fence, bool interruptible)
{
    long ret = 0;

    if (vigs_fence_signaled(fence)) {
        DRM_DEBUG_DRIVER("Fence wait (seq = %u, signaled = %u)\n",
                         fence->seq,
                         fence->signaled);
        return 0;
    }

    DRM_DEBUG_DRIVER("Fence wait (seq = %u)\n", fence->seq);

    if (interruptible) {
        ret = wait_event_interruptible(fence->wait, vigs_fence_signaled(fence));
    } else {
        wait_event(fence->wait, vigs_fence_signaled(fence));
    }

    if (ret != 0) {
        DRM_INFO("Fence wait interrupted (seq = %u) = %ld\n", fence->seq, ret);
    } else {
        DRM_DEBUG_DRIVER("Fence wait done (seq = %u)\n", fence->seq);
    }

    return ret;
}

bool vigs_fence_signaled(struct vigs_fence *fence)
{
    unsigned long flags;
    bool signaled;

    spin_lock_irqsave(&fence->fenceman->lock, flags);

    signaled = fence->signaled;

    spin_unlock_irqrestore(&fence->fenceman->lock, flags);

    return signaled;
}

void vigs_fence_ref(struct vigs_fence *fence)
{
    if (unlikely(!fence)) {
        return;
    }

    kref_get(&fence->kref);
}

void vigs_fence_unref(struct vigs_fence *fence)
{
    struct vigs_fenceman *fenceman;

    if (unlikely(!fence)) {
        return;
    }

    fenceman = fence->fenceman;

    spin_lock_irq(&fenceman->lock);
    BUG_ON(atomic_read(&fence->kref.refcount) == 0);
    kref_put(&fence->kref, vigs_fence_release_locked);
    spin_unlock_irq(&fenceman->lock);
}

int vigs_fence_create_ioctl(struct drm_device *drm_dev,
                            void *data,
                            struct drm_file *file_priv)
{
    struct vigs_device *vigs_dev = drm_dev->dev_private;
    struct vigs_file *vigs_file = file_priv->driver_priv;
    struct drm_vigs_create_fence *args = data;
    struct vigs_user_fence *user_fence;
    uint32_t handle;
    int ret;

    ret = vigs_user_fence_create(vigs_dev->fenceman,
                                 file_priv,
                                 &user_fence,
                                 &handle);

    if (ret != 0) {
        goto out;
    }

    if (args->send) {
        ret = vigs_comm_fence(vigs_dev->comm, &user_fence->fence);

        if (ret != 0) {
            ttm_ref_object_base_unref(vigs_file->obj_file,
                                      handle,
                                      TTM_REF_USAGE);
            goto out;
        }
    }

    args->handle = handle;
    args->seq = user_fence->fence.seq;

out:
    vigs_fence_unref(&user_fence->fence);

    return ret;
}

int vigs_fence_wait_ioctl(struct drm_device *drm_dev,
                          void *data,
                          struct drm_file *file_priv)
{
    struct vigs_file *vigs_file = file_priv->driver_priv;
    struct drm_vigs_fence_wait *args = data;
    struct ttm_base_object *base;
    struct vigs_user_fence *user_fence;
    int ret;

    base = ttm_base_object_lookup(vigs_file->obj_file, args->handle);

    if (!base) {
        return -ENOENT;
    }

    user_fence = base_to_vigs_user_fence(base);

    ret = vigs_fence_wait(&user_fence->fence, true);

    ttm_base_object_unref(&base);

    return ret;
}

int vigs_fence_signaled_ioctl(struct drm_device *drm_dev,
                              void *data,
                              struct drm_file *file_priv)
{
    struct vigs_file *vigs_file = file_priv->driver_priv;
    struct drm_vigs_fence_signaled *args = data;
    struct ttm_base_object *base;
    struct vigs_user_fence *user_fence;

    base = ttm_base_object_lookup(vigs_file->obj_file, args->handle);

    if (!base) {
        return -ENOENT;
    }

    user_fence = base_to_vigs_user_fence(base);

    args->signaled = vigs_fence_signaled(&user_fence->fence);

    ttm_base_object_unref(&base);

    return 0;
}

int vigs_fence_unref_ioctl(struct drm_device *drm_dev,
                           void *data,
                           struct drm_file *file_priv)
{
    struct vigs_file *vigs_file = file_priv->driver_priv;
    struct drm_vigs_fence_unref *args = data;

    return ttm_ref_object_base_unref(vigs_file->obj_file,
                                     args->handle,
                                     TTM_REF_USAGE);
}
