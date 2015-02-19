#ifndef _VIGS_FENCE_H_
#define _VIGS_FENCE_H_

#include "drmP.h"
#include <ttm/ttm_object.h>

#define VIGS_FENCE_TYPE ttm_driver_type2

struct vigs_fenceman;

struct vigs_fence
{
    struct kref kref;

    struct list_head list;

    struct vigs_fenceman *fenceman;

    uint32_t seq;

    bool signaled;

    wait_queue_head_t wait;

    void (*destroy)(struct vigs_fence *fence);
};

/*
 * Users can access fences via TTM base object mechanism,
 * thus, we need to wrap vigs_fence into vigs_user_fence because
 * not every fence object needs to be referenced from user space.
 * So no point in always having struct ttm_base_object inside vigs_fence.
 */

struct vigs_user_fence
{
    struct ttm_base_object base;

    struct vigs_fence fence;
};

static inline struct vigs_fence *kref_to_vigs_fence(struct kref *kref)
{
    return container_of(kref, struct vigs_fence, kref);
}

static inline struct vigs_user_fence *vigs_fence_to_vigs_user_fence(struct vigs_fence *fence)
{
    return container_of(fence, struct vigs_user_fence, fence);
}

static inline struct vigs_user_fence *base_to_vigs_user_fence(struct ttm_base_object *base)
{
    return container_of(base, struct vigs_user_fence, base);
}

static inline uint32_t vigs_fence_seq_next(uint32_t seq)
{
    if (++seq == 0) {
        ++seq;
    }
    return seq;
}

#define vigs_fence_seq_num_after(a, b) \
    (typecheck(u32, a) && typecheck(u32, b) && ((s32)(b) - (s32)(a) < 0))

#define vigs_fence_seq_num_before(a, b) vigs_fence_seq_num_after(b, a)

#define vigs_fence_seq_num_after_eq(a, b)  \
    ( typecheck(u32, a) && typecheck(u32, b) && \
      ((s32)(a) - (s32)(b) >= 0) )

#define vigs_fence_seq_num_before_eq(a, b) vigs_fence_seq_num_after_eq(b, a)

int vigs_fence_create(struct vigs_fenceman *fenceman,
                      struct vigs_fence **fence);

int vigs_user_fence_create(struct vigs_fenceman *fenceman,
                           struct drm_file *file_priv,
                           struct vigs_user_fence **user_fence,
                           uint32_t *handle);

int vigs_fence_wait(struct vigs_fence *fence, bool interruptible);

bool vigs_fence_signaled(struct vigs_fence *fence);

/*
 * Passing NULL won't hurt, this is for convenience.
 */
void vigs_fence_ref(struct vigs_fence *fence);

/*
 * Passing NULL won't hurt, this is for convenience.
 */
void vigs_fence_unref(struct vigs_fence *fence);

/*
 * IOCTLs
 * @{
 */

int vigs_fence_create_ioctl(struct drm_device *drm_dev,
                            void *data,
                            struct drm_file *file_priv);

int vigs_fence_wait_ioctl(struct drm_device *drm_dev,
                          void *data,
                          struct drm_file *file_priv);

int vigs_fence_signaled_ioctl(struct drm_device *drm_dev,
                              void *data,
                              struct drm_file *file_priv);

int vigs_fence_unref_ioctl(struct drm_device *drm_dev,
                           void *data,
                           struct drm_file *file_priv);

/*
 * @}
 */

#endif
