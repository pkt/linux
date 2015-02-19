#ifndef _VIGS_GEM_H_
#define _VIGS_GEM_H_

#include "drmP.h"
#include <ttm/ttm_bo_driver.h>
#include <ttm/ttm_object.h>

#define VIGS_GEM_TYPE_SURFACE ttm_driver_type0
#define VIGS_GEM_TYPE_EXECBUFFER ttm_driver_type1

struct vigs_device;
struct vigs_gem_object;

typedef void (*vigs_gem_destroy_func)(struct vigs_gem_object *vigs_gem);

struct vigs_gem_object
{
    struct drm_gem_object base;

    struct ttm_buffer_object bo;

    /*
     * Indicates that drm_driver::gem_free_object was called.
     */
    bool freed;

    enum ttm_object_type type;

    /*
     * Valid only after successful call to 'vigs_gem_kmap'.
     * @{
     */

    struct ttm_bo_kmap_obj kmap;
    void *kptr; /* Kernel pointer to buffer data. */

    /*
     * @}
     */

    volatile unsigned pin_count;

    vigs_gem_destroy_func destroy;
};

static inline struct vigs_gem_object *gem_to_vigs_gem(struct drm_gem_object *gem)
{
    return container_of(gem, struct vigs_gem_object, base);
}

static inline struct vigs_gem_object *bo_to_vigs_gem(struct ttm_buffer_object *bo)
{
    return container_of(bo, struct vigs_gem_object, bo);
}

/*
 * Must be called with drm_device::struct_mutex held.
 * @{
 */

static inline bool vigs_gem_freed(struct vigs_gem_object *vigs_gem)
{
    return vigs_gem->freed;
}

/*
 * @}
 */

/*
 * Initializes a gem object. 'size' is automatically rounded up to page size.
 * 'vigs_gem' is kfree'd on failure.
 */
int vigs_gem_init(struct vigs_gem_object *vigs_gem,
                  struct vigs_device *vigs_dev,
                  enum ttm_object_type type,
                  unsigned long size,
                  bool kernel,
                  vigs_gem_destroy_func destroy);

void vigs_gem_cleanup(struct vigs_gem_object *vigs_gem);

/*
 * Buffer size.
 */
static inline unsigned long vigs_gem_size(struct vigs_gem_object *vigs_gem)
{
    return vigs_gem->bo.num_pages << PAGE_SHIFT;
}

/*
 * GEM offset in a placement. In case of execbuffer always the same.
 * In case of surface only valid when GEM is in VRAM.
 */
static inline unsigned long vigs_gem_offset(struct vigs_gem_object *vigs_gem)
{
    return vigs_gem->bo.offset;
}

/*
 * GEM offset relative to DRM_FILE_OFFSET. For kernel buffers it's always 0.
 */
static inline u64 vigs_gem_mmap_offset(struct vigs_gem_object *vigs_gem)
{
    return drm_vma_node_offset_addr(&vigs_gem->bo.vma_node);
}

static inline void vigs_gem_reserve(struct vigs_gem_object *vigs_gem)
{
    int ret;

    ret = ttm_bo_reserve(&vigs_gem->bo, false, false, false, 0);

    BUG_ON(ret != 0);
}

static inline void vigs_gem_unreserve(struct vigs_gem_object *vigs_gem)
{
    ttm_bo_unreserve(&vigs_gem->bo);
}

/*
 * Functions below MUST be called between
 * vigs_gem_reserve/vigs_gem_unreserve.
 * @{
 */

/*
 * Pin/unpin GEM. For execbuffers this is a no-op, since they're always
 * in RAM placement. For surfaces this pins the GEM into VRAM. The
 * operation can fail if there's no room in VRAM and all GEMs currently
 * in VRAM are pinned.
 * @{
 */
int vigs_gem_pin(struct vigs_gem_object *vigs_gem);
void vigs_gem_unpin(struct vigs_gem_object *vigs_gem);
/*
 * @}
 */

/*
 * Surface GEMs must be pinned before calling these.
 * @{
 */
int vigs_gem_kmap(struct vigs_gem_object *vigs_gem);
void vigs_gem_kunmap(struct vigs_gem_object *vigs_gem);
/*
 * @}
 */

/*
 * true if GEM is currently in VRAM. Note that this doesn't
 * necessarily mean that it's pinned.
 */
int vigs_gem_in_vram(struct vigs_gem_object *vigs_gem);

int vigs_gem_wait(struct vigs_gem_object *vigs_gem);

/*
 * @}
 */

/*
 * Driver hooks.
 * @{
 */

void vigs_gem_free_object(struct drm_gem_object *gem);

int vigs_gem_init_object(struct drm_gem_object *gem);

int vigs_gem_open_object(struct drm_gem_object *gem,
                         struct drm_file *file_priv);

void vigs_gem_close_object(struct drm_gem_object *gem,
                           struct drm_file *file_priv);

/*
 * @}
 */

/*
 * IOCTLs
 * @{
 */

int vigs_gem_map_ioctl(struct drm_device *drm_dev,
                       void *data,
                       struct drm_file *file_priv);

int vigs_gem_wait_ioctl(struct drm_device *drm_dev,
                        void *data,
                        struct drm_file *file_priv);

/*
 * @}
 */

/*
 * Dumb
 * @{
 */

int vigs_gem_dumb_create(struct drm_file *file_priv,
                         struct drm_device *drm_dev,
                         struct drm_mode_create_dumb *args);

int vigs_gem_dumb_destroy(struct drm_file *file_priv,
                          struct drm_device *drm_dev,
                          uint32_t handle);

int vigs_gem_dumb_map_offset(struct drm_file *file_priv,
                             struct drm_device *drm_dev,
                             uint32_t handle, uint64_t *offset_p);

/*
 * @}
 */

#endif
