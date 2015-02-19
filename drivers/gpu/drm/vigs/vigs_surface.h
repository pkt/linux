#ifndef _VIGS_SURFACE_H_
#define _VIGS_SURFACE_H_

#include "drmP.h"
#include "vigs_protocol.h"
#include "vigs_gem.h"

struct vigs_surface
{
    /*
     * Must be first member!
     */
    struct vigs_gem_object gem;

    u32 width;
    u32 height;
    u32 stride;
    vigsp_surface_format format;
    bool scanout;
    vigsp_surface_id id;

    /*
     * Members below MUST be accessed between
     * vigs_gem_reserve/vigs_gem_unreserve.
     * @{
     */

    bool is_gpu_dirty;

    /*
     * Number of mmap areas (vmas) that accessed this surface for
     * read/write.
     * @{
     */
    u32 num_readers;
    u32 num_writers;
    /*
     * @}
     */

    /*
     * Number of mmap area writers that ended access asynchronously, i.e.
     * they still account for in 'num_writers', but as soon as first GPU
     * update operation takes place they'll be gone.
     */
    u32 num_pending_writers;

    /*
     * Specifies that we should not update VRAM on next 'update_vram'
     * request. Lasts for one request.
     */
    bool skip_vram_update;

    /*
     * @}
     */
};

struct vigs_vma_data
{
    struct vigs_surface *sfc;
    u32 saf;
    bool track_access;
};

void vigs_vma_data_init(struct vigs_vma_data *vma_data,
                        struct vigs_surface *sfc,
                        bool track_access);

void vigs_vma_data_cleanup(struct vigs_vma_data *vma_data);

static inline struct vigs_surface *vigs_gem_to_vigs_surface(struct vigs_gem_object *vigs_gem)
{
    return container_of(vigs_gem, struct vigs_surface, gem);
}

int vigs_surface_create(struct vigs_device *vigs_dev,
                        u32 width,
                        u32 height,
                        u32 stride,
                        vigsp_surface_format format,
                        bool scanout,
                        struct vigs_surface **sfc);

/*
 * Functions below MUST be accessed between
 * vigs_gem_reserve/vigs_gem_unreserve.
 * @{
 */

bool vigs_surface_need_vram_update(struct vigs_surface *sfc);

bool vigs_surface_need_gpu_update(struct vigs_surface *sfc);

/*
 * @}
 */

/*
 * IOCTLs
 * @{
 */

int vigs_surface_create_ioctl(struct drm_device *drm_dev,
                              void *data,
                              struct drm_file *file_priv);

int vigs_surface_info_ioctl(struct drm_device *drm_dev,
                            void *data,
                            struct drm_file *file_priv);

int vigs_surface_set_gpu_dirty_ioctl(struct drm_device *drm_dev,
                                     void *data,
                                     struct drm_file *file_priv);

int vigs_surface_start_access_ioctl(struct drm_device *drm_dev,
                                    void *data,
                                    struct drm_file *file_priv);

int vigs_surface_end_access_ioctl(struct drm_device *drm_dev,
                                  void *data,
                                  struct drm_file *file_priv);

/*
 * @}
 */

#endif
