#ifndef _VIGS_DEVICE_H_
#define _VIGS_DEVICE_H_

#include "drmP.h"
#include "vigs_protocol.h"

struct vigs_mman;
struct vigs_fenceman;
struct vigs_dp;
struct vigs_comm;
struct vigs_fbdev;
struct vigs_surface;

struct vigs_device
{
    struct device *dev;
    struct drm_device *drm_dev;
    struct pci_dev *pci_dev;

    struct list_head pageflip_event_list;

    resource_size_t vram_base;
    resource_size_t vram_size;

    resource_size_t ram_base;
    resource_size_t ram_size;

    resource_size_t io_base;
    resource_size_t io_size;

    struct idr surface_idr;
    struct mutex surface_idr_mutex;

    /* Map of IO BAR. */
    drm_local_map_t *io_map;

    struct vigs_mman *mman;

    struct ttm_object_device *obj_dev;

    struct vigs_fenceman *fenceman;

    struct vigs_dp *dp;

    struct vigs_comm *comm;

    struct vigs_fbdev *fbdev;

    /*
     * We need this because it's essential to read 'lower' and 'upper'
     * fence acks atomically in IRQ handler and on SMP systems IRQ handler
     * can be run on several CPUs concurrently.
     */
    spinlock_t irq_lock;

    /*
     * A hack we're forced to have in order to tell if we
     * need to track GEM access or not in 'vigs_device_mmap'.
     * current's 'mmap_sem' is write-locked while this is true,
     * so no race will occur.
     */
    bool track_gem_access;

    /*
     * A hack to tell if DPMS callback is called from inside
     * 'fb_blank' or vice-versa.
     */
    bool in_dpms;
};

int vigs_device_init(struct vigs_device *vigs_dev,
                     struct drm_device *drm_dev,
                     struct pci_dev *pci_dev,
                     unsigned long flags);

void vigs_device_cleanup(struct vigs_device *vigs_dev);

int vigs_device_mmap(struct file *filp, struct vm_area_struct *vma);

int vigs_device_add_surface(struct vigs_device *vigs_dev,
                            struct vigs_surface *sfc,
                            vigsp_surface_id* id);

void vigs_device_remove_surface(struct vigs_device *vigs_dev,
                                vigsp_surface_id sfc_id);

struct vigs_surface
    *vigs_device_reference_surface(struct vigs_device *vigs_dev,
                                   vigsp_surface_id sfc_id);

/*
 * Locks drm_device::struct_mutex.
 * @{
 */

int vigs_device_add_surface_unlocked(struct vigs_device *vigs_dev,
                                     struct vigs_surface *sfc,
                                     vigsp_surface_id* id);

void vigs_device_remove_surface_unlocked(struct vigs_device *vigs_dev,
                                         vigsp_surface_id sfc_id);

/*
 * @}
 */

#endif
