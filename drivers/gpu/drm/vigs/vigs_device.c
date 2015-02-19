#include "vigs_device.h"
#include "vigs_mman.h"
#include "vigs_fenceman.h"
#include "vigs_crtc.h"
#include "vigs_output.h"
#include "vigs_plane.h"
#include "vigs_framebuffer.h"
#include "vigs_comm.h"
#include "vigs_fbdev.h"
#include "vigs_execbuffer.h"
#include "vigs_surface.h"
#include "vigs_dp.h"
#include <drm/vigs_drm.h>

static void vigs_device_mman_vram_to_gpu(void *user_data,
                                         struct ttm_buffer_object *bo)
{
    struct vigs_device *vigs_dev = user_data;
    struct vigs_gem_object *vigs_gem = bo_to_vigs_gem(bo);
    struct vigs_surface *vigs_sfc = vigs_gem_to_vigs_surface(vigs_gem);
    bool need_gpu_update = vigs_surface_need_gpu_update(vigs_sfc);

    if (!vigs_sfc->is_gpu_dirty && need_gpu_update) {
        DRM_INFO("vram_to_gpu: 0x%llX\n",
                 drm_vma_node_offset_addr(&bo->vma_node));
        vigs_comm_update_gpu(vigs_dev->comm,
                             vigs_sfc->id,
                             vigs_sfc->width,
                             vigs_sfc->height,
                             vigs_gem_offset(vigs_gem));
    } else {
        DRM_INFO("vram_to_gpu: 0x%llX (no-op)\n",
                 drm_vma_node_offset_addr(&bo->vma_node));
    }

    vigs_sfc->is_gpu_dirty = false;
}

static void vigs_device_mman_gpu_to_vram(void *user_data,
                                         struct ttm_buffer_object *bo,
                                         unsigned long new_offset)
{
    struct vigs_device *vigs_dev = user_data;
    struct vigs_gem_object *vigs_gem = bo_to_vigs_gem(bo);
    struct vigs_surface *vigs_sfc = vigs_gem_to_vigs_surface(vigs_gem);

    if (vigs_surface_need_vram_update(vigs_sfc)) {
        DRM_DEBUG_DRIVER("0x%llX\n",
                         drm_vma_node_offset_addr(&bo->vma_node));
        vigs_comm_update_vram(vigs_dev->comm,
                              vigs_sfc->id,
                              new_offset);
    } else {
        DRM_DEBUG_DRIVER("0x%llX (no-op)\n",
                         drm_vma_node_offset_addr(&bo->vma_node));
    }
}

static void vigs_device_mman_init_vma(void *user_data,
                                      void *vma_data_opaque,
                                      struct ttm_buffer_object *bo,
                                      bool track_access)
{
    struct vigs_vma_data *vma_data = vma_data_opaque;
    struct vigs_gem_object *vigs_gem = bo_to_vigs_gem(bo);

    if (vigs_gem->type != VIGS_GEM_TYPE_SURFACE) {
        vma_data->sfc = NULL;
        return;
    }

    vigs_vma_data_init(vma_data,
                       vigs_gem_to_vigs_surface(vigs_gem),
                       track_access);
}

static void vigs_device_mman_cleanup_vma(void *user_data,
                                         void *vma_data_opaque)
{
    struct vigs_vma_data *vma_data = vma_data_opaque;

    if (!vma_data->sfc) {
        return;
    }

    vigs_vma_data_cleanup(vma_data);
}

static struct vigs_mman_ops mman_ops =
{
    .vram_to_gpu = &vigs_device_mman_vram_to_gpu,
    .gpu_to_vram = &vigs_device_mman_gpu_to_vram,
    .init_vma = &vigs_device_mman_init_vma,
    .cleanup_vma = &vigs_device_mman_cleanup_vma
};

int vigs_device_init(struct vigs_device *vigs_dev,
                     struct drm_device *drm_dev,
                     struct pci_dev *pci_dev,
                     unsigned long flags)
{
    int ret;
    u32 i;

    DRM_DEBUG_DRIVER("enter\n");

    vigs_dev->dev = &pci_dev->dev;
    vigs_dev->drm_dev = drm_dev;
    vigs_dev->pci_dev = pci_dev;

    INIT_LIST_HEAD(&vigs_dev->pageflip_event_list);

    vigs_dev->vram_base = pci_resource_start(pci_dev, 0);
    vigs_dev->vram_size = pci_resource_len(pci_dev, 0);

    vigs_dev->ram_base = pci_resource_start(pci_dev, 1);
    vigs_dev->ram_size = pci_resource_len(pci_dev, 1);

    vigs_dev->io_base = pci_resource_start(pci_dev, 2);
    vigs_dev->io_size = pci_resource_len(pci_dev, 2);

    idr_init(&vigs_dev->surface_idr);
    mutex_init(&vigs_dev->surface_idr_mutex);

    if (!vigs_dev->vram_base || !vigs_dev->ram_base || !vigs_dev->io_base) {
        DRM_ERROR("VRAM, RAM or IO bar not found on device\n");
        ret = -ENODEV;
        goto fail1;
    }

    if ((vigs_dev->io_size < sizeof(void*)) ||
        ((vigs_dev->io_size % sizeof(void*)) != 0)) {
        DRM_ERROR("IO bar has bad size: %u bytes\n", vigs_dev->io_size);
        ret = -ENODEV;
        goto fail1;
    }

    ret = drm_addmap(vigs_dev->drm_dev,
                     vigs_dev->io_base,
                     vigs_dev->io_size,
                     _DRM_REGISTERS,
                     0,
                     &vigs_dev->io_map);
    if (ret != 0) {
        goto fail1;
    }

    ret = vigs_mman_create(vigs_dev->vram_base, vigs_dev->vram_size,
                           vigs_dev->ram_base, vigs_dev->ram_size,
                           sizeof(struct vigs_vma_data),
                           &mman_ops,
                           vigs_dev,
                           &vigs_dev->mman);

    if (ret != 0) {
        goto fail2;
    }

    vigs_dev->obj_dev = ttm_object_device_init(vigs_dev->mman->mem_global_ref.object,
                                               12);

    if (!vigs_dev->obj_dev) {
        DRM_ERROR("Unable to initialize obj_dev\n");
        ret = -ENOMEM;
        goto fail3;
    }

    ret = vigs_fenceman_create(&vigs_dev->fenceman);

    if (ret != 0) {
        goto fail4;
    }

    ret = vigs_dp_create(vigs_dev, &vigs_dev->dp);

    if (ret != 0) {
        goto fail5;
    }

    ret = vigs_comm_create(vigs_dev, &vigs_dev->comm);

    if (ret != 0) {
        goto fail6;
    }

    spin_lock_init(&vigs_dev->irq_lock);

    drm_mode_config_init(vigs_dev->drm_dev);

    vigs_framebuffer_config_init(vigs_dev);

    ret = vigs_crtc_init(vigs_dev);

    if (ret != 0) {
        goto fail7;
    }

    ret = vigs_output_init(vigs_dev);

    if (ret != 0) {
        goto fail7;
    }

    for (i = 0; i < VIGS_MAX_PLANES; ++i) {
        ret = vigs_plane_init(vigs_dev, i);

        if (ret != 0) {
            goto fail7;
        }
    }

    ret = drm_vblank_init(drm_dev, 1);

    if (ret != 0) {
        goto fail7;
    }

    /*
     * We allow VBLANK interrupt disabling right from the start. There's
     * no point in "waiting until first modeset".
     */
    drm_dev->vblank_disable_allowed = 1;

    ret = drm_irq_install(drm_dev);

    if (ret != 0) {
        goto fail8;
    }

    ret = vigs_fbdev_create(vigs_dev, &vigs_dev->fbdev);

    if (ret != 0) {
        goto fail9;
    }

    return 0;

fail9:
    drm_irq_uninstall(drm_dev);
fail8:
    drm_vblank_cleanup(drm_dev);
fail7:
    drm_mode_config_cleanup(vigs_dev->drm_dev);
    vigs_comm_destroy(vigs_dev->comm);
fail6:
    vigs_dp_destroy(vigs_dev->dp);
fail5:
    vigs_fenceman_destroy(vigs_dev->fenceman);
fail4:
    ttm_object_device_release(&vigs_dev->obj_dev);
fail3:
    vigs_mman_destroy(vigs_dev->mman);
fail2:
    drm_rmmap(vigs_dev->drm_dev, vigs_dev->io_map);
fail1:
    idr_destroy(&vigs_dev->surface_idr);
    mutex_destroy(&vigs_dev->surface_idr_mutex);

    return ret;
}

void vigs_device_cleanup(struct vigs_device *vigs_dev)
{
    DRM_DEBUG_DRIVER("enter\n");

    vigs_fbdev_destroy(vigs_dev->fbdev);
    drm_irq_uninstall(vigs_dev->drm_dev);
    drm_vblank_cleanup(vigs_dev->drm_dev);
    drm_mode_config_cleanup(vigs_dev->drm_dev);
    vigs_comm_destroy(vigs_dev->comm);
    vigs_dp_destroy(vigs_dev->dp);
    vigs_fenceman_destroy(vigs_dev->fenceman);
    ttm_object_device_release(&vigs_dev->obj_dev);
    vigs_mman_destroy(vigs_dev->mman);
    drm_rmmap(vigs_dev->drm_dev, vigs_dev->io_map);
    idr_destroy(&vigs_dev->surface_idr);
    mutex_destroy(&vigs_dev->surface_idr_mutex);
}

int vigs_device_mmap(struct file *filp, struct vm_area_struct *vma)
{
    struct drm_file *file_priv = filp->private_data;
    struct vigs_device *vigs_dev = file_priv->minor->dev->dev_private;

    if (vigs_dev == NULL) {
        DRM_ERROR("no device\n");
        return -EINVAL;
    }

    return vigs_mman_mmap(vigs_dev->mman,
                          filp,
                          vma,
                          vigs_dev->track_gem_access);
}

int vigs_device_add_surface(struct vigs_device *vigs_dev,
                            struct vigs_surface *sfc,
                            vigsp_surface_id* id)
{
    int ret;

    mutex_lock(&vigs_dev->surface_idr_mutex);

    ret = idr_alloc(&vigs_dev->surface_idr, sfc, 1, 0, GFP_KERNEL);

    mutex_unlock(&vigs_dev->surface_idr_mutex);

    if (ret < 0) {
        return ret;
    }

    *id = ret;

    return 0;
}

void vigs_device_remove_surface(struct vigs_device *vigs_dev,
                                vigsp_surface_id sfc_id)
{
    mutex_lock(&vigs_dev->surface_idr_mutex);
    idr_remove(&vigs_dev->surface_idr, sfc_id);
    mutex_unlock(&vigs_dev->surface_idr_mutex);
}

struct vigs_surface
    *vigs_device_reference_surface(struct vigs_device *vigs_dev,
                                   vigsp_surface_id sfc_id)
{
    struct vigs_surface *sfc;

    mutex_lock(&vigs_dev->surface_idr_mutex);

    sfc = idr_find(&vigs_dev->surface_idr, sfc_id);

    if (sfc) {
        if (vigs_gem_freed(&sfc->gem)) {
            sfc = NULL;
        } else {
            drm_gem_object_reference(&sfc->gem.base);
        }
    }

    mutex_unlock(&vigs_dev->surface_idr_mutex);

    return sfc;
}

int vigs_device_add_surface_unlocked(struct vigs_device *vigs_dev,
                                     struct vigs_surface *sfc,
                                     vigsp_surface_id* id)
{
    int ret;

    mutex_lock(&vigs_dev->drm_dev->struct_mutex);
    ret = vigs_device_add_surface(vigs_dev, sfc, id);
    mutex_unlock(&vigs_dev->drm_dev->struct_mutex);

    return ret;
}

void vigs_device_remove_surface_unlocked(struct vigs_device *vigs_dev,
                                         vigsp_surface_id sfc_id)
{
    mutex_lock(&vigs_dev->drm_dev->struct_mutex);
    vigs_device_remove_surface(vigs_dev, sfc_id);
    mutex_unlock(&vigs_dev->drm_dev->struct_mutex);
}
