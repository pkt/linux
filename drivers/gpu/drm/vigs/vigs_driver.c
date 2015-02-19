#include "vigs_driver.h"
#include "vigs_gem.h"
#include "vigs_device.h"
#include "vigs_fbdev.h"
#include "vigs_comm.h"
#include "vigs_surface.h"
#include "vigs_execbuffer.h"
#include "vigs_irq.h"
#include "vigs_fence.h"
#include "vigs_file.h"
#include "vigs_plane.h"
#include "vigs_mman.h"
#include "vigs_dp.h"
#include <drm/drmP.h>
#include <linux/module.h>
#include <drm/vigs_drm.h>

#define PCI_VENDOR_ID_VIGS 0x19B2
#define PCI_DEVICE_ID_VIGS 0x1011

#define DRIVER_NAME "vigs"
#define DRIVER_DESC "VIGS DRM"
#define DRIVER_DATE "20121102"
#define DRIVER_MAJOR DRM_VIGS_DRIVER_VERSION
#define DRIVER_MINOR 0

static struct pci_device_id vigs_pci_table[] =
{
    {
        .vendor     = PCI_VENDOR_ID_VIGS,
        .device     = PCI_DEVICE_ID_VIGS,
        .subvendor  = PCI_ANY_ID,
        .subdevice  = PCI_ANY_ID,
    },
    { 0 }
};
MODULE_DEVICE_TABLE(pci, vigs_pci_table);

static struct drm_ioctl_desc vigs_drm_ioctls[] =
{
    DRM_IOCTL_DEF_DRV(VIGS_GET_PROTOCOL_VERSION, vigs_comm_get_protocol_version_ioctl,
                                                 DRM_UNLOCKED | DRM_AUTH),
    DRM_IOCTL_DEF_DRV(VIGS_CREATE_SURFACE, vigs_surface_create_ioctl,
                                           DRM_UNLOCKED | DRM_AUTH),
    DRM_IOCTL_DEF_DRV(VIGS_CREATE_EXECBUFFER, vigs_execbuffer_create_ioctl,
                                              DRM_UNLOCKED | DRM_AUTH),
    DRM_IOCTL_DEF_DRV(VIGS_GEM_MAP, vigs_gem_map_ioctl,
                                    DRM_UNLOCKED | DRM_AUTH),
    DRM_IOCTL_DEF_DRV(VIGS_GEM_WAIT, vigs_gem_wait_ioctl,
                                     DRM_UNLOCKED | DRM_AUTH),
    DRM_IOCTL_DEF_DRV(VIGS_SURFACE_INFO, vigs_surface_info_ioctl,
                                         DRM_UNLOCKED | DRM_AUTH),
    DRM_IOCTL_DEF_DRV(VIGS_EXEC, vigs_execbuffer_exec_ioctl,
                                 DRM_UNLOCKED | DRM_AUTH),
    DRM_IOCTL_DEF_DRV(VIGS_SURFACE_SET_GPU_DIRTY, vigs_surface_set_gpu_dirty_ioctl,
                                                  DRM_UNLOCKED | DRM_AUTH),
    DRM_IOCTL_DEF_DRV(VIGS_SURFACE_START_ACCESS, vigs_surface_start_access_ioctl,
                                                 DRM_UNLOCKED | DRM_AUTH),
    DRM_IOCTL_DEF_DRV(VIGS_SURFACE_END_ACCESS, vigs_surface_end_access_ioctl,
                                               DRM_UNLOCKED | DRM_AUTH),
    DRM_IOCTL_DEF_DRV(VIGS_CREATE_FENCE, vigs_fence_create_ioctl,
                                         DRM_UNLOCKED | DRM_AUTH),
    DRM_IOCTL_DEF_DRV(VIGS_FENCE_WAIT, vigs_fence_wait_ioctl,
                                       DRM_UNLOCKED | DRM_AUTH),
    DRM_IOCTL_DEF_DRV(VIGS_FENCE_SIGNALED, vigs_fence_signaled_ioctl,
                                           DRM_UNLOCKED | DRM_AUTH),
    DRM_IOCTL_DEF_DRV(VIGS_FENCE_UNREF, vigs_fence_unref_ioctl,
                                        DRM_UNLOCKED | DRM_AUTH),
    DRM_IOCTL_DEF_DRV(VIGS_PLANE_SET_ZPOS, vigs_plane_set_zpos_ioctl,
                                           DRM_UNLOCKED | DRM_AUTH),
    DRM_IOCTL_DEF_DRV(VIGS_PLANE_SET_TRANSFORM, vigs_plane_set_transform_ioctl,
                                                DRM_UNLOCKED | DRM_AUTH),

    DRM_IOCTL_DEF_DRV(VIGS_DP_CREATE_SURFACE, vigs_dp_surface_create_ioctl,
                                              DRM_UNLOCKED | DRM_AUTH),
    DRM_IOCTL_DEF_DRV(VIGS_DP_OPEN_SURFACE, vigs_dp_surface_open_ioctl,
                                            DRM_UNLOCKED | DRM_AUTH)
};

static const struct file_operations vigs_drm_driver_fops =
{
    .owner = THIS_MODULE,
    .open = drm_open,
    .release = drm_release,
    .unlocked_ioctl = drm_ioctl,
    .poll = drm_poll,
    .mmap = vigs_device_mmap,
    .read = drm_read
};

static int vigs_drm_load(struct drm_device *dev, unsigned long flags)
{
    int ret = 0;
    struct vigs_device *vigs_dev = NULL;

    DRM_DEBUG_DRIVER("enter\n");

    vigs_dev = kzalloc(sizeof(*vigs_dev), GFP_KERNEL);

    if (vigs_dev == NULL) {
        DRM_ERROR("failed to allocate VIGS device\n");
        return -ENOMEM;
    }

    dev->dev_private = vigs_dev;

    ret = vigs_device_init(vigs_dev, dev, dev->pdev, flags);

    if (ret != 0) {
        goto fail;
    }

    return 0;

fail:
    kfree(vigs_dev);

    return ret;
}

static int vigs_drm_unload(struct drm_device *dev)
{
    struct vigs_device *vigs_dev = dev->dev_private;

    DRM_DEBUG_DRIVER("enter\n");

    vigs_device_cleanup(vigs_dev);

    kfree(dev->dev_private);
    dev->dev_private = NULL;

    return 0;
}

static int vigs_drm_open(struct drm_device *dev, struct drm_file *file_priv)
{
    int ret = 0;
    struct vigs_device *vigs_dev = dev->dev_private;
    struct vigs_file *vigs_file;

    DRM_DEBUG_DRIVER("enter\n");

    ret = vigs_file_create(vigs_dev, &vigs_file);

    if (ret != 0) {
        return ret;
    }

    file_priv->driver_priv = vigs_file;

    vigs_dev->mman->bo_dev.dev_mapping = dev->dev_mapping;

    return 0;
}

static void vigs_drm_preclose(struct drm_device *dev,
                              struct drm_file *file_priv)
{
    struct vigs_device *vigs_dev = dev->dev_private;
    struct drm_pending_vblank_event *event, *tmp;
    unsigned long flags;

    DRM_DEBUG_DRIVER("enter\n");

    spin_lock_irqsave(&dev->event_lock, flags);

    list_for_each_entry_safe(event, tmp,
                             &vigs_dev->pageflip_event_list,
                             base.link) {
        if (event->base.file_priv == file_priv) {
            list_del(&event->base.link);
            event->base.destroy(&event->base);
        }
    }

    spin_unlock_irqrestore(&dev->event_lock, flags);
}

static void vigs_drm_postclose(struct drm_device *dev,
                               struct drm_file *file_priv)
{
    struct vigs_file *vigs_file = file_priv->driver_priv;

    DRM_DEBUG_DRIVER("enter\n");

    vigs_file_destroy(vigs_file);

    file_priv->driver_priv = NULL;
}

static void vigs_drm_lastclose(struct drm_device *dev)
{
    struct vigs_device *vigs_dev = dev->dev_private;

    DRM_DEBUG_DRIVER("enter\n");

    if (vigs_dev->fbdev) {
        vigs_fbdev_restore_mode(vigs_dev->fbdev);
    }

    vigs_comm_reset(vigs_dev->comm);
}

static struct drm_driver vigs_drm_driver =
{
    .driver_features = DRIVER_GEM | DRIVER_MODESET |
                       DRIVER_HAVE_IRQ | DRIVER_IRQ_SHARED,
    .load = vigs_drm_load,
    .unload = vigs_drm_unload,
    .open = vigs_drm_open,
    .preclose = vigs_drm_preclose,
    .postclose = vigs_drm_postclose,
    .lastclose = vigs_drm_lastclose,
    .get_vblank_counter = drm_vblank_count,
    .enable_vblank = vigs_enable_vblank,
    .disable_vblank = vigs_disable_vblank,
    .irq_handler = vigs_irq_handler,
    .gem_init_object = vigs_gem_init_object,
    .gem_free_object = vigs_gem_free_object,
    .gem_open_object = vigs_gem_open_object,
    .gem_close_object = vigs_gem_close_object,
    .dumb_create = vigs_gem_dumb_create,
    .dumb_map_offset = vigs_gem_dumb_map_offset,
    .dumb_destroy = vigs_gem_dumb_destroy,
    .ioctls = vigs_drm_ioctls,
    .num_ioctls = DRM_ARRAY_SIZE(vigs_drm_ioctls),
    .fops = &vigs_drm_driver_fops,
    .name = DRIVER_NAME,
    .desc = DRIVER_DESC,
    .date = DRIVER_DATE,
    .major = DRIVER_MAJOR,
    .minor = DRIVER_MINOR,
};

static int vigs_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
    return drm_get_pci_dev(pdev, ent, &vigs_drm_driver);
}

static void vigs_pci_remove(struct pci_dev *pdev)
{
    struct drm_device *dev = pci_get_drvdata(pdev);

    drm_put_dev(dev);
}

static struct pci_driver vigs_pci_driver =
{
     .name = DRIVER_NAME,
     .id_table = vigs_pci_table,
     .probe = vigs_pci_probe,
     .remove = vigs_pci_remove,
};

int vigs_driver_register(void)
{
    return drm_pci_init(&vigs_drm_driver, &vigs_pci_driver);
}

void vigs_driver_unregister(void)
{
    drm_pci_exit(&vigs_drm_driver, &vigs_pci_driver);
}
