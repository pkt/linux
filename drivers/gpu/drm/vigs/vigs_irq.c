#include "vigs_irq.h"
#include "vigs_device.h"
#include "vigs_regs.h"
#include "vigs_fenceman.h"

static void vigs_finish_pageflips(struct vigs_device *vigs_dev)
{
    struct drm_pending_vblank_event *event, *tmp;
    struct timeval now;
    unsigned long flags;
    bool is_checked = false;

    spin_lock_irqsave(&vigs_dev->drm_dev->event_lock, flags);

    list_for_each_entry_safe(event, tmp,
                             &vigs_dev->pageflip_event_list,
                             base.link) {
        if (event->pipe != 0) {
            continue;
        }

        is_checked = true;

        do_gettimeofday(&now);
        event->event.sequence = 0;
        event->event.tv_sec = now.tv_sec;
        event->event.tv_usec = now.tv_usec;

        list_move_tail(&event->base.link, &event->base.file_priv->event_list);
        wake_up_interruptible(&event->base.file_priv->event_wait);
    }

    if (is_checked) {
        /*
         * Call 'drm_vblank_put' only in case that 'drm_vblank_get' was
         * called.
         */
        if (atomic_read(&vigs_dev->drm_dev->vblank_refcount[0]) > 0) {
            drm_vblank_put(vigs_dev->drm_dev, 0);
        }
    }

    spin_unlock_irqrestore(&vigs_dev->drm_dev->event_lock, flags);
}

int vigs_enable_vblank(struct drm_device *drm_dev, int crtc)
{
    struct vigs_device *vigs_dev = drm_dev->dev_private;
    u32 value;

    DRM_DEBUG_KMS("enter: crtc = %d\n", crtc);

    if (crtc != 0) {
        DRM_ERROR("bad crtc = %d", crtc);
        return -EINVAL;
    }

    value = VIGS_REG_CON_VBLANK_ENABLE;

    writel(value, vigs_dev->io_map->handle + VIGS_REG_CON);

    return 0;
}

void vigs_disable_vblank(struct drm_device *drm_dev, int crtc)
{
    struct vigs_device *vigs_dev = drm_dev->dev_private;
    u32 value;

    DRM_DEBUG_KMS("enter: crtc = %d\n", crtc);

    if (crtc != 0) {
        DRM_ERROR("bad crtc = %d", crtc);
    }

    value = 0;

    writel(value, vigs_dev->io_map->handle + VIGS_REG_CON);
}

irqreturn_t vigs_irq_handler(DRM_IRQ_ARGS)
{
    struct drm_device *drm_dev = (struct drm_device*)arg;
    struct vigs_device *vigs_dev = drm_dev->dev_private;
    u32 int_value;
    irqreturn_t ret = IRQ_NONE;

    int_value = readl(vigs_dev->io_map->handle + VIGS_REG_INT);

    if ((int_value & (VIGS_REG_INT_VBLANK_PENDING | VIGS_REG_INT_FENCE_ACK_PENDING)) != 0) {
        /*
         * Clear the interrupt first in order
         * not to stall the hardware.
         */

        writel(int_value, vigs_dev->io_map->handle + VIGS_REG_INT);

        ret = IRQ_HANDLED;
    }

    if ((int_value & VIGS_REG_INT_FENCE_ACK_PENDING) != 0) {
        u32 lower, upper;

        while (1) {
            spin_lock(&vigs_dev->irq_lock);

            lower = readl(vigs_dev->io_map->handle + VIGS_REG_FENCE_LOWER);
            upper = readl(vigs_dev->io_map->handle + VIGS_REG_FENCE_UPPER);

            spin_unlock(&vigs_dev->irq_lock);

            if (lower) {
                vigs_fenceman_ack(vigs_dev->fenceman, lower, upper);
            } else {
                break;
            }
        }
    }

    if ((int_value & VIGS_REG_INT_VBLANK_PENDING) != 0) {
        drm_handle_vblank(drm_dev, 0);

        vigs_finish_pageflips(vigs_dev);
    }

    return ret;
}
