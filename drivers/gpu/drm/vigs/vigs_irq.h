#ifndef _VIGS_IRQ_H_
#define _VIGS_IRQ_H_

#include "drmP.h"

int vigs_enable_vblank(struct drm_device *drm_dev, int crtc);

void vigs_disable_vblank(struct drm_device *drm_dev, int crtc);

irqreturn_t vigs_irq_handler(DRM_IRQ_ARGS);

#endif
