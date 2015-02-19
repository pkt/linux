#ifndef _VIGS_OUTPUT_H_
#define _VIGS_OUTPUT_H_

#include "drmP.h"

struct vigs_device;

int vigs_output_init(struct vigs_device *vigs_dev);

int vigs_output_get_dpi(void);

int vigs_output_get_phys_width(int dpi, u32 width);

int vigs_output_get_phys_height(int dpi, u32 height);

#endif
