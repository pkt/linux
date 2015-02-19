#ifndef _VIGS_FILE_H_
#define _VIGS_FILE_H_

#include "drmP.h"
#include <ttm/ttm_object.h>

struct vigs_device;

struct vigs_file
{
    struct ttm_object_file *obj_file;
};

int vigs_file_create(struct vigs_device *vigs_dev,
                     struct vigs_file **vigs_file);

void vigs_file_destroy(struct vigs_file *vigs_file);

#endif
