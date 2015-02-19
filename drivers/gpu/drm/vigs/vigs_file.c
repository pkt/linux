#include "vigs_file.h"
#include "vigs_device.h"

int vigs_file_create(struct vigs_device *vigs_dev,
                     struct vigs_file **vigs_file)
{
    int ret = 0;

    *vigs_file = kzalloc(sizeof(**vigs_file), GFP_KERNEL);

    if (!*vigs_file) {
        ret = -ENOMEM;
        goto fail1;
    }

    (*vigs_file)->obj_file = ttm_object_file_init(vigs_dev->obj_dev, 10);

    if (!(*vigs_file)->obj_file) {
        ret = -ENOMEM;
        goto fail2;
    }

    return 0;

fail2:
    kfree(*vigs_file);
fail1:
    *vigs_file = NULL;

    return ret;
}

void vigs_file_destroy(struct vigs_file *vigs_file)
{
    ttm_object_file_release(&vigs_file->obj_file);
    kfree(vigs_file);
}
