#include "vigs_fenceman.h"
#include "vigs_fence.h"

int vigs_fenceman_create(struct vigs_fenceman **fenceman)
{
    int ret = 0;

    DRM_DEBUG_DRIVER("enter\n");

    *fenceman = kzalloc(sizeof(**fenceman), GFP_KERNEL);

    if (!*fenceman) {
        ret = -ENOMEM;
        goto fail1;
    }

    spin_lock_init(&(*fenceman)->lock);
    INIT_LIST_HEAD(&(*fenceman)->fence_list);
    (*fenceman)->seq = UINT_MAX;

    return 0;

fail1:
    *fenceman = NULL;

    return ret;
}

void vigs_fenceman_destroy(struct vigs_fenceman *fenceman)
{
    unsigned long flags;
    bool fence_list_empty;

    DRM_DEBUG_DRIVER("enter\n");

    spin_lock_irqsave(&fenceman->lock, flags);
    fence_list_empty = list_empty(&fenceman->fence_list);
    spin_unlock_irqrestore(&fenceman->lock, flags);

    BUG_ON(!fence_list_empty);

    kfree(fenceman);
}

void vigs_fenceman_ack(struct vigs_fenceman *fenceman,
                       uint32_t lower, uint32_t upper)
{
    unsigned long flags;
    struct vigs_fence *fence, *tmp;

    spin_lock_irqsave(&fenceman->lock, flags);

    list_for_each_entry_safe(fence, tmp, &fenceman->fence_list, list) {
        if (vigs_fence_seq_num_after_eq(fence->seq, lower) &&
            vigs_fence_seq_num_before_eq(fence->seq, upper)) {
            DRM_DEBUG_DRIVER("Fence signaled (seq = %u)\n",
                             fence->seq);
            list_del_init(&fence->list);
            fence->signaled = true;
            wake_up_all(&fence->wait);
        }
    }

    spin_unlock_irqrestore(&fenceman->lock, flags);
}
