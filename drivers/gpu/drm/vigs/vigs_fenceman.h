#ifndef _VIGS_FENCEMAN_H_
#define _VIGS_FENCEMAN_H_

#include "drmP.h"

/*
 * This is fence manager for VIGS. It's responsible for the following:
 * + Fence bookkeeping.
 * + Fence sequence number management and IRQ processing.
 */

struct vigs_fenceman
{
    /*
     * Lock that's used to guard all data inside
     * fence manager and fence objects. Don't confuse it
     * with struct ttm_bo_device::fence_lock, that lock
     * is used to work with TTM sync objects, i.e. it's more
     * "high level".
     */
    spinlock_t lock;

    /*
     * List of currently pending fences.
     */
    struct list_head fence_list;

    /*
     * Current sequence number, new fence should be
     * assigned (seq + 1).
     * Note! Sequence numbers are always non-0, 0 is
     * a special value that tells GPU not to fence things.
     */
    uint32_t seq;
};

int vigs_fenceman_create(struct vigs_fenceman **fenceman);

void vigs_fenceman_destroy(struct vigs_fenceman *fenceman);

/*
 * Can be called from IRQ handler.
 */
void vigs_fenceman_ack(struct vigs_fenceman *fenceman,
                       uint32_t lower, uint32_t upper);

#endif
