#ifndef _YAGL_IOCTL_H_
#define _YAGL_IOCTL_H_

#include <linux/ioctl.h>

/*
 * Version number.
 */
#define YAGL_VERSION 23

/*
 * Device control codes magic.
 */
#define YAGL_IOC_MAGIC 'Y'

/*
 * Get version number.
 */
#define YAGL_IOC_GET_VERSION _IOR(YAGL_IOC_MAGIC, 0, unsigned int)

/*
 * Get user info.
 */
struct yagl_user_info
{
    unsigned int index;
    unsigned int render_type;
    unsigned int gl_version;
};

#define YAGL_IOC_GET_USER_INFO _IOR(YAGL_IOC_MAGIC, 1, struct yagl_user_info)

/*
 * Locks/unlocks memory. Exists solely
 * for offscreen backend's backing images.
 * @{
 */

struct yagl_mlock_arg
{
    unsigned long address;
    unsigned int size;
};

#define YAGL_IOC_MLOCK _IOW(YAGL_IOC_MAGIC, 2, struct yagl_mlock_arg)

#define YAGL_IOC_MUNLOCK _IOW(YAGL_IOC_MAGIC, 3, unsigned long)

/*
 * @}
 */

#endif
