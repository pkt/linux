#ifndef _YAGL_PRINT_H_
#define _YAGL_PRINT_H_

#include <linux/kernel.h>
#include "yagl.h"

#define print_info(fmt, args...) printk(KERN_INFO YAGL_NAME ": " fmt, ## args)

#define print_error(fmt, args...) printk(KERN_ERR YAGL_NAME ": " fmt, ## args)

#endif
