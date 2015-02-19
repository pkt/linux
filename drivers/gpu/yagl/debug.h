#ifndef _YAGL_DEBUG_H_
#define _YAGL_DEBUG_H_

#include <linux/compiler.h>
#include <linux/kernel.h>
#include "yagl.h"

#ifdef CONFIG_YAGL_DEBUG
#   define dprintk(fmt, args...) printk(KERN_DEBUG YAGL_NAME "::%s: " fmt, __FUNCTION__, ## args)
#else
#   define dprintk(fmt, args...)
#endif

#endif
