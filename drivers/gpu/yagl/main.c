#include <linux/module.h>
#include <linux/init.h>
#include "print.h"
#include "yagl_driver.h"

MODULE_AUTHOR("Stanislav Vorobiov");
MODULE_LICENSE("Dual BSD/GPL");

int yagl_init(void)
{
    int ret = yagl_driver_register();

    if (ret != 0)
    {
        return ret;
    }

    print_info("module loaded\n");

    return 0;
}

void yagl_cleanup(void)
{
    yagl_driver_unregister();

    print_info("module unloaded\n");
}

module_init(yagl_init);
module_exit(yagl_cleanup);
