#include "vigs_driver.h"
#include <linux/module.h>
#include <linux/init.h>

MODULE_AUTHOR("Stanislav Vorobiov");
MODULE_LICENSE("Dual BSD/GPL");

int vigs_init(void)
{
    int ret = vigs_driver_register();

    if (ret != 0) {
        return ret;
    }

    return 0;
}

void vigs_cleanup(void)
{
    vigs_driver_unregister();
}

module_init(vigs_init);
module_exit(vigs_cleanup);
