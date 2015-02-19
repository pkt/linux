#include "yagl_driver.h"
#include "yagl_ioctl.h"
#include "yagl.h"
#include "debug.h"
#include "print.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/pci.h>
#include <linux/pagemap.h>

#define YAGL_REG_BUFFPTR 0
#define YAGL_REG_TRIGGER 4
#define YAGL_REGS_SIZE   8

#define YAGL_MAX_USERS (PAGE_SIZE / YAGL_REGS_SIZE)

#define YAGL_USER_PTR(regs, index) ((regs) + ((index) * YAGL_REGS_SIZE))

#define PCI_VENDOR_ID_YAGL 0x19B1
#define PCI_DEVICE_ID_YAGL 0x1010

static struct pci_device_id yagl_pci_table[] =
{
    {
        .vendor     = PCI_VENDOR_ID_YAGL,
        .device     = PCI_DEVICE_ID_YAGL,
        .subvendor  = PCI_ANY_ID,
        .subdevice  = PCI_ANY_ID,
    },
    { 0 }
};
MODULE_DEVICE_TABLE(pci, yagl_pci_table);

struct yagl_device
{
    /* PCI device we're managing */
    struct pci_dev *pci_dev;

    /* Misc device for accessing YaGL memory from user space */
    struct miscdevice miscdev;

    /* Physical address of YaGL registers. */
    unsigned long regs_pa;

    /* Memory area which is used for target <-> host communications */
    void __iomem *regs;

    /* 1 when user is active, 0 when slot can be used */
    int user_map[YAGL_MAX_USERS];

    /* Mutex used to serialize device operations */
    struct mutex mutex;
};

struct yagl_mlock
{
    struct list_head list;

    unsigned long address;

    struct page **pages;
    u32 num_pages;
};

struct yagl_file
{
    /* Owning device */
    struct yagl_device *device;

    /* Index in 'user_map', filled on 'open' */
    int index;

    /* Pages of a buffer. */
    struct page **pages;
    u32 num_pages;

    /* Render type and host OpenGL version for this client, filled on 'open'. */
    u32 render_type;
    u32 gl_version;

    /* List of mlock'ed memory regions. */
    struct list_head mlock_list;
};

static __inline void yagl_marshal_put_uint32_t(u8** buff, u32 value)
{
    *(u32*)(*buff) = value;
    *buff += 8;
}

static __inline u32 yagl_marshal_get_uint32_t(u8** buff)
{
    u32 tmp = *(u32*)*buff;
    *buff += 8;
    return tmp;
}

static void yagl_marshal_put_page_list(u8 **buff,
                                       struct page **pages,
                                       u32 count)
{
    u32 i;

    yagl_marshal_put_uint32_t(buff, count);

    for (i = 0; i < count; ++i) {
        yagl_marshal_put_uint32_t(buff, (uint32_t)page_to_phys(pages[i]));
    }
}

static void yagl_user_activate_update(void __iomem *regs,
                                      int index,
                                      unsigned long buff_pa)
{
    writel(buff_pa, YAGL_USER_PTR(regs, index) + YAGL_REG_BUFFPTR);
}

static void yagl_user_deactivate(void __iomem *regs, int index)
{
    writel(0, YAGL_USER_PTR(regs, index) + YAGL_REG_BUFFPTR);
}

static int yagl_alloc_pages(struct page ***pages,
                            u32 num_present,
                            u32 num_alloc)
{
    struct page **tmp;
    int ret = 0, i;

    tmp = kzalloc((num_present + num_alloc) * sizeof(*tmp), GFP_KERNEL);

    if (!tmp) {
        dprintk("unable to allocate memory\n");
        ret = -ENOMEM;
        goto fail1;
    }

    for (i = 0; i < (int)num_alloc; ++i) {
        tmp[num_present + i] = alloc_page(GFP_KERNEL | __GFP_HIGHMEM);
        if (!tmp[num_present + i]) {
            dprintk("unable to allocate page\n");
            ret = -ENOMEM;
            goto fail2;
        }
    }

    if (num_present > 0) {
        memcpy(tmp, *pages, num_present * sizeof(*tmp));
        kfree(*pages);
    }

    *pages = tmp;

    return 0;

fail2:
    while (--i >= 0) {
        __free_page(tmp[num_present + i]);
    }
    kfree(tmp);
fail1:
    return ret;
}

static void yagl_put_pages(struct page ***pages, u32 num_present, u32 num_put)
{
    u32 i;

    for (i = 1; i <= num_put; ++i) {
        __free_page((*pages)[num_present - i]);
    }

    if (num_present == num_put) {
        kfree(*pages);
        *pages = NULL;
    }
}

static int yagl_misc_open(struct inode *inode, struct file *file)
{
    int ret = 0;
    struct yagl_device *device = container_of(file->private_data,
                                              struct yagl_device,
                                              miscdev);
    struct yagl_file *yfile;
    int i;
    u8 *buff;
    pid_t process_id;
    pid_t thread_id;

    mutex_lock(&device->mutex);

    if (file->f_mode & FMODE_EXEC) {
        ret = -EPERM;
        goto fail1;
    }

    yfile = kzalloc(sizeof(*yfile), GFP_KERNEL);

    if (!yfile) {
        dprintk("unable to allocate memory\n");
        ret = -ENOMEM;
        goto fail1;
    }

    yfile->device = device;
    yfile->index = -1;

    for (i = 0; i < YAGL_MAX_USERS; ++i) {
        if (!device->user_map[i]) {
            yfile->index = i;
            device->user_map[i] = 1;
            break;
        }
    }

    if (yfile->index == -1) {
        print_error("no free slots\n");
        ret = -ENOMEM;
        goto fail2;
    }

    yfile->num_pages = 1;
    ret = yagl_alloc_pages(&yfile->pages, 0, yfile->num_pages);

    if (ret != 0) {
        goto fail3;
    }

    buff = kmap(yfile->pages[0]);

    memset(buff, 0, PAGE_SIZE);

    process_id = task_tgid_vnr(current);
    thread_id = task_pid_vnr(current);

    yagl_marshal_put_uint32_t(&buff, YAGL_VERSION);
    yagl_marshal_put_uint32_t(&buff, process_id);
    yagl_marshal_put_uint32_t(&buff, thread_id);

    yagl_user_activate_update(device->regs,
                              yfile->index,
                              page_to_phys(yfile->pages[0]));

    if (yagl_marshal_get_uint32_t(&buff) != 1) {
        ret = -EIO;
        print_error("unable to init YaGL: probably version mismatch\n");
        goto fail4;
    }

    yfile->render_type = yagl_marshal_get_uint32_t(&buff);
    yfile->gl_version = yagl_marshal_get_uint32_t(&buff);

    kunmap(yfile->pages[0]);

    INIT_LIST_HEAD(&yfile->mlock_list);

    file->private_data = yfile;

    mutex_unlock(&device->mutex);

    print_info("%d opened\n", yfile->index);

    return nonseekable_open(inode, file);

fail4:
    kunmap(yfile->pages[0]);
    yagl_put_pages(&yfile->pages, yfile->num_pages, yfile->num_pages);
fail3:
    device->user_map[yfile->index] = 0;
fail2:
    kfree(yfile);
fail1:
    mutex_unlock(&device->mutex);

    return ret;
}

static int yagl_misc_release(struct inode *inode, struct file *file)
{
    struct yagl_file *yfile = file->private_data;
    struct yagl_mlock *mlock, *tmp;
    u32 i;

    mutex_lock(&yfile->device->mutex);

    yagl_user_deactivate(yfile->device->regs, yfile->index);

    list_for_each_entry_safe(mlock, tmp, &yfile->mlock_list, list) {
        for (i = 0; i < mlock->num_pages; ++i) {
            set_page_dirty_lock(mlock->pages[i]);
            put_page(mlock->pages[i]);
        }
        kfree(mlock->pages);
        list_del(&mlock->list);
        kfree(mlock);
    }

    yagl_put_pages(&yfile->pages, yfile->num_pages, yfile->num_pages);

    yfile->device->user_map[yfile->index] = 0;

    mutex_unlock(&yfile->device->mutex);

    print_info("%d closed\n", yfile->index);

    kfree(file->private_data);
    file->private_data = NULL;

    return 0;
}

static int yagl_misc_mmap_regs(struct yagl_file *yfile,
                               struct vm_area_struct *vma)
{
    int ret = 0;
    u32 num_pages = (vma->vm_end - vma->vm_start) / PAGE_SIZE;

    if (num_pages != 1) {
        dprintk("%d mmap must be called for 1 page only\n",
                yfile->index);
        ret = -EINVAL;
        goto out;
    }

    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

    ret = remap_pfn_range(vma,
                          vma->vm_start,
                          (yfile->device->regs_pa >> PAGE_SHIFT),
                          num_pages,
                          vma->vm_page_prot);

    if (ret != 0) {
        dprintk("%d unable to remap regs memory: %d\n",
                yfile->index,
                ret);
        goto out;
    }

    ret = 0;

out:
    return ret;
}

static int yagl_misc_mmap_buffer(struct yagl_file *yfile,
                                 struct vm_area_struct *vma)
{
    int ret = 0;
    u32 i, num_pages = (vma->vm_end - vma->vm_start) / PAGE_SIZE;
    u8 *buff;
    u32 status;
    unsigned long addr;

    if (num_pages == 0) {
        dprintk("%d mmap must be called with one page or more\n",
                yfile->index);
        return -EINVAL;
    }

    if (num_pages > ((PAGE_SIZE / 8) - 2)) {
        dprintk("%d mmap must be called with not more than %ld pages\n",
                yfile->index,
                ((PAGE_SIZE / 8) - 2));
        return -EINVAL;
    }

    if (num_pages != yfile->num_pages) {
        if (num_pages > yfile->num_pages) {
            ret = yagl_alloc_pages(&yfile->pages,
                                   yfile->num_pages,
                                   (num_pages - yfile->num_pages));

            if (ret != 0) {
                goto out;
            }

            /*
             * We have at least one new page, use it for page list.
             */

            buff = kmap(yfile->pages[num_pages - 1]);

            memset(buff, 0, PAGE_SIZE);

            yagl_marshal_put_page_list(&buff, yfile->pages, num_pages);

            yagl_user_activate_update(yfile->device->regs,
                                      yfile->index,
                                      page_to_phys(yfile->pages[num_pages - 1]));

            status = yagl_marshal_get_uint32_t(&buff);

            kunmap(yfile->pages[num_pages - 1]);

            if (status != 1) {
                yagl_put_pages(&yfile->pages,
                               num_pages,
                               (num_pages - yfile->num_pages));
                ret = -EIO;
                print_error("%d unable to increase YaGL buffer due to host error\n",
                            yfile->index);
                goto out;
            }
        } else {
            /*
             * We're putting at least one page, use it for page list before
             * putting.
             */

            buff = kmap(yfile->pages[yfile->num_pages - 1]);

            memset(buff, 0, PAGE_SIZE);

            yagl_marshal_put_page_list(&buff, yfile->pages, num_pages);

            yagl_user_activate_update(yfile->device->regs,
                                      yfile->index,
                                      page_to_phys(yfile->pages[yfile->num_pages - 1]));

            status = yagl_marshal_get_uint32_t(&buff);

            kunmap(yfile->pages[yfile->num_pages - 1]);

            if (status != 1) {
                ret = -EIO;
                print_error("%d unable to decrease YaGL buffer due to host error\n",
                            yfile->index);
                goto out;
            }

            yagl_put_pages(&yfile->pages,
                           yfile->num_pages,
                           (yfile->num_pages - num_pages));
        }
    }

    yfile->num_pages = num_pages;

    vma->vm_flags |= VM_DONTDUMP | VM_DONTEXPAND;

    addr = vma->vm_start;

    for (i = 0; i < num_pages; ++i) {
        ret = vm_insert_page(vma, addr, yfile->pages[i]);
        if (ret != 0) {
            dprintk("%d unable to map buffer: %d\n",
                    yfile->index,
                    ret);
            goto out;
        }

        addr += PAGE_SIZE;
    }

out:
    return ret;
}

static int yagl_misc_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct yagl_file *yfile = file->private_data;
    int ret = 0;

    dprintk("user = %d, pgoff = %lu, size = %lu\n",
            yfile->index,
            vma->vm_pgoff,
            (vma->vm_end - vma->vm_start));

    mutex_lock(&yfile->device->mutex);

    if (vma->vm_pgoff == 0) {
        /*
         * First page is 'regs'.
         */

        ret = yagl_misc_mmap_regs(yfile, vma);
    } else if (vma->vm_pgoff == 1) {
        /*
         * Everything else is buffer.
         */

        ret = yagl_misc_mmap_buffer(yfile, vma);
    } else {
        dprintk("%d mmap must be called with page offset 0 or 1\n",
                yfile->index);
        ret = -EINVAL;
    }

    mutex_unlock(&yfile->device->mutex);

    return ret;
}

static int yagl_misc_mlock(struct yagl_file *yfile,
                           const struct yagl_mlock_arg *arg)
{
    int ret, i;
    unsigned long address = arg->address & PAGE_MASK;
    struct yagl_mlock *mlock;

    dprintk("user = %d, address = %p, size = %u\n",
            yfile->index,
            (void*)arg->address,
            arg->size);

    if (arg->size == 0) {
        dprintk("%d unable to mlock 0 bytes\n",
                yfile->index);
        return -EFAULT;
    }

    down_read(&current->mm->mmap_sem);
    mutex_lock(&yfile->device->mutex);

    list_for_each_entry(mlock, &yfile->mlock_list, list) {
        if (mlock->address == address) {
            dprintk("%d address %p already locked\n",
                    yfile->index,
                    (void*)address);
            ret = -EEXIST;
            goto out;
        }
    }

    mlock = kzalloc(sizeof(*mlock), GFP_KERNEL);

    if (!mlock) {
        dprintk("%d unable to allocate memory\n",
                yfile->index);
        ret = -ENOMEM;
        goto out;
    }

    mlock->address = address;
    mlock->num_pages = PAGE_ALIGN((arg->address & ~PAGE_MASK) + arg->size) >> PAGE_SHIFT;
    mlock->pages = kzalloc(mlock->num_pages * sizeof(*mlock->pages), GFP_KERNEL);

    if (!mlock->pages) {
        dprintk("%d unable to allocate memory\n",
                yfile->index);
        kfree(mlock);
        ret = -ENOMEM;
        goto out;
    }

    ret = get_user_pages(current, current->mm, mlock->address,
                         mlock->num_pages, 1, 0, mlock->pages, NULL);

    if (ret < (int)mlock->num_pages) {
        mutex_unlock(&yfile->device->mutex);
        up_read(&current->mm->mmap_sem);

        for (i = 0; i < ret; ++i) {
            put_page(mlock->pages[i]);
        }
        kfree(mlock->pages);
        kfree(mlock);

        ret = (ret >= 0) ? -EFAULT : ret;

        dprintk("%d unable to get user pages: %d\n",
                yfile->index,
                ret);

        return ret;
    }

    INIT_LIST_HEAD(&mlock->list);

    list_add_tail(&mlock->list, &yfile->mlock_list);

    ret = 0;

out:
    mutex_unlock(&yfile->device->mutex);
    up_read(&current->mm->mmap_sem);

    return ret;
}

static int yagl_misc_munlock(struct yagl_file *yfile,
                             unsigned long address)
{
    u32 i;
    struct yagl_mlock *mlock;

    dprintk("user = %d, address = %p\n",
            yfile->index,
            (void*)address);

    address &= PAGE_MASK;

    mutex_lock(&yfile->device->mutex);

    list_for_each_entry(mlock, &yfile->mlock_list, list) {
        if (mlock->address == address) {
            for (i = 0; i < mlock->num_pages; ++i) {
                set_page_dirty_lock(mlock->pages[i]);
                put_page(mlock->pages[i]);
            }
            kfree(mlock->pages);
            list_del(&mlock->list);
            kfree(mlock);

            mutex_unlock(&yfile->device->mutex);

            return 0;
        }
    }

    mutex_unlock(&yfile->device->mutex);

    dprintk("%d address %p not locked\n",
            yfile->index,
            (void*)address);

    return -ENOENT;
}

static long yagl_misc_ioctl(struct file* file, unsigned int cmd, unsigned long arg)
{
    struct yagl_file *yfile = file->private_data;
    int ret = 0;
    union
    {
        unsigned int uint;
        unsigned long ulong;
        struct yagl_user_info user_info;
        struct yagl_mlock_arg mlock_arg;
    } value;

    if (_IOC_TYPE(cmd) != YAGL_IOC_MAGIC) {
        return -ENOTTY;
    }

    if (_IOC_DIR(cmd) & _IOC_READ) {
        ret = !access_ok(VERIFY_WRITE, (void __user*)arg, _IOC_SIZE(cmd));
    }

    if (_IOC_DIR(cmd) & _IOC_WRITE) {
        ret = ret || !access_ok(VERIFY_READ, (void __user*)arg, _IOC_SIZE(cmd));
    }

    if (ret != 0) {
        return -EFAULT;
    }

    ret = 0;

    switch (cmd) {
    case YAGL_IOC_GET_VERSION:
        value.uint = YAGL_VERSION;
        ret = put_user(value.uint, (unsigned int __user*)arg);
        break;
    case YAGL_IOC_GET_USER_INFO:
        value.user_info.index = yfile->index;
        value.user_info.render_type = yfile->render_type;
        value.user_info.gl_version = yfile->gl_version;
        if (copy_to_user((struct yagl_user_info __user*)arg,
                         &value.user_info,
                         sizeof(value.user_info)) != 0) {
            ret = -EFAULT;
        }
        break;
    case YAGL_IOC_MLOCK:
        if (copy_from_user(&value.mlock_arg,
                           (struct yagl_mlock_arg __user*)arg,
                           sizeof(value.mlock_arg)) == 0) {
            ret = yagl_misc_mlock(yfile, &value.mlock_arg);
        } else {
            ret = -EFAULT;
        }
        break;
    case YAGL_IOC_MUNLOCK:
        ret = get_user(value.ulong, (unsigned long __user*)arg);
        if (ret == 0) {
            ret = yagl_misc_munlock(yfile, value.ulong);
        }
        break;
    default:
        ret = -ENOTTY;
        break;
    }

    return ret;
}

static struct file_operations yagl_misc_fops =
{
    .owner          = THIS_MODULE,
    .open           = yagl_misc_open,
    .mmap           = yagl_misc_mmap,
    .release        = yagl_misc_release,
    .unlocked_ioctl = yagl_misc_ioctl,
};

static int yagl_driver_probe(struct pci_dev *pci_dev,
                             const struct pci_device_id *pci_id)
{
    int ret = 0;
    struct yagl_device *device = NULL;
    u32 mem_size = 0;

    dprintk("probing PCI device \"%s\"\n", dev_name(&pci_dev->dev));

    device = kzalloc(sizeof(*device), GFP_KERNEL);

    if (!device) {
        ret = -ENOMEM;
        goto fail;
    }

    ret = pci_enable_device(pci_dev);

    if (ret != 0) {
        dprintk("%s: unable to enable PCI device\n", dev_name(&pci_dev->dev));

        goto fail;
    }

    device->pci_dev = pci_dev;

    pci_set_master(pci_dev);

    if (!pci_resource_start(pci_dev, 0)) {
        dprintk("%s: bad PCI resource\n", dev_name(&pci_dev->dev));
        ret = -ENXIO;
        goto fail;
    }

    mem_size = pci_resource_len(pci_dev, 0);

    if (mem_size != PAGE_SIZE) {
        dprintk("%s: mem size must be PAGE_SIZE\n", dev_name(&pci_dev->dev));
        ret = -ENXIO;
        goto fail;
    }

    if (!request_mem_region(pci_resource_start(pci_dev, 0),
                            PAGE_SIZE,
                            dev_name(&pci_dev->dev))) {
        dprintk("%s: mem size must be PAGE_SIZE\n", dev_name(&pci_dev->dev));
        ret = -EBUSY;
        goto fail;
    }

    device->regs_pa = pci_resource_start(pci_dev, 0);

    device->regs = ioremap(device->regs_pa, mem_size);

    if (!device->regs) {
        ret = -ENXIO;
        goto fail;
    }

    mutex_init(&device->mutex);

    device->miscdev.minor = MISC_DYNAMIC_MINOR;
    device->miscdev.name = YAGL_NAME;
    device->miscdev.fops = &yagl_misc_fops;

    ret = misc_register(&device->miscdev);

    if (ret != 0) {
        dprintk("%s: unable to register misc device\n", dev_name(&pci_dev->dev));

        goto fail;
    }

    pci_set_drvdata(pci_dev, device);

    print_info("%s: device added\n", dev_name(&pci_dev->dev));

    return 0;

fail:
    if (device) {
        if (device->regs) {
            iounmap(device->regs);
        }
        if (device->regs_pa) {
            release_mem_region(device->regs_pa, mem_size);
        }
        if (device->pci_dev) {
            pci_disable_device(device->pci_dev);
        }
        kfree(device);
    }

    return ret;
}

static void yagl_driver_remove(struct pci_dev *pci_dev)
{
    struct yagl_device* device;

    dprintk("removing driver from \"%s\"\n", dev_name(&pci_dev->dev));

    device = pci_get_drvdata(pci_dev);

    if (device != NULL) {
        misc_deregister(&device->miscdev);

        pci_set_drvdata(pci_dev, NULL);

        iounmap(device->regs);
        release_mem_region(device->regs_pa, PAGE_SIZE);
        pci_disable_device(device->pci_dev);
        kfree(device);
    }
}

static struct pci_driver yagl_driver =
{
    .name       = YAGL_NAME,
    .id_table   = yagl_pci_table,
    .probe      = yagl_driver_probe,
    .remove     = yagl_driver_remove,
};

int yagl_driver_register(void)
{
    return pci_register_driver(&yagl_driver);
}

void yagl_driver_unregister(void)
{
    pci_unregister_driver(&yagl_driver);
}
