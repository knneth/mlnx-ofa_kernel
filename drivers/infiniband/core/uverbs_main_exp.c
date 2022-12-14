#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/cdev.h>
#include <linux/anon_inodes.h>
#include <linux/slab.h>

#include <linux/uaccess.h>

#include "uverbs.h"
#include "uverbs_exp.h"

DEFINE_IDR(ib_uverbs_dct_idr);

unsigned long ib_uverbs_exp_get_unmapped_area(struct file *filp,
					      unsigned long addr,
					      unsigned long len,
					      unsigned long pgoff,
					      unsigned long flags)
{
	struct ib_uverbs_file *file = filp->private_data;
	unsigned long ret = 0;
	struct ib_device *ib_dev;
	int srcu_key;

	srcu_key = srcu_read_lock(&file->device->disassociate_srcu);
	ib_dev = srcu_dereference(file->device->ib_dev,
				  &file->device->disassociate_srcu);
	if (!ib_dev) {
		ret = -EIO;
		goto out;
	}

	if (!file->ucontext) {
		ret = -ENODEV;
	} else {
		if (!file->device->ib_dev->exp_get_unmapped_area) {
			ret = current->mm->get_unmapped_area(filp, addr, len,
								pgoff, flags);
			goto out;
		}

		ret = file->device->ib_dev->exp_get_unmapped_area(filp, addr, len,
								pgoff, flags);
	}
out:
	srcu_read_unlock(&file->device->disassociate_srcu, srcu_key);
	return ret;
}

long ib_uverbs_exp_ioctl(struct file *filp,
			 unsigned int cmd, unsigned long arg)
{
	struct ib_uverbs_file *file = filp->private_data;
	long ret = 0;
	int srcu_key;
	struct ib_device *ib_dev;

	srcu_key = srcu_read_lock(&file->device->disassociate_srcu);
	ib_dev = srcu_dereference(file->device->ib_dev,
				  &file->device->disassociate_srcu);

	if (!ib_dev) {
		ret = -EIO;
		goto out;
	}

	if (!ib_dev->exp_ioctl) {
		ret = -ENOTSUPP;
		goto out;
	}

	if (!file->ucontext) {
		ret = -ENODEV;
		goto out;
	} else {
		/* provider should provide it's own locking mechanism */
		ret = ib_dev->exp_ioctl(file->ucontext, cmd, arg);
	}

out:
	srcu_read_unlock(&file->device->disassociate_srcu, srcu_key);
	return ret;
}

void ib_uverbs_dct_event_handler(struct ib_event *event, void *context_ptr)
{
	struct ib_uevent_object *uobj;

	uobj = container_of(event->element.dct->uobject,
			    struct ib_uevent_object, uobject);

	ib_uverbs_async_handler(context_ptr, uobj->uobject.user_handle,
				event->event, &uobj->event_list,
				&uobj->events_reported);
}
