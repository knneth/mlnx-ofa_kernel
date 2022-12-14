#ifndef HAVE_IDA_SIMPLE_GET

#include <linux/slab.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/idr.h>
#include <linux/spinlock.h>
#include <linux/export.h>

static DEFINE_SPINLOCK(simple_ida_lock);

void ida_simple_remove(struct ida *ida, unsigned int id)
{
	BUG_ON((int)id < 0);
	spin_lock(&simple_ida_lock);
	ida_remove(ida, id);
	spin_unlock(&simple_ida_lock);
}
EXPORT_SYMBOL(ida_simple_remove);

int ida_simple_get(struct ida *ida, unsigned int start, unsigned int end,
		   gfp_t gfp_mask)
{
	int ret, id;
	unsigned int max;

	BUG_ON((int)start < 0);
	BUG_ON((int)end < 0);

	if (end == 0)
		max = 0x80000000;
	else {
		BUG_ON(end < start);
		max = end - 1;
	}

again:
	if (!ida_pre_get(ida, gfp_mask))
		return -ENOMEM;

	spin_lock(&simple_ida_lock);
	ret = ida_get_new_above(ida, start, &id);
	if (!ret) {
		if (id > max) {
			ida_remove(ida, id);
			ret = -ENOSPC;
		} else {
			ret = id;
		}
	}
	spin_unlock(&simple_ida_lock);

	if (unlikely(ret == -EAGAIN))
		goto again;

	return ret;
}
EXPORT_SYMBOL(ida_simple_get);

#endif
