/*
 * Simple work processor based on kthread.
 *
 * This provides easier way to make use of kthreads.  A kthread_work
 * can be queued and flushed using queue/flush_kthread_work()
 * respectively.  Queued kthread_works are processed by a kthread
 * running kthread_worker_fn().
 *
 * A kthread_work can't be freed while it is executing.
 */
#ifndef BACKPORT_LINUX_KTHREAD_H
#define BACKPORT_LINUX_KTHREAD_H

#include <linux/version.h>
#include "../../compat/config.h"

#include_next <linux/kthread.h>

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,38))
/*
 * Kernels between 2.6.36 and 2.6.38 have the above functions but still lack the
 * following.
 */
#define kthread_create_on_node(threadfn, data, node, namefmt, arg...) \
	kthread_create(threadfn, data, namefmt, ##arg)

#endif

#endif /* _LINUX_KTHREAD_H */

