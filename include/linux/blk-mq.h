#ifndef _COMPAT_LINUX_BLK_MQ_H
#define _COMPAT_LINUX_BLK_MQ_H

#include "../../compat/config.h"
#include <linux/version.h>

#include_next <linux/blk-mq.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0))
#ifndef HAVE_BLK_MQ_FREEZE_QUEUE_WAIT_TIMEOUT
static inline int blk_mq_freeze_queue_wait_timeout(struct request_queue *q,
						   unsigned long timeout)
{
	return wait_event_timeout(q->mq_freeze_wq,
				  percpu_ref_is_zero(&q->q_usage_counter),
				  timeout);
}
#endif

#ifndef HAVE_BLK_MQ_FREEZE_QUEUE_WAIT
static inline void blk_mq_freeze_queue_wait(struct request_queue *q)
{
	wait_event(q->mq_freeze_wq, percpu_ref_is_zero(&q->q_usage_counter));
}
#endif

#endif

#endif /* _COMPAT_LINUX_BLK_MQ_H */
