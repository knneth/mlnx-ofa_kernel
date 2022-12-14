#ifndef _COMPAT_LINUX_BLKDEV_H
#define _COMPAT_LINUX_BLKDEV_H

#include "../../compat/config.h"

#include_next <linux/blkdev.h>

#ifndef HAVE_BLK_RQ_IS_PASSTHROUGH
static inline bool blk_rq_is_passthrough(struct request *rq)
{
	return rq->cmd_type != REQ_TYPE_FS;
}
#endif

#ifndef HAVE_BLK_QUEUE_WRITE_CACHE
#ifdef HAVE_QUEUE_FLAG_WC_FUA
static inline void blk_queue_write_cache(struct request_queue *q, bool wc, bool fua)
{
	spin_lock_irq(q->queue_lock);
	if (wc)
		queue_flag_set(QUEUE_FLAG_WC, q);
	else
		queue_flag_clear(QUEUE_FLAG_WC, q);
	if (fua)
		queue_flag_set(QUEUE_FLAG_FUA, q);
	else
		queue_flag_clear(QUEUE_FLAG_FUA, q);
	spin_unlock_irq(q->queue_lock);

	wbt_set_write_cache(q->rq_wb, test_bit(QUEUE_FLAG_WC, &q->queue_flags));
}
#else
static inline void blk_queue_write_cache(struct request_queue *q, bool wc, bool fua)
{
}
#endif
#endif

#endif /* _COMPAT_LINUX_BLKDEV_H */
