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

#endif /* _COMPAT_LINUX_BLKDEV_H */
