#ifndef _COMPAT_LINUX_BLK_MQ_H
#define _COMPAT_LINUX_BLK_MQ_H

#include "../../compat/config.h"

#include_next <linux/blk-mq.h>

#if !defined(HAVE_REQUEST_TO_QC_T) && defined(HAVE_BLK_TYPES_REQ_HIPRI)
static inline blk_qc_t request_to_qc_t(struct blk_mq_hw_ctx *hctx,
		struct request *rq)
{
	if (rq->tag != -1)
		return rq->tag | (hctx->queue_num << BLK_QC_T_SHIFT);

	return rq->internal_tag | (hctx->queue_num << BLK_QC_T_SHIFT) |
			BLK_QC_T_INTERNAL;
}
#endif

#ifndef HAVE_BLK_MQ_SET_REQUEST_COMPLETE
static inline void blk_mq_set_request_complete(struct request *rq)
{
	WRITE_ONCE(rq->state, MQ_RQ_COMPLETE);
}
#endif


#if !defined(HAVE_STRUCT_RQ_LIST) && !defined(rq_list_add_tail)
#define rq_list_add_tail(lastpptr, rq)	do {		\
	(rq)->rq_next = NULL;				\
	**(lastpptr) = rq;				\
	*(lastpptr) = &rq->rq_next;			\
} while (0)
#endif

#endif /* _COMPAT_LINUX_BLK_MQ_H */
