#ifndef _COMPAT_LINUX_BLK_MQ_H
#define _COMPAT_LINUX_BLK_MQ_H

#include "../../compat/config.h"

#include_next <linux/blk-mq.h>
#ifndef HAVE_BLK_MQ_TAGSET_WAIT_COMPLETED_REQUEST
#include <linux/delay.h>
#endif

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

#ifndef HAVE_BLK_MQ_REQUEST_COMPLETED
static inline enum mq_rq_state blk_mq_rq_state(struct request *rq)
{
	return READ_ONCE(rq->state);
}

static inline int blk_mq_request_completed(struct request *rq)
{
	return blk_mq_rq_state(rq) == MQ_RQ_COMPLETE;
}
#endif

#ifndef HAVE_BLK_MQ_TAGSET_WAIT_COMPLETED_REQUEST
#ifdef HAVE_BLK_MQ_BUSY_TAG_ITER_FN_BOOL_3_PARAMS
static inline bool blk_mq_tagset_count_completed_rqs(struct request *rq,
                        void *data, bool reserved)
#elif defined HAVE_BLK_MQ_BUSY_TAG_ITER_FN_BOOL_2_PARAMS
static inline bool blk_mq_tagset_count_completed_rqs(struct request *rq,
                        void *data)
#else
static inline void blk_mq_tagset_count_completed_rqs(struct request *rq,
                        void *data, bool reserved)
#endif
{
   unsigned *count = data;

   if (blk_mq_request_completed(rq))
       (*count)++;
#ifdef HAVE_BLK_MQ_BUSY_TAG_ITER_FN_BOOL
   return true;
#endif
}

static inline void
blk_mq_tagset_wait_completed_request(struct blk_mq_tag_set *tagset)
{
   while (true) {
       unsigned count = 0;

       blk_mq_tagset_busy_iter(tagset,
               blk_mq_tagset_count_completed_rqs, &count);
       if (!count)
           break;
       msleep(5);
   }
}
#endif /* HAVE_BLK_MQ_TAGSET_WAIT_COMPLETED_REQUEST */

#endif /* _COMPAT_LINUX_BLK_MQ_H */
