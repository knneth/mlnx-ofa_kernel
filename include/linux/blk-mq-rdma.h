#ifndef _LINUX_BLK_MQ_RDMA_H
#define _LINUX_BLK_MQ_RDMA_H

#include "../../compat/config.h"

#ifdef HAVE_BLK_MQ_MAP_QUEUES
struct blk_mq_tag_set;
struct ib_device;

#define blk_mq_rdma_map_queues LINUX_BACKPORT(blk_mq_rdma_map_queues)
int blk_mq_rdma_map_queues(struct blk_mq_tag_set *set,
		struct ib_device *dev, int first_vec);
#endif /* HAVE_BLK_MQ_MAP_QUEUES */

#endif /* _LINUX_BLK_MQ_RDMA_H */
