#ifndef _COMPAT_LINUX_BLKDEV_H
#define _COMPAT_LINUX_BLKDEV_H

#include "../../compat/config.h"

#include_next <linux/blkdev.h>

#ifndef rq_dma_dir
#define rq_dma_dir(rq) \
	(op_is_write(req_op(rq)) ? DMA_TO_DEVICE : DMA_FROM_DEVICE)
#endif

#ifndef blk_queue_pci_p2pdma
static inline unsigned int blk_queue_pci_p2pdma(struct request_queue *q)
{
	return 0;
}
#endif

#endif /* _COMPAT_LINUX_BLKDEV_H */
