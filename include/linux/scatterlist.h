#ifndef _COMPAT_LINUX_SCATTERLIST_H
#define _COMPAT_LINUX_SCATTERLIST_H

#include "../../compat/config.h"
#include <linux/version.h>

#include_next <linux/scatterlist.h>

#ifndef for_each_sgtable_dma_sg
#define for_each_sgtable_dma_sg(sgt, sg, i)     \
	        for_each_sg((sgt)->sgl, sg, (sgt)->nents, i)
#endif

#endif /* _COMPAT_LINUX_SCATTERLIST_H */
