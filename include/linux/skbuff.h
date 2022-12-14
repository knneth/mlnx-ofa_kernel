#ifndef _COMPAT_LINUX_SKBUFF_H
#define _COMPAT_LINUX_SKBUFF_H

#include "../../compat/config.h"
#include <linux/version.h>

#include_next <linux/skbuff.h>

#ifndef HAVE_DEV_ALLOC_PAGES
static inline struct page *dev_alloc_pages(unsigned int order)
{
	gfp_t gfp_mask = GFP_ATOMIC | __GFP_NOWARN | __GFP_COLD | __GFP_COMP | __GFP_MEMALLOC;
	return alloc_pages_node(NUMA_NO_NODE, gfp_mask, order);
}
#endif
#ifndef HAVE_SKB_PULL_INLINE
static inline unsigned char *skb_pull_inline(struct sk_buff *skb, unsigned int len)
{
	return unlikely(len > skb->len) ? NULL : __skb_pull(skb, len);
}
#endif /* HAVE_SKB_PULL_INLINE */

#ifndef SKB_TRUESIZE
#define SKB_TRUESIZE(X) ((X) +						\
			SKB_DATA_ALIGN(sizeof(struct sk_buff)) +	\
			SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28))
#define v2_6_28_skb_add_rx_frag LINUX_BACKPORT(v2_6_28_skb_add_rx_frag)
extern void v2_6_28_skb_add_rx_frag(struct sk_buff *skb, int i, struct page *page,
			    int off, int size);
#define skb_add_rx_frag(skb, i, page, off, size, truesize) \
	v2_6_28_skb_add_rx_frag(skb, i, page, off, size)
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28) */
#ifdef HAVE_SKB_ADD_RX_FRAG_5_PARAMS
#define skb_add_rx_frag(skb, i, page, off, size, truesize) \
	skb_add_rx_frag(skb, i, page, off, size)
#endif /* HAVE_SKB_ADD_RX_FRAG_5_PARAMS */
#endif /*  LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28) */

#endif /* _COMPAT_LINUX_SKBUFF_H */
