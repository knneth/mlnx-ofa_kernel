#ifndef _COMPAT_LINUX_FILTER_H
#define _COMPAT_LINUX_FILTER_H

#include "../../compat/config.h"

#include_next <linux/filter.h>

#ifndef HAVE_XDP_UPDATE_SKB_SHARED_INFO
static inline void
xdp_update_skb_shared_info(struct sk_buff *skb, u8 nr_frags,
			   unsigned int size, unsigned int truesize,
			   bool pfmemalloc)
{
	skb_shinfo(skb)->nr_frags = nr_frags;

	skb->len += size;
	skb->data_len += size;
	skb->truesize += truesize;
	skb->pfmemalloc |= pfmemalloc;
}
#endif

#ifndef HAVE_XDP_GET_SHARED_INFO_FROM_BUFF
#ifndef HAVE_XDP_BUFF_HAS_FRAME_SZ
#define xdp_data_hard_end(xdp, frame_sz)		\
	((xdp)->data_hard_start + (frame_sz) -		\
	SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))

static inline struct skb_shared_info *
xdp_get_shared_info_from_buff(struct xdp_buff *xdp, u32 frame_sz)
{
	return (struct skb_shared_info *)xdp_data_hard_end(xdp, frame_sz);
}
#else /* HAVE_XDP_BUFF_HAS_FRAME_SZ */
#define xdp_data_hard_end(xdp)				\
	((xdp)->data_hard_start + (xdp)->frame_sz -	\
	SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))

static inline struct skb_shared_info *
xdp_get_shared_info_from_buff(struct xdp_buff *xdp)
{
	return (struct skb_shared_info *)xdp_data_hard_end(xdp);
}
#endif /* HAVE_XDP_BUFF_HAS_FRAME_SZ */
#endif /* HAVE_XDP_GET_SHARED_INFO_FROM_BUFF */

#ifndef HAVE_XDP_INIT_BUFF
static __always_inline void
xdp_init_buff(struct xdp_buff *xdp, u32 frame_sz, struct xdp_rxq_info *rxq)
{
#ifdef HAVE_XDP_BUFF_HAS_FRAME_SZ
	xdp->frame_sz = frame_sz;
#endif
	xdp->rxq = rxq;
#ifdef HAVE_XDP_BUFF_HAS_FLAGS
	xdp->flags = 0;
#endif
}
static __always_inline void
xdp_prepare_buff(struct xdp_buff *xdp, unsigned char *hard_start,
		 int headroom, int data_len, const bool meta_valid)
{
	unsigned char *data = hard_start + headroom;

	xdp->data_hard_start = hard_start;
	xdp->data = data;
	xdp->data_end = data + data_len;
	xdp->data_meta = meta_valid ? data : data + 1;
}
#endif /* HAVE_XDP_INIT_BUFF */

#endif /* _COMPAT_LINUX_FILTER_H */
