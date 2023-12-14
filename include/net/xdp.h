#ifndef _COMPAT_NET_XDP_H
#define _COMPAT_NET_XDP_H

#include "../../compat/config.h"

#ifdef HAVE_NET_XDP_H
#include_next <net/xdp.h>
#endif

#ifdef HAVE_XDP_SUPPORT
#ifndef HAVE_XSK_BUFF_ALLOC
#define MEM_TYPE_XSK_BUFF_POOL MEM_TYPE_ZERO_COPY
#endif
#endif

#ifndef XDP_RSS_TYPE_L4_IPV4_IPSEC
#define XDP_RSS_TYPE_L4_IPV4_IPSEC  XDP_RSS_L3_IPV4 | XDP_RSS_L4 | XDP_RSS_L4_IPSEC
#define XDP_RSS_TYPE_L4_IPV6_IPSEC  XDP_RSS_L3_IPV6 | XDP_RSS_L4 | XDP_RSS_L4_IPSEC
#endif

#ifndef HAVE_FILTER_H_HAVE_XDP_BUFF
#if !defined(HAVE_XDP_H_HAVE_XDP_BUFF)
struct xdp_buff {
	void *data;
	void *data_end;
	void *data_meta;
	void *data_hard_start;
	struct xdp_rxq_info *rxq;
	struct xdp_txq_info *txq;
	u32 frame_sz; /* frame size to deduce data_hard_end/reserved tailroom*/
	u32 flags; /* supported values defined in xdp_buff_flags */
};
#endif /* !defined(HAVE_XDP_H_HAVE_XDP_BUFF) && !defined(HAVE_FILTER_H_HAVE_XDP_BUFF) */

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
#ifndef HAVE_XDP_BUFF_DATA_HARD_START
#define xdp_data_hard_end(xdp, frame_sz, hard_start)	\
	((hard_start) + (frame_sz) -			\
	SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))

static inline struct skb_shared_info *
xdp_get_shared_info_from_buff(struct xdp_buff *xdp, u32 frame_sz, void *hard_start)
{
	return (struct skb_shared_info *)xdp_data_hard_end(xdp, frame_sz, hard_start);
}

#else /* HAVE_XDP_BUFF_DATA_HARD_START */
#define xdp_data_hard_end(xdp, frame_sz)		\
	((xdp)->data_hard_start + (frame_sz) -		\
	SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))

static inline struct skb_shared_info *
xdp_get_shared_info_from_buff(struct xdp_buff *xdp, u32 frame_sz)
{
	return (struct skb_shared_info *)xdp_data_hard_end(xdp, frame_sz);
}
#endif /* HAVE_XDP_BUFF_DATA_HARD_START */
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
#ifdef HAVE_XDP_RXQ_INFO
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
#else /* HAVE_XDP_RXQ_INFO */
static __always_inline void
xdp_init_buff(struct xdp_buff *xdp, u32 frame_sz)
{
#ifdef HAVE_XDP_BUFF_HAS_FRAME_SZ
	xdp->frame_sz = frame_sz;
#endif
#ifdef HAVE_XDP_BUFF_HAS_FLAGS
	xdp->flags = 0;
#endif
}
#endif /* HAVE_XDP_RXQ_INFO */
static __always_inline void
xdp_prepare_buff(struct xdp_buff *xdp, unsigned char *hard_start,
		 int headroom, int data_len, const bool meta_valid)
{
	unsigned char *data = hard_start + headroom;

#ifdef HAVE_XDP_BUFF_DATA_HARD_START
	xdp->data_hard_start = hard_start;
#endif
	xdp->data = data;
	xdp->data_end = data + data_len;
#ifdef HAVE_XDP_BUFF_HAS_DATA_META
	xdp->data_meta = meta_valid ? data : data + 1;
#endif
}
#endif /* HAVE_XDP_INIT_BUFF */
#endif /* HAVE_FILTER_H_HAVE_XDP_BUFF */
#endif /* _COMPAT_NET_XDP_H */
