#ifndef _COMPAT_LINUX_FILTER_H
#define _COMPAT_LINUX_FILTER_H

#include "../../compat/config.h"

#include_next <linux/filter.h>

#ifdef HAVE_FILTER_H_HAVE_XDP_BUFF
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
#ifdef HAVE_XDP_SUPPORT
#ifndef HAVE_XDP_FRAME
struct xdp_frame {
	void *data;
	u16 len;
	u16 headroom;
#ifdef HAVE_XDP_SET_DATA_META_INVALID
	u16 metasize;
#endif
};

/* Convert xdp_buff to xdp_frame */
static inline
struct xdp_frame *convert_to_xdp_frame(struct xdp_buff *xdp)
{
	struct xdp_frame *xdp_frame;
	int metasize;
	int headroom;

	/* Assure headroom is available for storing info */
#ifdef HAVE_XDP_BUFF_DATA_HARD_START
	headroom = xdp->data - xdp->data_hard_start;
#else
	headroom = 0;
#endif
#ifdef HAVE_XDP_SET_DATA_META_INVALID
	metasize = xdp->data - xdp->data_meta;
#else
	metasize = 0;
#endif
	metasize = metasize > 0 ? metasize : 0;
	if (unlikely((headroom - metasize) < sizeof(*xdp_frame)))
		return NULL;

	/* Store info in top of packet */
#ifdef HAVE_XDP_BUFF_DATA_HARD_START
	xdp_frame = xdp->data_hard_start;
#else
	xdp_frame = xdp->data;
#endif

	xdp_frame->data = xdp->data;
	xdp_frame->len  = xdp->data_end - xdp->data;
	xdp_frame->headroom = headroom - sizeof(*xdp_frame);
#ifdef HAVE_XDP_SET_DATA_META_INVALID
	xdp_frame->metasize = metasize;
#endif

	return xdp_frame;
}
#endif
#endif /* HAVE_XDP_SUPPORT */

#endif /* _COMPAT_LINUX_FILTER_H */
