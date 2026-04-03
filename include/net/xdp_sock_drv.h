#ifndef _COMPAT_NET_XDP_SOCK_DRV_H
#define _COMPAT_NET_XDP_SOCK_DRV_H

#include "../../compat/config.h"

#ifdef HAVE_XDP_SOCK_DRV_H
#include_next <net/xdp_sock_drv.h>
#endif

#ifndef HAVE_XDP_UMEM_MIN_CHUNK_SHIFT
#define XDP_UMEM_MIN_CHUNK_SHIFT 11
#endif

#ifndef HAVE_XSK_BUFF_SET_SIZE
static inline void xsk_buff_set_size(struct xdp_buff *xdp, u32 size)
{
	xdp->data = xdp->data_hard_start + XDP_PACKET_HEADROOM;
	xdp->data_meta = xdp->data;
	xdp->data_end = xdp->data + size;
}
#endif
#endif /* _COMPAT_NET_XDP_SOCK_DRV_H */
