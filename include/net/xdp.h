#ifndef _COMPAT_NET_XDP_H
#define _COMPAT_NET_XDP_H

#include "../../compat/config.h"

#ifdef HAVE_XDP_BUFF
#ifdef HAVE_NET_XDP_H
#include_next <net/xdp.h>
#ifndef HAVE_XSK_BUFF_ALLOC
#define MEM_TYPE_XSK_BUFF_POOL MEM_TYPE_ZERO_COPY
#endif
#endif

#else

struct xdp_rxq_info {};
struct xdp_frame {};

static inline
void xdp_rxq_info_unused(struct xdp_rxq_info *xdp_rxq)
{
	return;
}

static inline
void xdp_rxq_info_unreg_mem_model(struct xdp_rxq_info *xdp_rxq)
{
	return;
}

static inline
void xdp_rxq_info_unreg(struct xdp_rxq_info *xdp_rxq)
{
	return;
}

#endif

#endif /* _COMPAT_NET_XDP_H */
