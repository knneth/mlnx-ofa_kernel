#ifndef _COMPAT_NET_XDP_H
#define _COMPAT_NET_XDP_H

#include "../../compat/config.h"

#include_next <net/xdp.h>

#ifdef HAVE_XDP_SUPPORT
#ifndef HAVE_XSK_BUFF_ALLOC
#define MEM_TYPE_XSK_BUFF_POOL MEM_TYPE_ZERO_COPY
#endif
#endif

#ifndef XDP_RSS_TYPE_L4_IPV4_IPSEC
#define XDP_RSS_TYPE_L4_IPV4_IPSEC  XDP_RSS_L3_IPV4 | XDP_RSS_L4 | XDP_RSS_L4_IPSEC
#define XDP_RSS_TYPE_L4_IPV6_IPSEC  XDP_RSS_L3_IPV6 | XDP_RSS_L4 | XDP_RSS_L4_IPSEC
#endif

#endif /* _COMPAT_NET_XDP_H */
