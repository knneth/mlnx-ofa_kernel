#ifndef _COMPAT_NET_XDP_SOCK_DRV_H
#define _COMPAT_NET_XDP_SOCK_DRV_H

#include "../../compat/config.h"

#include_next <net/xdp_sock_drv.h>

#ifndef XDP_UMEM_MIN_CHUNK_SHIFT
#define XDP_UMEM_MIN_CHUNK_SHIFT 11
#endif

#endif /* _COMPAT_NET_XDP_SOCK_DRV_H */
