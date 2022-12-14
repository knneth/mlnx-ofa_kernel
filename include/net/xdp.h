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


#endif /* _COMPAT_NET_XDP_H */
