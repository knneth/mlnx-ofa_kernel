#ifndef _COMPAT_NET_IP6_FIB_H
#define _COMPAT_NET_IP6_FIB_H 1

#include "../../compat/config.h"

#include_next <net/ip6_fib.h>


#ifndef HAVE_CONTAINER_OF_H
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define container_of_const(ptr, type, member)				\
	_Generic(ptr,							\
			const typeof(*(ptr)) *: ((const type *)container_of(ptr, type, member)),\
			default: ((type *)container_of(ptr, type, member))	\
		)
#else
#define container_of_const container_of
#endif
#endif

#ifndef dst_rtable
#define dst_rtable(_ptr) container_of_const(_ptr, struct rtable, dst)
#endif
#ifndef dst_rt6_info
#define dst_rt6_info(_ptr) container_of_const(_ptr, struct rt6_info, dst)
#endif

#endif	/* _COMPAT_NET_IP6_FIB_H */
