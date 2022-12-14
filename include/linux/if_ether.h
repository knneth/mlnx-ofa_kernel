#ifndef _COMPAT_LINUX_IF_ETHER_H
#define _COMPAT_LINUX_IF_ETHER_H

#include "../../compat/config.h"

#include_next <linux/if_ether.h>

#ifndef HAVE_ETH_MIN_MTU
#define ETH_MIN_MTU  68 /* Min IPv4 MTU per RFC791 */
#endif
#ifndef HAVE_ETH_MAX_MTU
#define ETH_MAX_MTU  0xFFFFU         /* 65535, same as IP_MAX_MTU    */
#endif

#endif /* _COMPAT_LINUX_IF_ETHER_H */
