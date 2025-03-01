#ifndef _COMPAT_NET_NETLINK_H
#define _COMPAT_NET_NETLINK_H 1

#include "../../compat/config.h"

#include_next <net/netlink.h>
#include <net/genetlink.h>

#ifndef nla_for_each_nested_type
#define nla_for_each_nested_type(pos, type, nla, rem) \
		nla_for_each_nested(pos, nla, rem) \
				if (nla_type(pos) == type)
#endif

#endif	/* _COMPAT_NET_NETLINK_H */

