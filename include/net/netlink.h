#ifndef _COMPAT_NET_NETLINK_H
#define _COMPAT_NET_NETLINK_H 1

#include "../../compat/config.h"

#include_next <net/netlink.h>

/* forward port */
#ifdef HAVE_NLA_PARSE_6_PARAMS
#define nla_parse(p1, p2, p3, p4, p5) nla_parse(p1, p2, p3, p4, p5, NULL)
#define nlmsg_parse(p1, p2, p3, p4, p5) nlmsg_parse(p1, p2, p3, p4, p5, NULL)
#define nlmsg_validate(p1, p2, p3, p4) nlmsg_validate(p1, p2, p3, p4, NULL)
#endif

#endif	/* _COMPAT_NET_NETLINK_H */

