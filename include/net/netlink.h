#ifndef _COMPAT_NET_NETLINK_H
#define _COMPAT_NET_NETLINK_H 1

#include "../../compat/config.h"

#include_next <net/netlink.h>
#include <net/genetlink.h>

#ifndef HAVE_NLA_PARSE_6_PARAMS
#define nla_parse(p1, p2, p3, p4, p5, p6) nla_parse(p1, p2, p3, p4, p5)
#define nlmsg_parse(p1, p2, p3, p4, p5, p6) nlmsg_parse(p1, p2, p3, p4, p5)
#define nlmsg_validate(p1, p2, p3, p4, p5) nlmsg_validate(p1, p2, p3, p4)
#endif

#ifndef HAVE_NLA_PUT_U64_64BIT
#define nla_put_u64_64bit(p1, p2, p3, p4) nla_put_u64(p1, p2, p3)
#endif

#ifndef HAVE_NETLINK_EXTACK
struct netlink_ext_ack;

#define UNUSED(x) (void)(x)
#undef NL_SET_ERR_MSG_MOD
#define NL_SET_ERR_MSG_MOD(extack, msg) \
	do { UNUSED(extack); pr_err("%s\n", msg); } while (0)
#endif

#endif	/* _COMPAT_NET_NETLINK_H */

