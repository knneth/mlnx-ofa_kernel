#ifndef _COMPAT_NET_NETLINK_H
#define _COMPAT_NET_NETLINK_H 1

#include "../../compat/config.h"

#include_next <net/netlink.h>
#include <net/genetlink.h>

#ifndef HAVE_NLA_FOR_EACH_NESTED_TYPE
#define nla_for_each_nested_type(pos, type, nla, rem) \
		nla_for_each_nested(pos, nla, rem) \
				if (nla_type(pos) == type)
#endif


#ifndef HAVE_NLA_POLICY_BITFIELD32
#define NLA_POLICY_BITFIELD32(valid) \
		{ .type = NLA_BITFIELD32 }
#endif

#ifndef HAVE_NLA_PUT_BITFIELD32
static inline int nla_put_bitfield32(struct sk_buff *skb, int attrtype,
		__u32 value, __u32 selector)
{
	struct nla_bitfield32 tmp = { value, selector, };

	return nla_put(skb, attrtype, sizeof(tmp), &tmp);
}
#endif


#ifndef HAVE_NLMSG_FOR_EACH_ATTR_TYPE
/**
 * nlmsg_for_each_attr_type - iterate over a stream of attributes
 * @pos: loop counter, set to the current attribute
 * @type: required attribute type for @pos
 * @nlh: netlink message header
 * @hdrlen: length of the family specific header
 * @rem: initialized to len, holds bytes currently remaining in stream
 */
#define nlmsg_for_each_attr_type(pos, type, nlh, hdrlen, rem) \
	nlmsg_for_each_attr(pos, nlh, hdrlen, rem) \
		if (nla_type(pos) == type)

#endif /* HAVE_NLMSG_FOR_EACH_ATTR_TYPE */

#endif	/* _COMPAT_NET_NETLINK_H */

