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

#ifndef HAVE_NLA_PUT_UINT
/* NLA_UINT/NLA_SINT (added in v6.7) are not known to the host netlink
 * validator, so map them to the closest fixed-width enum value. Wire
 * payload is always 4 bytes here since current readers use nla_get_u32.
 */
#define NLA_UINT NLA_U32
#define NLA_SINT NLA_S32

static inline int nla_put_uint(struct sk_buff *skb, int attrtype, u64 value)
{
	u64 tmp64 = value;
	u32 tmp32 = value;

	if (tmp64 == tmp32)
		return nla_put_u32(skb, attrtype, tmp32);
	return nla_put(skb, attrtype, sizeof(u64), &tmp64);
}

static inline int nla_put_sint(struct sk_buff *skb, int attrtype, s64 value)
{
	s64 tmp64 = value;
	s32 tmp32 = value;

	if (tmp64 == tmp32)
		return nla_put_s32(skb, attrtype, tmp32);
	return nla_put(skb, attrtype, sizeof(s64), &tmp64);
}

static inline u64 nla_get_uint(const struct nlattr *nla)
{
	if (nla_len(nla) == sizeof(u32))
		return nla_get_u32(nla);
	return nla_get_u64(nla);
}

static inline s64 nla_get_sint(const struct nlattr *nla)
{
	if (nla_len(nla) == sizeof(s32))
		return nla_get_s32(nla);
	return nla_get_s64(nla);
}
#endif /* HAVE_NLA_PUT_UINT */


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

