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

#ifndef HAVE_NLA_POLICY_NESTED
#define NLA_POLICY_RANGE(tp, _min, _max) {		\
		.type = NLA_ENSURE_INT_TYPE(tp),		\
}

#define _NLA_POLICY_NESTED(maxattr, policy) \
		{ .type = NLA_NESTED, .validation_data = policy, .len = maxattr }
#define _NLA_POLICY_NESTED_ARRAY(maxattr, policy) \
		{ .type = NLA_NESTED_ARRAY, .validation_data = policy, .len = maxattr }
#define NLA_POLICY_NESTED(policy) \
		_NLA_POLICY_NESTED(ARRAY_SIZE(policy) - 1, policy)
#define NLA_POLICY_NESTED_ARRAY(policy) \
		_NLA_POLICY_NESTED_ARRAY(ARRAY_SIZE(policy) - 1, policy)

#define __NLA_ENSURE(condition) BUILD_BUG_ON_ZERO(!(condition))
#define NLA_ENSURE_INT_TYPE(tp)				\
	(__NLA_ENSURE(tp == NLA_S8 || tp == NLA_U8 ||	\
		      tp == NLA_S16 || tp == NLA_U16 ||	\
		      tp == NLA_S32 || tp == NLA_U32 ||	\
		      tp == NLA_S64 || tp == NLA_U64) + tp)
#define NLA_POLICY_MAX(tp, _max) {			\
	.type = NLA_ENSURE_INT_TYPE(tp),		\
}
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

#ifndef HAVE_NLA_NEST_START_NOFLAG
static inline struct nlattr *nla_nest_start_noflag(struct sk_buff *skb,
		int attrtype)
{
	struct nlattr *start = (struct nlattr *)skb_tail_pointer(skb);

	if (nla_put(skb, attrtype, 0, NULL) < 0)
		return NULL;

	return start;
}
#endif

#endif	/* _COMPAT_NET_NETLINK_H */

