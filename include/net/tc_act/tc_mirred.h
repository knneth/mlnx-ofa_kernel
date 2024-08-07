#ifndef _COMPAT_NET_TC_ACT_TC_MIRRED_H
#define _COMPAT_NET_TC_ACT_TC_MIRRED_H 1

#include "../../../compat/config.h"

#include <uapi/linux/tc_act/tc_mirred.h>

#include_next <net/tc_act/tc_mirred.h>

#include <net/netlink.h>
#include <linux/skbuff.h>

#ifdef CONFIG_NET_CLS_ACT
static const struct nla_policy mirred_policy_compat[TCA_MIRRED_MAX + 1] = {
	[TCA_MIRRED_PARMS]		= { .len = sizeof(struct tc_mirred) },
};

static inline bool is_tcf_mirred_compat(const struct tc_action *a)
{
#ifdef CONFIG_NET_CLS_ACT
#ifdef HAVE_TC_ACTION_OPS_HAS_ID
	if (a->ops && a->ops->id == TCA_ACT_MIRRED)
#else
	if (a->ops && a->ops->type == TCA_ACT_MIRRED)
#endif
		return true;
#endif
	return false;
}

static struct tc_mirred to_mirred_compat(const struct tc_action *a)
{
	struct nlattr *tb[TCA_MIRRED_MAX + 1];
	struct tc_mirred m = { .ifindex = 0 };
	struct sk_buff *skb;
	struct nlattr *nla;

	if (!a->ops || !a->ops->dump || !is_tcf_mirred_compat(a))
		return m;

	skb = alloc_skb(256, GFP_KERNEL);
	if (!skb)
		return m;

	if (a->ops->dump(skb, (struct tc_action *) a, 0, 0) < 0)
		goto freeskb;

	nla = (struct nlattr *) skb->data;
	if (nla_parse(tb, TCA_MIRRED_MAX, nla, skb->len, mirred_policy_compat,
		      NULL) < 0)
		goto freeskb;

	if (!tb[TCA_MIRRED_PARMS])
		goto freeskb;

	m = *((struct tc_mirred *) nla_data(tb[TCA_MIRRED_PARMS]));

freeskb:
	kfree_skb(skb);

	return m;
}

static inline int tcf_mirred_ifindex(const struct tc_action *a)
{
	return to_mirred_compat(a).ifindex;
}

#endif  /*  CONFIG_NET_CLS_ACT */
#endif	/* _COMPAT_NET_TC_ACT_TC_MIRRED_H */
