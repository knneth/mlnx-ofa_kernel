#ifndef _COMPAT_NET_TC_ACT_TC_VLAN_H
#define _COMPAT_NET_TC_ACT_TC_VLAN_H 1

#include "../../../compat/config.h"

#ifdef HAVE_TC_VLAN_H
#include <linux/tc_act/tc_vlan.h>
#include_next <net/tc_act/tc_vlan.h>
#endif

#ifndef HAVE_TC_VLAN_H
static inline bool is_tcf_vlan(const struct tc_action *a)
{
	return false;
}

static inline u32 tcf_vlan_action(const struct tc_action *a)
{
	return 0;
}

static inline u16 tcf_vlan_push_vid(const struct tc_action *a)
{
	return 0;
}

static inline __be16 tcf_vlan_push_proto(const struct tc_action *a)
{
	return 0;
}
#else
#ifndef HAVE_IS_TCF_VLAN
static inline bool is_tcf_vlan(const struct tc_action *a)
{
#ifdef CONFIG_NET_CLS_ACT
	if (a->ops && a->ops->type == TCA_ACT_VLAN)
		return true;
#endif
	return false;
}
#endif

#ifndef HAVE_TCF_VLAN_ACTION
static inline u32 tcf_vlan_action(const struct tc_action *a)
{
	return to_vlan(a)->tcfv_action;
}
#endif

#ifndef HAVE_TCF_VLAN_PUSH_VID
static inline u16 tcf_vlan_push_vid(const struct tc_action *a)
{
	return to_vlan(a)->tcfv_push_vid;
}
#endif

#ifndef HAVE_TCF_VLAN_PUSH_PROTO
static inline __be16 tcf_vlan_push_proto(const struct tc_action *a)
{
	return to_vlan(a)->tcfv_push_proto;
}
#endif

#endif /* HAVE_TC_VLAN_H */

#endif	/* _COMPAT_NET_TC_ACT_TC_VLAN_H */
