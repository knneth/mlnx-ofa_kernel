#ifndef _COMPAT_NET_TC_ACT_TC_VLAN_H
#define _COMPAT_NET_TC_ACT_TC_VLAN_H 1

#include "../../../compat/config.h"

#ifdef HAVE_IS_TCF_VLAN
#include_next <net/tc_act/tc_vlan.h>

#ifndef to_vlan
#define act_to_vlan(a) ((struct tcf_vlan *) a->priv)
#else
#define act_to_vlan(a) to_vlan(a)
#endif

#ifndef HAVE_TCF_VLAN_PUSH_PRIO
static inline __be16 tcf_vlan_push_prio(const struct tc_action *a)
{
	return act_to_vlan(a)->tcfv_push_prio;
}
#endif

#endif /* HAVE_IS_TCF_VLAN */
#endif	/* _COMPAT_NET_TC_ACT_TC_VLAN_H */
