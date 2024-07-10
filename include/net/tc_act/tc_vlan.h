#ifndef _COMPAT_NET_TC_ACT_TC_VLAN_H
#define _COMPAT_NET_TC_ACT_TC_VLAN_H 1

#include "../../../compat/config.h"

#include_next <net/tc_act/tc_vlan.h>

#ifndef to_vlan
#define act_to_vlan(a) ((struct tcf_vlan *) a->priv)
#else
#define act_to_vlan(a) to_vlan(a)
#endif

#endif	/* _COMPAT_NET_TC_ACT_TC_VLAN_H */
