#ifndef _COMPAT_NET_TC_ACT_TC_CT_H
#define _COMPAT_NET_TC_ACT_TC_CT_H 1

#include "../../../compat/config.h"

#include <uapi/linux/tc_act/tc_ct.h>

#ifdef HAVE_FLOW_RULE_MATCH_CT
#include_next <net/tc_act/tc_ct.h>
#endif


#endif /* _COMPAT_NET_TC_ACT_TC_CT_H */
