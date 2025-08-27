#ifndef _COMPAT_NET_NETFILTER_NF_FLOW_TABLE_H
#define _COMPAT_NET_NETFILTER_NF_FLOW_TABLE_H

#include "../../../compat/config.h"

#ifdef HAVE_FLOW_RULE_MATCH_CT
#include_next <net/netfilter/nf_flow_table.h>
#endif


#endif /* _COMPAT_NET_NETFILTER_NF_FLOW_TABLE_H */
