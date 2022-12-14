#ifndef _COMPAT_NET_NETFILTER_NF_FLOW_TABLE_H
#define _COMPAT_NET_NETFILTER_NF_FLOW_TABLE_H

#include "../../../compat/config.h"

#ifdef CONFIG_COMPAT_KERNEL_CT
#include_next <net/netfilter/nf_flow_table.h>
#endif

#ifdef CONFIG_COMPAT_CLS_FLOWER_4_18_MOD
#include <net/netfilter/nf_flow_table_4_18.h>
#endif

#endif /* _COMPAT_NET_NETFILTER_NF_FLOW_TABLE_H */
