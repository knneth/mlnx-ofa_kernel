#ifndef _COMPAT_NET_PSAMPLE_H
#define _COMPAT_NET_PSAMPLE_H 1

#include "../../compat/config.h"

#ifdef HAVE_NET_PSAMPLE_H
#include_next <net/psample.h>
#else
struct psample_group {
	struct list_head list;
	struct net *net;
	u32 group_num;
	u32 refcount;
	u32 seq;
	struct rcu_head rcu;
};

static inline void psample_sample_packet(struct psample_group *group,
					 struct sk_buff *skb, u32 trunc_size,
					 int in_ifindex, int out_ifindex,
					 u32 sample_rate)
{
}
#endif

#endif /* _COMPAT_NET_PSAMPLE_H */
