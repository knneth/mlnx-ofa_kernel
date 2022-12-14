#ifndef _COMPAT_NET_PKT_CLS_H
#define _COMPAT_NET_PKT_CLS_H 1

#include_next <net/pkt_cls.h>

#ifdef CONFIG_COMPAT_CLS_FLOWER_MOD
#include <uapi/linux/uapi/pkt_cls.h>

#ifndef CONFIG_NET_SCHED_NEW
enum tc_fl_command {
	TC_CLSFLOWER_REPLACE,
	TC_CLSFLOWER_DESTROY,
	TC_CLSFLOWER_STATS,
};

struct tc_cls_flower_offload {
	enum tc_fl_command command;
	u32 prio;
	unsigned long cookie;
	struct LINUX_BACKPORT(flow_dissector) *dissector;
	struct fl_flow_key *mask;
	struct fl_flow_key *key;
	struct tcf_exts *exts;
};

#define tc_no_actions(exts) (exts->action == NULL)
#define tc_for_each_action(a, exts) for (a = exts->action; a; a = a->next)

#define TC_SETUP_CLSFLOWER 1

#define NETIF_F_HW_TC ((netdev_features_t)1 << ((NETDEV_FEATURE_COUNT + 1)))

static inline bool tc_skip_sw(u32 flags)
{
	return (flags & TCA_CLS_FLAGS_SKIP_SW) ? true : false;
}

/* SKIP_HW and SKIP_SW are mutually exclusive flags. */
static inline bool tc_flags_valid(u32 flags)
{
	if (flags & ~(TCA_CLS_FLAGS_SKIP_HW | TCA_CLS_FLAGS_SKIP_SW))
		return false;

	if (!(flags ^ (TCA_CLS_FLAGS_SKIP_HW | TCA_CLS_FLAGS_SKIP_SW)))
		return false;

	return true;
}

#endif /* CONFIG_NET_SCHED_NEW */

#define tc_in_hw LINUX_BACKPORT(tc_in_hw)
static inline bool tc_in_hw(u32 flags)
{
	return (flags & TCA_CLS_FLAGS_IN_HW) ? true : false;
}

#define tc_skip_hw LINUX_BACKPORT(tc_skip_hw)
static inline bool tc_skip_hw(u32 flags)
{
	return (flags & TCA_CLS_FLAGS_SKIP_HW) ? true : false;
}

#endif

#endif	/* _COMPAT_NET_PKT_CLS_H */
