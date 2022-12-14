#ifndef _COMPAT_NET_PKT_CLS_H
#define _COMPAT_NET_PKT_CLS_H 1

#include "../../compat/config.h"
#include_next <uapi/linux/pkt_cls.h>
#include_next <net/pkt_cls.h>
#include <net/tc_act/tc_tunnel_key.h>

#if !IS_ENABLED(CONFIG_NET_CLS_E2E_CACHE)
#define FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS_E2E 0xFFFFFFFF
#endif

#ifdef CONFIG_COMPAT_CLS_FLOWER_MOD
#define HAVE_FLOWER_MULTI_MASK 1
#include <uapi/linux/pkt_cls.h>

#if !defined(CONFIG_NET_SCHED_NEW) && !defined(CONFIG_COMPAT_KERNEL_4_14)
enum tc_fl_command {
	TC_CLSFLOWER_REPLACE,
	TC_CLSFLOWER_DESTROY,
	TC_CLSFLOWER_STATS,
	TC_CLSFLOWER_TMPLT_CREATE,
	TC_CLSFLOWER_TMPLT_DESTROY,
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

#ifndef HAVE_TC_SETUP_TYPE
enum tc_setup_type {
	dummy,
};
#endif

#ifndef HAVE___TC_INDR_BLOCK_CB_REGISTER
typedef int tc_indr_block_bind_cb_t(struct net_device *dev, void *cb_priv,
                                    enum tc_setup_type type, void *type_data);

static inline
int __tc_indr_block_cb_register(struct net_device *dev, void *cb_priv,
                                tc_indr_block_bind_cb_t *cb, void *cb_ident)
{
	        return 0;
}

static inline
void __tc_indr_block_cb_unregister(struct net_device *dev,
                                   tc_indr_block_bind_cb_t *cb, void *cb_ident)
{
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)) && (LINUX_VERSION_CODE <= KERNEL_VERSION(4,7,10))
#undef tc_for_each_action
#define tc_for_each_action(_a, _exts) \
	list_for_each_entry(_a, &(_exts)->actions, list)
#endif

#if defined(CONFIG_NET_CLS_ACT) && defined(HAVE_TCF_EXTS_HAS_ARRAY_ACTIONS)
#define tcf_exts_for_each_action(i, a, exts) \
	for (i = 0; i < TCA_ACT_MAX_PRIO && ((a) = (exts)->actions[i]); i++)
#elif defined tc_for_each_action
#define tcf_exts_for_each_action(i, a, exts) \
	(void)i; tc_for_each_action(a, exts)
#else
#define tcf_exts_for_each_action(i, a, exts) \
	for (; 0; (void)(i), (void)(a), (void)(exts))
#endif

#ifndef HAVE_TCF_EXTS_NUM_ACTIONS
#include_next <net/pkt_cls.h>
#define tcf_exts_num_actions LINUX_BACKPORT(tcf_exts_num_actions)
unsigned int tcf_exts_num_actions(struct tcf_exts *exts);
#endif

#ifdef HAVE_TC_FLOWER_OFFLOAD
#define FLOW_BLOCK_BIND TC_BLOCK_BIND
#define FLOW_BLOCK_UNBIND TC_BLOCK_UNBIND
#define FLOW_CLS_REPLACE TC_CLSFLOWER_REPLACE
#define FLOW_CLS_DESTROY TC_CLSFLOWER_DESTROY
#define FLOW_CLS_STATS TC_CLSFLOWER_STATS
#define FLOW_CLS_TMPLT_CREATE TC_CLSFLOWER_TMPLT_CREATE
#define FLOW_CLS_TMPLT_DESTROY TC_CLSFLOWER_TMPLT_DESTROY
#define FLOW_BLOCK_BINDER_TYPE_UNSPEC TCF_BLOCK_BINDER_TYPE_UNSPEC
#define FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS TCF_BLOCK_BINDER_TYPE_CLSACT_INGRESS
#define FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS TCF_BLOCK_BINDER_TYPE_CLSACT_EGRESS
#define flow_block_offload tc_block_offload
#define __flow_indr_block_cb_register __tc_indr_block_cb_register
#define __flow_indr_block_cb_unregister __tc_indr_block_cb_unregister
#endif /* HAVE_TC_FLOWER_OFFLOAD */

#ifdef HAVE___TC_INDR_BLOCK_CB_REGISTER
#define __flow_indr_block_cb_register __tc_indr_block_cb_register
#define __flow_indr_block_cb_unregister __tc_indr_block_cb_unregister
#endif

#if !defined(HAVE_TC_FLOWER_OFFLOAD) && !defined(HAVE_FLOW_CLS_OFFLOAD)
enum tc_fl_command {
	TC_CLSFLOWER_REPLACE,
	TC_CLSFLOWER_DESTROY,
	TC_CLSFLOWER_STATS,
	TC_CLSFLOWER_TMPLT_CREATE,
	TC_CLSFLOWER_TMPLT_DESTROY,
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
#endif /* !defined(HAVE_TC_FLOWER_OFFLOAD) && !defined(HAVE_FLOW_CLS_OFFLOAD) */

#ifndef NETIF_F_HW_TC
#define NETIF_F_HW_TC ((netdev_features_t)1 << ((NETDEV_FEATURE_COUNT + 1)))
#endif

#ifndef HAVE_FLOW_CLS_OFFLOAD
#define flow_cls_offload tc_cls_flower_offload
#endif

#ifndef HAVE_FLOW_CLS_OFFLOAD_FLOW_RULE
#define flow_cls_offload_flow_rule tc_cls_flower_offload_flow_rule
#endif

#ifdef CONFIG_MLX5_ESWITCH
#ifndef HAVE_TC_SETUP_FLOW_ACTION
#include <net/flow_offload.h>

#define tc_setup_flow_action LINUX_BACKPORT(tc_setup_flow_action)
int tc_setup_flow_action(struct flow_action *flow_action,
			 const struct tcf_exts *exts);
#endif
#endif


#endif	/* _COMPAT_NET_PKT_CLS_H */
