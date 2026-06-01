#ifndef _COMPAT_NET_PKT_CLS_H
#define _COMPAT_NET_PKT_CLS_H 1

#include "../../compat/config.h"
#include_next <uapi/linux/pkt_cls.h>
#include_next <net/pkt_cls.h>
#include <net/tc_act/tc_tunnel_key.h>

#if !IS_ENABLED(CONFIG_NET_CLS_E2E_CACHE)
#define FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS_E2E 0xFFFFFFFF
#endif

#if IS_ENABLED(CONFIG_NET_TC_SKB_EXT)
#ifndef HAVE_TC_SKB_EXT_ALLOC
static inline struct tc_skb_ext *tc_skb_ext_alloc(struct sk_buff *skb)
{
	struct tc_skb_ext *tc_skb_ext = skb_ext_add(skb, TC_SKB_EXT);

	if (tc_skb_ext)
		memset(tc_skb_ext, 0, sizeof(*tc_skb_ext));
	return tc_skb_ext;
}
#endif
#endif

#ifndef HAVE_ENUM_TC_HTB_COMMAND
enum tc_htb_command {
	/* Root */
	TC_HTB_CREATE, /* Initialize HTB offload. */
	TC_HTB_DESTROY, /* Destroy HTB offload. */

	/* Classes */
	/* Allocate qid and create leaf. */
	TC_HTB_LEAF_ALLOC_QUEUE,
	/* Convert leaf to inner, preserve and return qid, create new leaf. */
	TC_HTB_LEAF_TO_INNER,
	/* Delete leaf, while siblings remain. */
	TC_HTB_LEAF_DEL,
	/* Delete leaf, convert parent to leaf, preserving qid. */
	TC_HTB_LEAF_DEL_LAST,
	/* TC_HTB_LEAF_DEL_LAST, but delete driver data on hardware errors. */
	TC_HTB_LEAF_DEL_LAST_FORCE,
	/* Modify parameters of a node. */
	TC_HTB_NODE_MODIFY,

	/* Class qdisc */
	TC_HTB_LEAF_QUERY_QUEUE, /* Query qid by classid. */
};
#endif

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

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)) && (LINUX_VERSION_CODE <= KERNEL_VERSION(4,7,10))
#undef tc_for_each_action
#define tc_for_each_action(_a, _exts) \
	list_for_each_entry(_a, &(_exts)->actions, list)
#endif

#if defined(CONFIG_NET_CLS_ACT)
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






#ifdef CONFIG_MLX5_ESWITCH
#ifndef HAVE_TC_SETUP_FLOW_ACTION
#include <net/flow_offload.h>

#define tc_setup_flow_action LINUX_BACKPORT(tc_setup_flow_action)
int tc_setup_flow_action(struct flow_action *flow_action,
			 const struct tcf_exts *exts);
#endif
#endif


#endif	/* _COMPAT_NET_PKT_CLS_H */
