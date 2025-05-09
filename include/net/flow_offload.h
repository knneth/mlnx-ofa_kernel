#ifndef _COMPAT_NET_FLOW_OFFLOAD_H
#define _COMPAT_NET_FLOW_OFFLOAD_H

#include "../../compat/config.h"

#ifdef HAVE_FLOW_RULE_MATCH_CVLAN
#include_next <net/flow_offload.h>
#else

#include <net/flow_dissector.h>
#include <net/ip_tunnels.h>

struct flow_match {
	struct flow_dissector	*dissector;
	void			*mask;
	void			*key;
};

struct flow_match_basic {
	struct flow_dissector_key_basic *key, *mask;
};

struct flow_match_control {
	struct flow_dissector_key_control *key, *mask;
};

struct flow_match_eth_addrs {
	struct flow_dissector_key_eth_addrs *key, *mask;
};

struct flow_match_vlan {
	struct flow_dissector_key_vlan *key, *mask;
};

struct flow_match_ipv4_addrs {
	struct flow_dissector_key_ipv4_addrs *key, *mask;
};

struct flow_match_ipv6_addrs {
	struct flow_dissector_key_ipv6_addrs *key, *mask;
};

struct flow_match_ip {
	struct flow_dissector_key_ip *key, *mask;
};

struct flow_match_ports {
	struct flow_dissector_key_ports *key, *mask;
};

struct flow_match_icmp {
	struct flow_dissector_key_icmp *key, *mask;
};

struct flow_match_tcp {
	struct flow_dissector_key_tcp *key, *mask;
};

struct flow_match_mpls {
	struct flow_dissector_key_mpls *key, *mask;
};

struct flow_match_enc_keyid {
	struct flow_dissector_key_keyid *key, *mask;
};

struct flow_match_enc_opts {
	struct flow_dissector_key_enc_opts *key, *mask;
};

struct flow_match_ct {
	struct flow_dissector_key_ct *key, *mask;
};

struct flow_rule;

#define  flow_rule_match_basic LINUX_BACKPORT(flow_rule_match_basic)
void flow_rule_match_basic(const struct flow_rule *rule,
			   struct flow_match_basic *out);
#define  flow_rule_match_control LINUX_BACKPORT(flow_rule_match_control)
void flow_rule_match_control(const struct flow_rule *rule,
			     struct flow_match_control *out);
#define  flow_rule_match_eth_addrs LINUX_BACKPORT(flow_rule_match_eth_addrs)
void flow_rule_match_eth_addrs(const struct flow_rule *rule,
			       struct flow_match_eth_addrs *out);
#define  flow_rule_match_vlan LINUX_BACKPORT(flow_rule_match_vlan)
void flow_rule_match_vlan(const struct flow_rule *rule,
			  struct flow_match_vlan *out);
#define  flow_rule_match_cvlan LINUX_BACKPORT(flow_rule_match_cvlan)
void flow_rule_match_cvlan(const struct flow_rule *rule,
			   struct flow_match_vlan *out);
#define  flow_rule_match_ipv4_addrs LINUX_BACKPORT(flow_rule_match_ipv4_addrs)
void flow_rule_match_ipv4_addrs(const struct flow_rule *rule,
				struct flow_match_ipv4_addrs *out);
#define  flow_rule_match_ipv6_addrs LINUX_BACKPORT(flow_rule_match_ipv6_addrs)
void flow_rule_match_ipv6_addrs(const struct flow_rule *rule,
				struct flow_match_ipv6_addrs *out);
#define  flow_rule_match_ip LINUX_BACKPORT(flow_rule_match_ip)
void flow_rule_match_ip(const struct flow_rule *rule,
			struct flow_match_ip *out);
#define  flow_rule_match_ports LINUX_BACKPORT(flow_rule_match_ports)
void flow_rule_match_ports(const struct flow_rule *rule,
			   struct flow_match_ports *out);
#define  flow_rule_match_tcp LINUX_BACKPORT(flow_rule_match_tcp)
void flow_rule_match_tcp(const struct flow_rule *rule,
			 struct flow_match_tcp *out);
#define  flow_rule_match_icmp LINUX_BACKPORT(flow_rule_match_icmp)
void flow_rule_match_icmp(const struct flow_rule *rule,
			  struct flow_match_icmp *out);
#define  flow_rule_match_mpls LINUX_BACKPORT(flow_rule_match_mpls)
void flow_rule_match_mpls(const struct flow_rule *rule,
			  struct flow_match_mpls *out);
#define  flow_rule_match_enc_control LINUX_BACKPORT(flow_rule_match_enc_control)
void flow_rule_match_enc_control(const struct flow_rule *rule,
				 struct flow_match_control *out);
#define  flow_rule_match_enc_ipv4_addrs LINUX_BACKPORT(flow_rule_match_enc_ipv4_addrs)
void flow_rule_match_enc_ipv4_addrs(const struct flow_rule *rule,
				    struct flow_match_ipv4_addrs *out);
#define  flow_rule_match_enc_ipv6_addrs LINUX_BACKPORT(flow_rule_match_enc_ipv6_addrs)
void flow_rule_match_enc_ipv6_addrs(const struct flow_rule *rule,
				    struct flow_match_ipv6_addrs *out);
#define  flow_rule_match_enc_ip LINUX_BACKPORT(flow_rule_match_enc_ip)
void flow_rule_match_enc_ip(const struct flow_rule *rule,
			    struct flow_match_ip *out);
#define  flow_rule_match_enc_ports LINUX_BACKPORT(flow_rule_match_enc_ports)
void flow_rule_match_enc_ports(const struct flow_rule *rule,
			       struct flow_match_ports *out);
#define  flow_rule_match_enc_keyid LINUX_BACKPORT(flow_rule_match_enc_keyid)
void flow_rule_match_enc_keyid(const struct flow_rule *rule,
			       struct flow_match_enc_keyid *out);
#define flow_rule_match_enc_opts LINUX_BACKPORT(flow_rule_match_enc_opts)
void flow_rule_match_enc_opts(const struct flow_rule *rule,
			      struct flow_match_enc_opts *out);
#define flow_rule_match_ct LINUX_BACKPORT(flow_rule_match_ct)
void flow_rule_match_ct(const struct flow_rule *rule,
			struct flow_match_ct *out);
#define flow_rule_match_cvlan LINUX_BACKPORT(flow_rule_match_cvlan)
void flow_rule_match_cvlan(const struct flow_rule *rule,
                           struct flow_match_vlan *out);

enum flow_action_id {
	FLOW_ACTION_ACCEPT		= 0,
	FLOW_ACTION_DROP,
	FLOW_ACTION_TRAP,
	FLOW_ACTION_GOTO,
	FLOW_ACTION_REDIRECT,
	FLOW_ACTION_MIRRED,
	FLOW_ACTION_VLAN_PUSH,
	FLOW_ACTION_VLAN_POP,
	FLOW_ACTION_VLAN_MANGLE,
	FLOW_ACTION_TUNNEL_ENCAP,
	FLOW_ACTION_TUNNEL_DECAP,
	FLOW_ACTION_MANGLE,
	FLOW_ACTION_ADD,
	FLOW_ACTION_CSUM,
	FLOW_ACTION_MARK,
	FLOW_ACTION_WAKE,
	FLOW_ACTION_QUEUE,
	FLOW_ACTION_SAMPLE,
	FLOW_ACTION_POLICE,
	FLOW_ACTION_CT,
	FLOW_ACTION_CT_METADATA,
};
#define HAVE_FLOW_ACTION_CT 1

/* This is mirroring enum pedit_header_type definition for easy mapping between
 * tc pedit action. Legacy TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK is mapped to
 * FLOW_ACT_MANGLE_UNSPEC, which is supported by no driver.
 */
enum flow_action_mangle_base {
	FLOW_ACT_MANGLE_UNSPEC		= 0,
	FLOW_ACT_MANGLE_HDR_TYPE_ETH,
	FLOW_ACT_MANGLE_HDR_TYPE_IP4,
	FLOW_ACT_MANGLE_HDR_TYPE_IP6,
	FLOW_ACT_MANGLE_HDR_TYPE_TCP,
	FLOW_ACT_MANGLE_HDR_TYPE_UDP,
};

struct flow_action_entry {
	enum flow_action_id		id;
	union {
		u32			chain_index;	/* FLOW_ACTION_GOTO */
		struct net_device	*dev;		/* FLOW_ACTION_REDIRECT */
		struct {				/* FLOW_ACTION_VLAN */
			u16		vid;
			__be16		proto;
			u8		prio;
		} vlan;
		struct {				/* FLOW_ACTION_PACKET_EDIT */
			enum flow_action_mangle_base htype;
			u32		offset;
			u32		mask;
			u32		val;
		} mangle;
		const struct ip_tunnel_info *tunnel;	/* FLOW_ACTION_TUNNEL_ENCAP */
		u32			csum_flags;	/* FLOW_ACTION_CSUM */
		u32			mark;		/* FLOW_ACTION_MARK */
		struct {				/* FLOW_ACTION_QUEUE */
			u32		ctx;
			u32		index;
			u8		vf;
		} queue;
		struct {				/* FLOW_ACTION_SAMPLE */
			struct psample_group	*psample_group;
			u32			rate;
			u32			trunc_size;
			bool			truncate;
		} sample;
		struct {				/* FLOW_ACTION_POLICE */
			s64			burst;
			u64			rate_bytes_ps;
		} police;
		struct {                                /* FLOW_ACTION_CT */
			int action;
			u16 zone;
			struct nf_flowtable *flow_table;
		} ct;
		struct {
			unsigned long cookie;
			u32 mark;
			u32 labels[4];
			u16 zone;
			bool orig_dir;
		} ct_metadata;
	};
};

struct flow_action {
	unsigned int			num_entries;
	struct flow_action_entry 	entries[0];
};

static inline bool flow_action_has_entries(const struct flow_action *action)
{
	return action->num_entries;
}

/**
 * flow_action_has_one_action() - check if exactly one action is present
 * @action: tc filter flow offload action
 *
 * Returns true if exactly one action is present.
 */
static inline bool flow_offload_has_one_action(const struct flow_action *action)
{
	return action->num_entries == 1;
}

#define flow_action_for_each(__i, __act, __actions)			\
        for (__i = 0, __act = &(__actions)->entries[0]; __i < (__actions)->num_entries; __act = &(__actions)->entries[++__i])

struct flow_rule {
	void *priv;	/* original offload struct */
	int priv_size;
	void *buff;	/* allocated buffer */

	struct flow_match	match;
	struct flow_action	action;
};

static inline bool flow_rule_match_key(const struct flow_rule *rule,
				       enum flow_dissector_key_id key)
{
	return dissector_uses_key(rule->match.dissector, key);
}

struct flow_stats {
	u64	pkts;
	u64	bytes;
	u64	lastused;
};

static inline void flow_stats_update(struct flow_stats *flow_stats,
				     u64 bytes, u64 pkts, u64 lastused)
{
	flow_stats->pkts	+= pkts;
	flow_stats->bytes	+= bytes;
	flow_stats->lastused	= max_t(u64, flow_stats->lastused, lastused);
}
#endif /* HAVE_FLOW_RULE_MATCH_CVLAN */

#ifndef HAVE_FLOW_RULE_MATCH_META
struct flow_match_meta {
	struct flow_dissector_key_meta *key, *mask;
};

void flow_rule_match_meta(const struct flow_rule *rule,
			  struct flow_match_meta *out);
#endif /* HAVE_FLOW_RULE_MATCH_META */

#define FLOW_ACTION_UNDEFINED_IN_KERNEL 100

#ifndef HAVE_FLOW_ACTION_JUMP_AND_PIPE
#define FLOW_ACTION_PIPE (FLOW_ACTION_UNDEFINED_IN_KERNEL + 1)
#define FLOW_ACTION_JUMP (FLOW_ACTION_UNDEFINED_IN_KERNEL + 2)
#endif

#ifndef HAVE_FLOW_ACTION_MPLS
#define FLOW_ACTION_MPLS_PUSH (FLOW_ACTION_UNDEFINED_IN_KERNEL + 3)
#define FLOW_ACTION_MPLS_POP (FLOW_ACTION_UNDEFINED_IN_KERNEL + 4)
#endif

#ifndef HAVE_FLOW_ACTION_REDIRECT_INGRESS
#define FLOW_ACTION_REDIRECT_INGRESS (FLOW_ACTION_UNDEFINED_IN_KERNEL + 5)
#endif

#ifndef HAVE_FLOW_ACTION_PTYPE
#define FLOW_ACTION_PTYPE (FLOW_ACTION_UNDEFINED_IN_KERNEL + 6)
#endif

#ifndef HAVE_FLOW_ACTION_PRIORITY
#define FLOW_ACTION_PRIORITY (FLOW_ACTION_UNDEFINED_IN_KERNEL + 7)
#endif

#ifndef HAVE_FLOW_ACTION_CT
#define FLOW_ACTION_CT (FLOW_ACTION_UNDEFINED_IN_KERNEL + 8)
#endif

#ifndef HAVE_FLOW_ACTION_VLAN_PUSH_ETH
#define FLOW_ACTION_VLAN_PUSH_ETH (FLOW_ACTION_UNDEFINED_IN_KERNEL + 9)
#define FLOW_ACTION_VLAN_POP_ETH (FLOW_ACTION_UNDEFINED_IN_KERNEL + 10)
#endif

#ifndef HAVE_FLOW_ACTION_POLICE
#define FLOW_ACTION_SAMPLE (FLOW_ACTION_UNDEFINED_IN_KERNEL + 11)
#define FLOW_ACTION_POLICE (FLOW_ACTION_UNDEFINED_IN_KERNEL + 12)
#endif

/* Update this if defining other actions above previous max */
#define NUM_FLOW_ACTIONS 200

#ifndef HAVE_TC_SETUP_FLOW_ACTION
#include <net/pkt_cls.h>

struct flow_rule *__alloc_flow_rule(struct tcf_exts *exts,
				    void *priv, int size);
struct flow_rule *alloc_flow_rule(struct tc_cls_flower_offload **f);
void free_flow_rule(struct flow_rule *rule);

static inline struct flow_rule *
tc_cls_flower_offload_flow_rule(struct tc_cls_flower_offload *flow_cmd)
{
	return (struct flow_rule *)(flow_cmd + 1);
}
#endif /* HAVE_TC_SETUP_FLOW_ACTION */

#ifndef HAVE_FLOW_SETUP_CB_T
enum tc_setup_type;
typedef int flow_setup_cb_t(enum tc_setup_type type, void *type_data,
					    void *cb_priv);
#endif

#ifdef CONFIG_COMPAT_CLS_FLOWER_4_18_MOD
struct flow_cls_common_offload {
	u32 chain_index;
	__be16 protocol;
	u32 prio;
	struct netlink_ext_ack *extack;
};

#define flow_cls_command tc_fl_command
struct flow_cls_offload1 {
	struct flow_cls_common_offload common;
	enum flow_cls_command command;
	unsigned long cookie;
	struct flow_rule *rule;
	struct flow_stats stats;
	u32 classid;
};


static inline struct flow_rule *
flow_cls_offload_flow_rule1(struct flow_cls_offload1 *flow_cmd)
{
	return flow_cmd->rule;
}
#else
#define flow_cls_offload1 flow_cls_offload
#define flow_cls_offload_flow_rule1 flow_cls_offload_flow_rule
#endif /* CONFIG_COMPAT_CLS_FLOWER_4_18_MOD */

#ifndef HAVE_FLOW_INDR_BLOCK_CB_ALLOC
#define flow_indr_block_cb_remove flow_block_cb_remove
#endif

#ifndef HAVE_FLOW_BLOCK_CB
struct flow_block_cb {
	struct list_head        driver_list;
	struct list_head        list;
	flow_setup_cb_t         *cb;
	void                    *cb_ident;
	void                    *cb_priv;
	void                    (*release)(void *cb_priv);
	unsigned int            refcnt;
};
#endif

#ifndef HAVE_ENCAP_CTRL_FLAG_HELPERS
#include <linux/netlink.h>
/**
 * flow_rule_is_supp_enc_control_flags() - check for supported control flags
 * @supp_enc_flags: encapsulation control flags supported by driver
 * @enc_ctrl_flags: encapsulation control flags present in rule
 * @extack: The netlink extended ACK for reporting errors.
 *
 * Return: true if only supported control flags are set, false otherwise.
 */
static inline bool flow_rule_is_supp_enc_control_flags(const u32 supp_enc_flags,
						       const u32 enc_ctrl_flags,
						       struct netlink_ext_ack *extack)
{
	if (likely((enc_ctrl_flags & ~supp_enc_flags) == 0))
		return true;

#ifdef NL_SET_ERR_MSG_FMT_MOD
	NL_SET_ERR_MSG_FMT_MOD(extack,
			       "Unsupported match on enc_control.flags %#x",
			       enc_ctrl_flags);
#else
	NL_SET_ERR_MSG_MOD(extack, "Unsupported match on enc_control.flags");
#endif

	return false;
}

/*
 * flow_rule_has_enc_control_flags() - check for presence of any control flags
 * @enc_ctrl_flags: encapsulation control flags present in rule
 * @extack: The netlink extended ACK for reporting errors.
 *
 * Return: true if control flags are set, false otherwise.
 */
static inline bool flow_rule_has_enc_control_flags(const u32 enc_ctrl_flags,
						   struct netlink_ext_ack *extack)
{
	return !flow_rule_is_supp_enc_control_flags(0, enc_ctrl_flags, extack);
}
#endif /* HAVE_ENCAP_CTRL_FLAG_HELPERS */

#ifndef HAVE_CTRL_FLAG_HELPERS
/**
 * flow_rule_is_supp_control_flags() - check for supported control flags
 * @supp_flags: control flags supported by driver
 * @ctrl_flags: control flags present in rule
 * @extack: The netlink extended ACK for reporting errors.
 *
 * Return: true if only supported control flags are set, false otherwise.
 */
static inline bool flow_rule_is_supp_control_flags(const u32 supp_flags,
						   const u32 ctrl_flags,
						   struct netlink_ext_ack *extack)
{
	if (likely((ctrl_flags & ~supp_flags) == 0))
		return true;

#ifdef NL_SET_ERR_MSG_FMT_MOD
	NL_SET_ERR_MSG_FMT_MOD(extack,
			       "Unsupported match on control.flags %#x",
			       ctrl_flags);
#else
	NL_SET_ERR_MSG_MOD(extack, "Unsupported match on control.flags");
#endif

	return false;
}

/**
 * flow_rule_has_control_flags() - check for presence of any control flags
 * @ctrl_flags: control flags present in rule
 * @extack: The netlink extended ACK for reporting errors.
 *
 * Return: true if control flags are set, false otherwise.
 */
static inline bool flow_rule_has_control_flags(const u32 ctrl_flags,
					       struct netlink_ext_ack *extack)
{
	return !flow_rule_is_supp_control_flags(0, ctrl_flags, extack);
}

/**
 * flow_rule_match_has_control_flags() - match and check for any control flags
 * @rule: The flow_rule under evaluation.
 * @extack: The netlink extended ACK for reporting errors.
 *
 * Return: true if control flags are set, false otherwise.
 */
static inline bool flow_rule_match_has_control_flags(struct flow_rule *rule,
						     struct netlink_ext_ack *extack)
{
	struct flow_match_control match;

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL))
		return false;

	flow_rule_match_control(rule, &match);

	return flow_rule_has_control_flags(match.mask->flags, extack);
}
#endif /* HAVE_CTRL_FLAG_HELPERS */
#endif /* _COMPAT_NET_FLOW_OFFLOAD_H */
