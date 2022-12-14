// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2021 Mellanox Technologies. */

#include <linux/refcount.h>

#include "tc_ct.h"
#include "tc_priv.h"
#include "en_tc.h"

#if IS_ENABLED(CONFIG_MLX5_SW_STEERING)
#include "steering/mlx5dr.h"
#include "steering/dr_types.h"

#define INIT_ERR_PREFIX "ct_fs_smfs init failed"
#define ct_dbg(fmt, args...)\
	netdev_dbg(fs->netdev, "ct_fs_smfs debug: " fmt "\n", ##args)
#define MLX5_CT_TCP_FLAGS_MASK cpu_to_be16(be32_to_cpu(TCP_FLAG_RST | TCP_FLAG_FIN) >> 16)

struct mlx5_ct_fs_smfs_matcher {
	struct mlx5dr_matcher *dr_matcher;
	struct list_head list;
	int prio;
	refcount_t ref;
};

struct mlx5_ct_fs_smfs_matchers {
	struct mlx5_ct_fs_smfs_matcher smfs_matchers[4];
	struct list_head used;
};

struct mlx5_ct_fs_smfs {
	struct mlx5dr_table *ct_tbl, *ct_nat_tbl;
	struct mlx5_ct_fs_smfs_matchers matchers;
	struct mlx5_ct_fs_smfs_matchers matchers_nat;
	struct mlx5dr_action *fwd_action;
	struct mutex lock; /* Guards matchers */
};

struct mlx5_ct_fs_smfs_zone_rule {
	struct mlx5_ct_fs_smfs_matcher *smfs_matcher;
	struct mlx5dr_rule *rule;
};

struct mlx5_ct_fs_smfs_counter {
	struct mlx5_ct_fs_counter fs_counter;
	struct mlx5dr_action *count_action;
};

static inline void
mlx5_ct_fs_smfs_fill_mask(struct mlx5_ct_fs *fs, struct mlx5_flow_spec *spec, bool ipv4, bool tcp)
{
	void *headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria, outer_headers);

	if (likely(MLX5_CAP_FLOWTABLE_NIC_RX(fs->dev, ft_field_support.outer_ip_version)))
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_version);
	else
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ethertype);

	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_protocol);
	if (likely(ipv4)) {
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c,
				 src_ipv4_src_ipv6.ipv4_layout.ipv4);
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c,
				 dst_ipv4_dst_ipv6.ipv4_layout.ipv4);
	} else {
		memset(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       0xFF,
		       MLX5_FLD_SZ_BYTES(fte_match_set_lyr_2_4,
					 dst_ipv4_dst_ipv6.ipv6_layout.ipv6));
		memset(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       0xFF,
		       MLX5_FLD_SZ_BYTES(fte_match_set_lyr_2_4,
					 src_ipv4_src_ipv6.ipv6_layout.ipv6));
	}

	if (likely(tcp)) {
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, tcp_sport);
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, tcp_dport);
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, tcp_flags,
			 ntohs(MLX5_CT_TCP_FLAGS_MASK));
	} else {
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, udp_sport);
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, udp_dport);
	}

	mlx5e_tc_match_to_reg_match(spec, ZONE_TO_REG, 0, MLX5_CT_ZONE_MASK);
}

static struct mlx5dr_matcher *
mlx5_ct_fs_smfs_matcher_create(struct mlx5_ct_fs *fs, struct mlx5dr_table *tbl, bool ipv4,
			       bool tcp, u32 priority)
{
	struct mlx5dr_match_parameters matcher_mask = {};
	struct mlx5dr_matcher *dr_matcher;
	struct mlx5_flow_spec *spec;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return ERR_PTR(-ENOMEM);

	mlx5_ct_fs_smfs_fill_mask(fs, spec, ipv4, tcp);

	matcher_mask.match_buf = (u64 *)&spec->match_criteria;
	matcher_mask.match_sz = DR_SZ_MATCH_PARAM;

	dr_matcher = mlx5dr_matcher_create(tbl, priority,
					   MLX5_MATCH_MISC_PARAMETERS_2 |
					   MLX5_MATCH_OUTER_HEADERS,
					   &matcher_mask);
	kfree(spec);
	if (!dr_matcher)
		return ERR_PTR(-EINVAL);

	return dr_matcher;
}

static struct mlx5_ct_fs_smfs_matcher *
mlx5_ct_fs_smfs_matcher_get(struct mlx5_ct_fs *fs, bool nat, bool ipv4, bool tcp)
{
	struct mlx5_ct_fs_smfs *fs_smfs = mlx5_ct_fs_priv(fs);
	struct mlx5_ct_fs_smfs_matcher *m, *smfs_matcher;
	struct mlx5_ct_fs_smfs_matchers *matchers;
	struct mlx5dr_matcher *dr_matcher;
	struct mlx5dr_table *tbl;
	struct list_head *prev;
	int err, prio;

	matchers = nat ? &fs_smfs->matchers_nat : &fs_smfs->matchers;
	smfs_matcher = &matchers->smfs_matchers[ipv4 * 2 + tcp];

	if (refcount_inc_not_zero(&smfs_matcher->ref))
		return smfs_matcher;

	mutex_lock(&fs_smfs->lock);

	/* Retry with lock, as another thread might have already created the relevant matcher
	 * till we acquired the lock
	 */
	if (refcount_inc_not_zero(&smfs_matcher->ref))
		goto out_unlock;

	// Find next available priority in sorted used list
	prio = 0;
	prev = &matchers->used;
	list_for_each_entry(m, &matchers->used, list) {
		prev = &m->list;

		if (m->prio == prio)
			prio = m->prio + 1;
		else
			break;
	}

	tbl = nat ? fs_smfs->ct_nat_tbl : fs_smfs->ct_tbl;
	dr_matcher = mlx5_ct_fs_smfs_matcher_create(fs, tbl, ipv4, tcp, prio);
	if (IS_ERR(dr_matcher)) {
		err = PTR_ERR(dr_matcher);
		netdev_warn(fs->netdev,
			    "ct_fs_smfs: failed to create matcher (nat %d, ipv4 %d, tcp %d), err: %d\n",
			    nat, ipv4, tcp, err);

		smfs_matcher = ERR_CAST(dr_matcher);
		goto out_unlock;
	}

	smfs_matcher->dr_matcher = dr_matcher;
	smfs_matcher->prio = prio;
	list_add(&smfs_matcher->list, prev);
	refcount_set(&smfs_matcher->ref, 1);

out_unlock:
	mutex_unlock(&fs_smfs->lock);
	return smfs_matcher;
}

static void
mlx5_ct_fs_smfs_matcher_put(struct mlx5_ct_fs *fs, struct mlx5_ct_fs_smfs_matcher *smfs_matcher)
{
	struct mlx5_ct_fs_smfs *fs_smfs = mlx5_ct_fs_priv(fs);

	if (!refcount_dec_and_mutex_lock(&smfs_matcher->ref, &fs_smfs->lock))
		return;

	mlx5dr_matcher_destroy(smfs_matcher->dr_matcher);
	list_del(&smfs_matcher->list);
	mutex_unlock(&fs_smfs->lock);
}

static int
mlx5_ct_fs_smfs_init(struct mlx5_ct_fs *fs)
{
	struct mlx5dr_table *ct_tbl, *ct_nat_tbl, *post_ct_tbl;
	struct mlx5_ct_fs_smfs *fs_smfs = mlx5_ct_fs_priv(fs);

	post_ct_tbl = mlx5dr_table_get_from_fs_ft(fs->post_ct);
	ct_nat_tbl = mlx5dr_table_get_from_fs_ft(fs->ct_nat);
	ct_tbl = mlx5dr_table_get_from_fs_ft(fs->ct);

	if (!ct_tbl || !ct_nat_tbl || !post_ct_tbl) {
		netdev_warn(fs->netdev, "ct_fs_smfs: failed to init, missing backing dr tables");
		return -EOPNOTSUPP;
	}

	ct_dbg("using smfs steering");

	fs_smfs->fwd_action = mlx5dr_action_create_dest_table(post_ct_tbl);
	if (!fs_smfs->fwd_action) {
		return -EINVAL;
	}

	fs_smfs->ct_tbl = ct_tbl;
	fs_smfs->ct_nat_tbl = ct_nat_tbl;
	mutex_init(&fs_smfs->lock);
	INIT_LIST_HEAD(&fs_smfs->matchers.used);
	INIT_LIST_HEAD(&fs_smfs->matchers_nat.used);

	return 0;
}

static void
mlx5_ct_fs_smfs_destroy(struct mlx5_ct_fs *fs)
{
	struct mlx5_ct_fs_smfs *fs_smfs = mlx5_ct_fs_priv(fs);

	mlx5dr_action_destroy(fs_smfs->fwd_action);
}

static inline bool
mlx5_tc_ct_valid_used_dissector_keys(const u32 used_keys)
{
#define DISSECTOR_BIT(name) BIT(FLOW_DISSECTOR_KEY_ ## name)
	const u32 basic_keys = DISSECTOR_BIT(BASIC) | DISSECTOR_BIT(CONTROL) |
			       DISSECTOR_BIT(PORTS) | DISSECTOR_BIT(META);
	const u32 ipv4_tcp = basic_keys | DISSECTOR_BIT(IPV4_ADDRS) | DISSECTOR_BIT(TCP);
	const u32 ipv4_udp = basic_keys | DISSECTOR_BIT(IPV4_ADDRS);
	const u32 ipv6_tcp = basic_keys | DISSECTOR_BIT(IPV6_ADDRS) | DISSECTOR_BIT(TCP);
	const u32 ipv6_udp = basic_keys | DISSECTOR_BIT(IPV6_ADDRS);

	return (used_keys == ipv4_tcp || used_keys == ipv4_udp || used_keys == ipv6_tcp ||
		used_keys == ipv6_udp);
}

static bool
mlx5_ct_fs_smfs_ct_validate_flow_rule(struct mlx5_ct_fs *fs, struct flow_rule *flow_rule)
{
	struct flow_match_ipv4_addrs ipv4_addrs;
	struct flow_match_ipv6_addrs ipv6_addrs;
	struct flow_match_control control;
	struct flow_match_basic basic;
	struct flow_match_ports ports;
	struct flow_match_tcp tcp;

	if (!mlx5_tc_ct_valid_used_dissector_keys(flow_rule->match.dissector->used_keys)) {
		ct_dbg("rule uses unexpected dissectors (0x%08x)",
		       flow_rule->match.dissector->used_keys);
		return false;
	}

	flow_rule_match_basic(flow_rule, &basic);
	flow_rule_match_control(flow_rule, &control);
	flow_rule_match_ipv4_addrs(flow_rule, &ipv4_addrs);
	flow_rule_match_ipv6_addrs(flow_rule, &ipv6_addrs);
	flow_rule_match_ports(flow_rule, &ports);
	flow_rule_match_tcp(flow_rule, &tcp);

	if (basic.mask->n_proto != 0xFFFF ||
	    (basic.key->n_proto != htons(ETH_P_IP) && basic.key->n_proto != htons(ETH_P_IPV6)) ||
	    basic.mask->ip_proto != 0xFF ||
	    (basic.key->ip_proto != IPPROTO_UDP && basic.key->ip_proto != IPPROTO_TCP)) {
		ct_dbg("rule uses unexpected basic match (n_proto 0x%04x/0x%04x, ip_proto 0x%02x/0x%02x)",
		       basic.key->n_proto, basic.mask->n_proto,
		       basic.key->ip_proto, basic.mask->ip_proto);
		return false;
	}

	if (ports.mask->src != 0xFFFF || ports.mask->dst != 0xFFFF) {
		ct_dbg("rule uses ports match (src 0x%04x, dst 0x%04x)",
		       ports.mask->src, ports.mask->dst);
		return false;
	}

	if (basic.key->ip_proto == IPPROTO_TCP && tcp.mask->flags != MLX5_CT_TCP_FLAGS_MASK) {
		ct_dbg("rule uses unexpected tcp match (flags 0x%02x)", tcp.mask->flags);
		return false;
	}

	return true;
}

static int
mlx5_ct_fs_smfs_ct_rule_add(struct mlx5_ct_fs *fs, void *conn_priv, struct mlx5_flow_spec *spec,
			    struct mlx5_flow_attr *attr, struct mlx5_ct_fs_counter *fs_counter,
			    struct flow_rule *flow_rule)
{
	struct mlx5_ct_fs_smfs_zone_rule *zone_rule = conn_priv;
	struct mlx5_ct_fs_smfs *fs_smfs = mlx5_ct_fs_priv(fs);
	struct mlx5_ct_fs_smfs_counter *smfs_counter;
	struct mlx5_ct_fs_smfs_matcher *smfs_matcher;
	struct mlx5dr_match_parameters value = {};
	struct mlx5dr_action *actions[5];
	struct mlx5dr_rule *rule;
	int num_actions = 0, err;
	bool nat, tcp, ipv4;

	if (!mlx5_ct_fs_smfs_ct_validate_flow_rule(fs, flow_rule))
		return -EOPNOTSUPP;

	value.match_buf = (u64 *)spec->match_value;
	value.match_sz = DR_SZ_MATCH_PARAM;

	smfs_counter = container_of(fs_counter, struct mlx5_ct_fs_smfs_counter, fs_counter);
	actions[num_actions++] = smfs_counter->count_action;
	actions[num_actions++] = attr->modify_hdr->action.dr_action;
	actions[num_actions++] = fs_smfs->fwd_action;

	nat = (attr->ft == fs->ct_nat);
	ipv4 = mlx5e_tc_get_ip_version(spec, true) == 4;
	tcp = MLX5_GET(fte_match_param, spec->match_value,
		       outer_headers.ip_protocol) == IPPROTO_TCP;

	smfs_matcher = mlx5_ct_fs_smfs_matcher_get(fs, nat, ipv4, tcp);
	if (IS_ERR(smfs_matcher))
		return PTR_ERR(smfs_matcher);

	rule = mlx5dr_rule_create(smfs_matcher->dr_matcher, &value, num_actions, actions,
				  MLX5_FLOW_CONTEXT_FLOW_SOURCE_ANY_VPORT);
	if (!rule) {
		err = -EINVAL;
		goto err_create;
	}

	zone_rule->smfs_matcher = smfs_matcher;
	zone_rule->rule = rule;

	return 0;

err_create:
	mlx5_ct_fs_smfs_matcher_put(fs, smfs_matcher);
	return err;
}

static void
mlx5_ct_fs_smfs_ct_rule_del(struct mlx5_ct_fs *fs, void *conn_priv, struct mlx5_flow_attr *attr)
{
	struct mlx5_ct_fs_smfs_zone_rule *zone_rule = conn_priv;

	mlx5dr_rule_destroy(zone_rule->rule);
	mlx5_ct_fs_smfs_matcher_put(fs, zone_rule->smfs_matcher);
}

static struct mlx5_ct_fs_counter *
mlx5_ct_fs_smfs_ct_counter_create(struct mlx5_ct_fs *fs)
{
	struct mlx5_ct_fs_smfs_counter *smfs_counter;
	struct mlx5_fc *fc;
	int err = 0;

	smfs_counter = kzalloc(sizeof(*smfs_counter), GFP_KERNEL);
	if (!smfs_counter)
		return ERR_PTR(-ENOMEM);

	fc = mlx5_fc_create(fs->dev, true);
	if (IS_ERR(fc)) {
		err = PTR_ERR(fc);
		goto err_create;
	}

	smfs_counter->count_action = mlx5dr_action_create_flow_counter(mlx5_fc_id(fc));
	if (!smfs_counter->count_action) {
		ct_dbg("Failed to create counter dr action");
		err = -EINVAL;
		goto err_dr_act;
	}

	smfs_counter->fs_counter.counter = fc;
	return &smfs_counter->fs_counter;

err_dr_act:
	mlx5_fc_destroy(fs->dev, fc);
err_create:
	kfree(smfs_counter);
	return ERR_PTR(err);
}

static void
mlx5_ct_fs_smfs_ct_counter_destroy(struct mlx5_ct_fs *fs, struct mlx5_ct_fs_counter *fs_counter)
{
	struct mlx5_ct_fs_smfs_counter *smfs_counter;

	smfs_counter = container_of(fs_counter, struct mlx5_ct_fs_smfs_counter, fs_counter);

	mlx5dr_action_destroy(smfs_counter->count_action);
	mlx5_fc_destroy(fs->dev, smfs_counter->fs_counter.counter);
	kfree(smfs_counter);
}

static struct mlx5_ct_fs_ops fs_smfs_ops = {
	.ct_counter_create = mlx5_ct_fs_smfs_ct_counter_create,
	.ct_counter_destroy = mlx5_ct_fs_smfs_ct_counter_destroy,

	.ct_rule_add = mlx5_ct_fs_smfs_ct_rule_add,
	.ct_rule_del = mlx5_ct_fs_smfs_ct_rule_del,

	.init = mlx5_ct_fs_smfs_init,
	.destroy = mlx5_ct_fs_smfs_destroy,

	.priv_size = sizeof(struct mlx5_ct_fs_smfs),
	.conn_priv_size = sizeof(struct mlx5_ct_fs_smfs_zone_rule),
};

struct mlx5_ct_fs_ops *
mlx5_ct_fs_smfs_ops_get(void)
{
	return &fs_smfs_ops;
}

#else

struct mlx5_ct_fs_ops *
mlx5_ct_fs_smfs_ops_get(void)
{
	return NULL;
}

#endif /* IS_ENABLED(CONFIG_MLX5_SW_STEERING) */
