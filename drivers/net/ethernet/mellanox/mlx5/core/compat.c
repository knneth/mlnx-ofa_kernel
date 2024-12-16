// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2019 Mellanox Technologies. */

#include <linux/mlx5/driver.h>
#include "devlink.h"
#include "eswitch.h"
#include "en.h"
#include "en_rep.h"
#include "en/rep/tc.h"
#include "compat.h"

#ifdef CONFIG_MLX5_ESWITCH
#if defined(HAVE_SWITCHDEV_OPS)
int mlx5e_attr_get(struct net_device *dev, struct switchdev_attr *attr)
{
	int err = 0;

	if (!netif_device_present(dev))
		return -EOPNOTSUPP;

	switch (attr->id) {
#ifndef HAVE_NDO_GET_PORT_PARENT_ID
	case SWITCHDEV_ATTR_ID_PORT_PARENT_ID:
		err = mlx5e_rep_get_port_parent_id(dev, &attr->u.ppid);
		break;
#endif
	default:
		return -EOPNOTSUPP;
	}

	return err;
}
#endif

void mlx5e_rep_set_sysfs_attr(struct net_device *netdev)
{
	if (!netdev)
		return;
}

int mlx5e_vport_rep_load_compat(struct mlx5e_priv *priv)
{
	struct net_device *netdev = priv->netdev;
#if IS_ENABLED(CONFIG_MLX5_CLS_ACT) && defined(HAVE_TC_SETUP_CB_EGDEV_REGISTER)
	struct mlx5e_rep_priv *uplink_rpriv;
#ifdef HAVE_TC_BLOCK_OFFLOAD
	struct mlx5e_priv *upriv;
#endif
	int err;

	uplink_rpriv = mlx5_eswitch_get_uplink_priv(priv->mdev->priv.eswitch,
						    REP_ETH);
#ifdef HAVE_TC_BLOCK_OFFLOAD
	upriv = netdev_priv(uplink_rpriv->netdev);
	err = tc_setup_cb_egdev_register(netdev, mlx5e_rep_setup_tc_cb_egdev,
					 upriv);
#else
	err = tc_setup_cb_egdev_register(netdev, mlx5e_rep_setup_tc_cb,
					 uplink_rpriv->netdev);
#endif
	if (err)
		return err;
#endif

	mlx5e_rep_set_sysfs_attr(netdev);
	return 0;
}

void mlx5e_vport_rep_unload_compat(struct mlx5e_priv *priv)
{
#if IS_ENABLED(CONFIG_MLX5_CLS_ACT) && defined(HAVE_TC_SETUP_CB_EGDEV_REGISTER)
	struct net_device *netdev = priv->netdev;
	struct mlx5e_rep_priv *uplink_rpriv;
#ifdef HAVE_TC_BLOCK_OFFLOAD
	struct mlx5e_priv *upriv;
#endif

	uplink_rpriv = mlx5_eswitch_get_uplink_priv(priv->mdev->priv.eswitch,
						    REP_ETH);
#ifdef HAVE_TC_BLOCK_OFFLOAD
	upriv = netdev_priv(uplink_rpriv->netdev);
	tc_setup_cb_egdev_unregister(netdev, mlx5e_rep_setup_tc_cb_egdev,
				     upriv);
#else
	tc_setup_cb_egdev_unregister(netdev, mlx5e_rep_setup_tc_cb,
				     uplink_rpriv->netdev);
#endif

#endif
}

struct ip_ttl_word {
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
};

struct ipv6_hoplimit_word {
	__be16	payload_len;
	__u8	nexthdr;
	__u8	hop_limit;
};

static inline bool
is_flow_action_entry_modify_ip_header(const struct flow_action_entry *act)
{
	u32 mask, offset;
	u8 htype;

	if (act->id != FLOW_ACTION_MANGLE && act->id != FLOW_ACTION_ADD)
		return false;

	htype = act->mangle.htype;
	offset = act->mangle.offset;
	mask = ~act->mangle.mask;

	if (htype == FLOW_ACT_MANGLE_HDR_TYPE_IP4) {
		struct ip_ttl_word *ttl_word =
			(struct ip_ttl_word *)&mask;

		if (offset != offsetof(struct iphdr, ttl) ||
		    ttl_word->protocol ||
		    ttl_word->check)
			return true;
	} else if (htype == FLOW_ACT_MANGLE_HDR_TYPE_IP6) {
		struct ipv6_hoplimit_word *hoplimit_word =
			(struct ipv6_hoplimit_word *)&mask;

		if (offset != offsetof(struct ipv6hdr, payload_len) ||
		    hoplimit_word->payload_len ||
		    hoplimit_word->nexthdr)
			return true;
	}

	return false;
}

#if IS_ENABLED(CONFIG_MLX5_CLS_ACT)
bool
mlx5e_tc_act_reorder_flow_actions(struct flow_action **flow_action_reorder,
				  struct flow_action **flow_action_before)
{
#ifndef HAVE_FLOW_ACTION_ENTRY_MISS_COOKIE
	struct flow_action *flow_action = *flow_action_before;
	struct flow_action *flow_action_after;
	struct flow_action_entry *act;
	int i, j = 0;

	flow_action_after = kzalloc(sizeof(*flow_action) +
				    flow_action->num_entries *
				    sizeof(flow_action->entries[0]), GFP_KERNEL);
	if (!flow_action_after)
		return false;

	flow_action_after->num_entries = flow_action->num_entries;

	flow_action_for_each(i, act, flow_action) {
		/* Add CT action to be first. */
		if (act->id == FLOW_ACTION_CT)
			flow_action_after->entries[j++] = *act;
	}

	flow_action_for_each(i, act, flow_action) {
		if (act->id == FLOW_ACTION_CT)
			continue;
		flow_action_after->entries[j++] = *act;
	}

	*flow_action_reorder = flow_action_after;
	*flow_action_before = flow_action_after;
#endif
	return true;
}

bool
mlx5e_tc_act_verify_actions(struct flow_action *flow_action)
{
#ifndef HAVE_FLOW_ACTION_ENTRY_MISS_COOKIE
	int ct = 0, ct_nat = 0, ip_modify = 0, sample = 0;
	struct flow_action_entry *act;
	int i;

#undef TCA_CT_ACT_NAT
#define TCA_CT_ACT_NAT		(1 << 3)

#undef TCA_CT_ACT_CLEAR
#define TCA_CT_ACT_CLEAR	(1 << 2)
	flow_action_for_each(i, act, flow_action) {
		if (act->id == FLOW_ACTION_CT) {
#if IS_ENABLED(CONFIG_MLX5_TC_CT)
			bool clear_action = act->ct.action & TCA_CT_ACT_CLEAR;

			if (act->ct.action & TCA_CT_ACT_NAT)
				ct_nat++;
			if (!clear_action)
				ct++;
#endif
			if (ct && ip_modify) /* Modify before CT */
				return false;
		} else if (act->id == FLOW_ACTION_SAMPLE) {
			sample++;
		} else if (is_flow_action_entry_modify_ip_header(act)) {
			ip_modify++;
		}
	}

	if (ct > 1) /* Double CT */
		return false;
	if (ct_nat && sample)
		return false;

	return true;
#endif
	return true;
}
#endif
#endif /* CONFIG_MLX5_ESWITCH */
