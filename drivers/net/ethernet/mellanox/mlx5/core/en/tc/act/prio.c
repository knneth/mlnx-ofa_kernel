// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include "act.h"
#include "en/tc_priv.h"

struct pedit_headers_action;

static bool
tc_act_can_offload_prio(struct mlx5e_tc_act_parse_state *parse_state,
			const struct flow_action_entry *act,
			int act_index,
			struct mlx5_flow_attr *attr)
{
	if (act->priority > mlx5e_fs_get_tc(parse_state->flow->priv->fs)->num_prio_hp) {
		NL_SET_ERR_MSG_MOD(parse_state->extack, "Skb priority value is out of range");
		return false;
	}

	return true;
}


static int
tc_act_parse_prio(struct mlx5e_tc_act_parse_state *parse_state,
			 const struct flow_action_entry *act,
			 struct mlx5e_priv *priv,
			 struct mlx5_flow_attr *attr)
{
	int err;

	attr->nic_attr->user_prio = act->priority;
	err = mlx5e_tc_match_to_reg_set(priv->mdev, &attr->parse_attr->mod_hdr_acts,
					MLX5_FLOW_NAMESPACE_KERNEL,
					USER_PRIO_TO_REG, attr->nic_attr->user_prio);
	if (err)
		return err;

	attr->action |= MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;

	return 0;
}

struct mlx5e_tc_act mlx5e_tc_act_prio = {
	.can_offload = tc_act_can_offload_prio,
	.parse_action = tc_act_parse_prio,
};
