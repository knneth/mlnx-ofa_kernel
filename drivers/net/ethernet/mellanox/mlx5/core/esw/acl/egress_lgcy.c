// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2020 Mellanox Technologies Inc. All rights reserved. */

#include "mlx5_core.h"
#include "eswitch.h"
#include "helper.h"
#include "lgcy.h"

static void esw_acl_egress_lgcy_rules_destroy(struct mlx5_vport *vport)
{
	struct mlx5_acl_vlan *trunk_vlan_rule, *tmp;

	esw_acl_egress_vlan_destroy(vport);

	list_for_each_entry_safe(trunk_vlan_rule, tmp,
				 &vport->egress.legacy.allow_vlans_rules, list) {
		mlx5_del_flow_rules(trunk_vlan_rule->acl_vlan_rule);
		list_del(&trunk_vlan_rule->list);
		kfree(trunk_vlan_rule);
	}

	if (!IS_ERR_OR_NULL(vport->egress.legacy.drop_rule)) {
		mlx5_del_flow_rules(vport->egress.legacy.drop_rule);
		vport->egress.legacy.drop_rule = NULL;
	}

	if (!IS_ERR_OR_NULL(vport->egress.legacy.allow_untagged_rule)) {
		mlx5_del_flow_rules(vport->egress.legacy.allow_untagged_rule);
		vport->egress.legacy.allow_untagged_rule = NULL;
	}
}

static int esw_acl_egress_lgcy_groups_create(struct mlx5_eswitch *esw,
					     struct mlx5_vport *vport)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_core_dev *dev = esw->dev;
	struct mlx5_flow_group *untagged_grp;
	struct mlx5_flow_group *drop_grp;
	void *match_criteria;
	u32 *flow_group_in;
	int err = 0;

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!flow_group_in)
		return -ENOMEM;

	MLX5_SET(create_flow_group_in, flow_group_in, match_criteria_enable, MLX5_MATCH_OUTER_HEADERS);
	match_criteria = MLX5_ADDR_OF(create_flow_group_in, flow_group_in, match_criteria);

	/* Create flow group for allowed untagged flow rule */
	MLX5_SET_TO_ONES(fte_match_param, match_criteria, outer_headers.cvlan_tag);
	MLX5_SET_TO_ONES(fte_match_param, match_criteria, outer_headers.svlan_tag);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, 0);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, 0);

	untagged_grp = mlx5_create_flow_group(vport->egress.acl, flow_group_in);
	if (IS_ERR(untagged_grp)) {
		err = PTR_ERR(untagged_grp);
		esw_warn(dev, "Failed to create E-Switch vport[%d] egress untagged flow group, err(%d)\n",
			 vport->vport, err);
		goto untagged_grp_err;
	}

	/* Create flow group for allowed tagged flow rules */
	err = esw_acl_egress_vlan_grp_create(esw, vport, 1, VLAN_N_VID);
	if (err) {
		esw_warn(dev, "Failed to create E-Switch vport[%d] egress tagged flow group, err(%d)\n",
			 vport->vport, err);
		goto tagged_grp_err;
	}

	/* Create flow group for drop rule */
	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, VLAN_N_VID + 1);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, VLAN_N_VID + 1);
	drop_grp = mlx5_create_flow_group(vport->egress.acl, flow_group_in);
	if (IS_ERR(drop_grp)) {
		err = PTR_ERR(drop_grp);
		esw_warn(dev, "Failed to create E-Switch vport[%d] egress drop flow group, err(%d)\n",
			 vport->vport, err);
		goto drop_grp_err;
	}

	vport->egress.legacy.allow_untagged_grp = untagged_grp;
	vport->egress.legacy.drop_grp = drop_grp;
	kvfree(flow_group_in);
	return 0;

drop_grp_err:
	esw_acl_egress_vlan_grp_destroy(vport);
tagged_grp_err:
	if (!IS_ERR_OR_NULL(untagged_grp))
		mlx5_destroy_flow_group(untagged_grp);
untagged_grp_err:
	kvfree(flow_group_in);
	return err;
}

static void esw_acl_egress_lgcy_groups_destroy(struct mlx5_vport *vport)
{
	if (!IS_ERR_OR_NULL(vport->egress.legacy.drop_grp)) {
		mlx5_destroy_flow_group(vport->egress.legacy.drop_grp);
		vport->egress.legacy.drop_grp = NULL;
	}

	esw_acl_egress_vlan_grp_destroy(vport);

	if (!IS_ERR_OR_NULL(vport->egress.legacy.allow_untagged_grp)) {
		mlx5_destroy_flow_group(vport->egress.legacy.allow_untagged_grp);
		vport->egress.legacy.allow_untagged_grp = NULL;
	}
}

int esw_acl_egress_lgcy_setup(struct mlx5_eswitch *esw,
			      struct mlx5_vport *vport)
{
	bool need_vlan_filter = !!bitmap_weight(vport->info.vlan_trunk_8021q_bitmap,
						VLAN_N_VID);
	bool need_acl_table = vport->info.vlan || vport->info.qos ||
			      need_vlan_filter;
	enum esw_vst_mode vst_mode = esw_get_vst_mode(esw);
	struct mlx5_acl_vlan *trunk_vlan_rule;
	struct mlx5_flow_destination drop_ctr_dst = {};
	struct mlx5_flow_destination *dst = NULL;
	struct mlx5_fc *drop_counter = NULL;
	struct mlx5_flow_act flow_act = {};
	/* The egress acl table contains 3 groups:
	 * 1)Allow untagged traffic
	 * 2)Allow tagged traffic with vlan_tag=vst_vlan_id/vgt+_vlan_id
	 * 3)Drop all other traffic
	 */
	int table_size = VLAN_N_VID + 2;
	struct mlx5_flow_spec *spec;
	int dest_num = 0;
	u16 vlan_id = 0;
	int err = 0;

	esw_acl_egress_lgcy_rules_destroy(vport);

	esw_acl_egress_lgcy_cleanup(esw, vport);
	if (!need_acl_table)
		return 0;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	if (MLX5_CAP_ESW_EGRESS_ACL(esw->dev, flow_counter)) {
		drop_counter = mlx5_fc_create(esw->dev, false);
		if (IS_ERR(drop_counter))
			esw_warn(esw->dev,
				 "vport[%d] configure egress drop rule counter err(%ld)\n",
				 vport->vport, PTR_ERR(drop_counter));
		vport->egress.legacy.drop_counter = drop_counter;
	}

	vport->egress.acl = esw_acl_table_create(esw, vport,
						 MLX5_FLOW_NAMESPACE_ESW_EGRESS,
						 0, table_size);
	if (IS_ERR_OR_NULL(vport->egress.acl)) {
		err = PTR_ERR(vport->egress.acl);
		vport->egress.acl = NULL;
		goto out;
	}

	err = esw_acl_egress_lgcy_groups_create(esw, vport);
	if (err)
		goto out;

	esw_debug(esw->dev,
		  "vport[%d] configure egress rules, vlan(%d) qos(%d)\n",
		  vport->vport, vport->info.vlan, vport->info.qos);

	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.cvlan_tag);
	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.svlan_tag);
	spec->match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_ALLOW;

	/* Allow untagged */
	if (need_vlan_filter && test_bit(0, vport->info.vlan_trunk_8021q_bitmap)) {
		vport->egress.legacy.allow_untagged_rule =
			mlx5_add_flow_rules(vport->egress.acl, spec,
					    &flow_act, NULL, 0);
		if (IS_ERR(vport->egress.legacy.allow_untagged_rule)) {
			err = PTR_ERR(vport->egress.legacy.allow_untagged_rule);
			esw_warn(esw->dev,
				 "vport[%d] configure egress allow rule, err(%d)\n",
				 vport->vport, err);
			vport->egress.legacy.allow_untagged_rule = NULL;
		}
	}

	/* VST rule */
	if (vport->info.vlan || vport->info.qos) {
		int actions_flag = MLX5_FLOW_CONTEXT_ACTION_ALLOW;

		if (vst_mode == ESW_VST_MODE_STEERING)
			actions_flag |= MLX5_FLOW_CONTEXT_ACTION_VLAN_POP;
		err = esw_egress_acl_vlan_create(esw, vport, NULL, vport->info.vlan_proto,
						 vport->info.vlan, actions_flag);
		if (err)
			goto out;
	}

	/* VGT+ rules */
	if (vport->info.vlan_proto == htons(ETH_P_8021Q))
		MLX5_SET_TO_ONES(fte_match_param, spec->match_value, outer_headers.cvlan_tag);
	else
		MLX5_SET_TO_ONES(fte_match_param, spec->match_value, outer_headers.svlan_tag);
	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.first_vid);
	for_each_set_bit(vlan_id, vport->acl_vlan_8021q_bitmap, VLAN_N_VID) {
		trunk_vlan_rule = kzalloc(sizeof(*trunk_vlan_rule), GFP_KERNEL);
		if (!trunk_vlan_rule) {
			err = -ENOMEM;
			goto out;
		}

		MLX5_SET(fte_match_param, spec->match_value, outer_headers.first_vid,
			 vlan_id);
		trunk_vlan_rule->acl_vlan_rule =
			mlx5_add_flow_rules(vport->egress.acl, spec, &flow_act, NULL, 0);
		if (IS_ERR(trunk_vlan_rule->acl_vlan_rule)) {
			err = PTR_ERR(trunk_vlan_rule->acl_vlan_rule);
			esw_warn(esw->dev,
				 "vport[%d] configure egress allowed vlan rule failed, err(%d)\n",
				 vport->vport, err);
			trunk_vlan_rule->acl_vlan_rule = NULL;
			goto out;
		}
		list_add(&trunk_vlan_rule->list, &vport->egress.legacy.allow_vlans_rules);
	}

	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_DROP;

	/* Attach egress drop flow counter */
	if (!IS_ERR_OR_NULL(drop_counter)) {
		flow_act.action |= MLX5_FLOW_CONTEXT_ACTION_COUNT;
		drop_ctr_dst.type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
		drop_ctr_dst.counter_id = mlx5_fc_id(drop_counter);
		dst = &drop_ctr_dst;
		dest_num++;
	}
	vport->egress.legacy.drop_rule =
		mlx5_add_flow_rules(vport->egress.acl, NULL,
				    &flow_act, dst, dest_num);
	if (IS_ERR(vport->egress.legacy.drop_rule)) {
		err = PTR_ERR(vport->egress.legacy.drop_rule);
		esw_warn(esw->dev,
			 "vport[%d] configure egress drop rule failed, err(%d)\n",
			 vport->vport, err);
		vport->egress.legacy.drop_rule = NULL;
		goto out;
	}

	kvfree(spec);
	return err;

out:
	esw_acl_egress_lgcy_cleanup(esw, vport);
	kvfree(spec);
	return err;
}

void esw_acl_egress_lgcy_cleanup(struct mlx5_eswitch *esw,
				 struct mlx5_vport *vport)
{
	if (IS_ERR_OR_NULL(vport->egress.acl))
		goto clean_drop_counter;

	esw_debug(esw->dev, "Destroy vport[%d] E-Switch egress ACL\n", vport->vport);

	esw_acl_egress_lgcy_rules_destroy(vport);
	esw_acl_egress_lgcy_groups_destroy(vport);
	esw_acl_egress_table_destroy(vport);

clean_drop_counter:
	if (!IS_ERR_OR_NULL(vport->egress.legacy.drop_counter)) {
		mlx5_fc_destroy(esw->dev, vport->egress.legacy.drop_counter);
		vport->egress.legacy.drop_counter = NULL;
	}
}
