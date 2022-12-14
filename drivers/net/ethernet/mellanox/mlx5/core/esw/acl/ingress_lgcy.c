// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2020 Mellanox Technologies Inc. All rights reserved. */

#include "mlx5_core.h"
#include "eswitch.h"
#include "helper.h"
#include "lgcy.h"

static void esw_acl_ingress_lgcy_rules_destroy(struct mlx5_vport *vport)
{
	struct mlx5_acl_vlan *trunk_vlan_rule, *tmp;

	if (vport->ingress.legacy.drop_rule) {
		mlx5_del_flow_rules(vport->ingress.legacy.drop_rule);
		vport->ingress.legacy.drop_rule = NULL;
	}

	list_for_each_entry_safe(trunk_vlan_rule, tmp,
				 &vport->ingress.legacy.allow_vlans_rules,
				 list) {
		mlx5_del_flow_rules(trunk_vlan_rule->acl_vlan_rule);
		list_del(&trunk_vlan_rule->list);
		kfree(trunk_vlan_rule);
	}

	if (vport->ingress.legacy.allow_untagged_rule) {
		mlx5_del_flow_rules(vport->ingress.legacy.allow_untagged_rule);
		vport->ingress.legacy.allow_untagged_rule = NULL;
	}
}

static int esw_acl_ingress_lgcy_groups_create(struct mlx5_eswitch *esw,
					      struct mlx5_vport *vport)
{
	bool need_vlan_filter = !!bitmap_weight(vport->info.vlan_trunk_8021q_bitmap,
						VLAN_N_VID);
	enum esw_vst_mode vst_mode = esw_get_vst_mode(esw);
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_flow_group *untagged_spoof_grp = NULL;
	struct mlx5_flow_group *tagged_spoof_grp = NULL;
	struct mlx5_flow_table *acl = vport->ingress.acl;
	struct mlx5_flow_group *drop_grp = NULL;
	struct mlx5_core_dev *dev = esw->dev;
	void *match_criteria;
	bool push_on_any_pkt;
	int allow_grp_sz = 1;
	u32 *flow_group_in;
	int err;

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!flow_group_in)
		return -ENOMEM;

	match_criteria = MLX5_ADDR_OF(create_flow_group_in, flow_group_in, match_criteria);

	push_on_any_pkt = (vst_mode != ESW_VST_MODE_BASIC) &&
			  !vport->info.spoofchk && !need_vlan_filter;
	if (!push_on_any_pkt)
		MLX5_SET(create_flow_group_in, flow_group_in, match_criteria_enable, MLX5_MATCH_OUTER_HEADERS);

	if (need_vlan_filter || (vst_mode == ESW_VST_MODE_BASIC &&
				 (vport->info.vlan || vport->info.qos)))
		MLX5_SET_TO_ONES(fte_match_param, match_criteria, outer_headers.cvlan_tag);

	if (vport->info.spoofchk) {
		MLX5_SET_TO_ONES(fte_match_param, match_criteria, outer_headers.smac_47_16);
		MLX5_SET_TO_ONES(fte_match_param, match_criteria, outer_headers.smac_15_0);
	}

	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, 0);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, 0);

	untagged_spoof_grp = mlx5_create_flow_group(acl, flow_group_in);
	if (IS_ERR(untagged_spoof_grp)) {
		err = PTR_ERR(untagged_spoof_grp);
		esw_warn(dev, "Failed to create E-Switch vport[%d] ingress untagged spoofchk flow group, err(%d)\n",
			 vport->vport, err);
		goto spoof_err;
	}

	if (push_on_any_pkt)
		goto set_grp;

	if (!need_vlan_filter)
		goto drop_grp;

	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, match_criteria_enable,
		 MLX5_MATCH_OUTER_HEADERS);
	if (vport->info.spoofchk) {
		MLX5_SET_TO_ONES(fte_match_param, match_criteria, outer_headers.smac_47_16);
		MLX5_SET_TO_ONES(fte_match_param, match_criteria, outer_headers.smac_15_0);
	}
	MLX5_SET_TO_ONES(fte_match_param, match_criteria, outer_headers.cvlan_tag);
	MLX5_SET_TO_ONES(fte_match_param, match_criteria, outer_headers.first_vid);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, 1);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, VLAN_N_VID);
	allow_grp_sz = VLAN_N_VID + 1;

	tagged_spoof_grp = mlx5_create_flow_group(acl, flow_group_in);
	if (IS_ERR(tagged_spoof_grp)) {
		err = PTR_ERR(tagged_spoof_grp);
		esw_warn(dev, "Failed to create E-Switch vport[%d] ingress spoofchk flow group, err(%d)\n",
			 vport->vport, err);
		goto allow_spoof_err;
	}

drop_grp:
	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, allow_grp_sz);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, allow_grp_sz);

	drop_grp = mlx5_create_flow_group(acl, flow_group_in);
	if (IS_ERR(drop_grp)) {
		err = PTR_ERR(drop_grp);
		esw_warn(dev, "Failed to create E-Switch vport[%d] ingress drop flow group, err(%d)\n",
			 vport->vport, err);
		goto drop_err;
	}

set_grp:
	vport->ingress.legacy.allow_untagged_spoofchk_grp = untagged_spoof_grp;
	vport->ingress.legacy.allow_tagged_spoofchk_grp = tagged_spoof_grp;
	vport->ingress.legacy.drop_grp = drop_grp;
	kvfree(flow_group_in);
	return 0;

drop_err:
	if (!IS_ERR_OR_NULL(tagged_spoof_grp))
		mlx5_destroy_flow_group(tagged_spoof_grp);
allow_spoof_err:
	if (!IS_ERR_OR_NULL(untagged_spoof_grp))
		mlx5_destroy_flow_group(untagged_spoof_grp);
spoof_err:
	kvfree(flow_group_in);
	return err;
}

static void esw_acl_ingress_lgcy_groups_destroy(struct mlx5_vport *vport)
{
	if (vport->ingress.legacy.allow_tagged_spoofchk_grp) {
		mlx5_destroy_flow_group(vport->ingress.legacy.allow_tagged_spoofchk_grp);
		vport->ingress.legacy.allow_tagged_spoofchk_grp = NULL;
	}
	if (vport->ingress.legacy.allow_untagged_spoofchk_grp) {
		mlx5_destroy_flow_group(vport->ingress.legacy.allow_untagged_spoofchk_grp);
		vport->ingress.legacy.allow_untagged_spoofchk_grp = NULL;
	}
	if (vport->ingress.legacy.drop_grp) {
		mlx5_destroy_flow_group(vport->ingress.legacy.drop_grp);
		vport->ingress.legacy.drop_grp = NULL;
	}
}

int esw_acl_ingress_lgcy_setup(struct mlx5_eswitch *esw,
			       struct mlx5_vport *vport)
{
	bool need_vlan_filter = !!bitmap_weight(vport->info.vlan_trunk_8021q_bitmap,
						VLAN_N_VID);
	enum esw_vst_mode vst_mode = esw_get_vst_mode(esw);
	struct mlx5_flow_destination drop_ctr_dst = {};
	struct mlx5_flow_destination *dst = NULL;
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_spec *spec = NULL;
	struct mlx5_acl_vlan *trunk_vlan_rule;
	struct mlx5_fc *counter = NULL;
	bool need_acl_table = true;
	bool push_on_any_pkt;
	/* The ingress acl table contains 4 groups
	 * (2 active rules at the same time -
	 *      1 allow rule from one of the first 3 groups.
	 *      1 drop rule from the last group):
	 * 1)Allow untagged traffic with smac=original mac.
	 * 2)Allow untagged traffic.
	 * 3)Allow tagged traffic with smac=original mac.
	 * 4)Drop all other traffic.
	 */
	int table_size = need_vlan_filter ? 8192 : 4;
	int dest_num = 0;
	u16 vlan_id = 0;
	int err = 0;
	u8 *smac_v;

	if ((vport->info.vlan || vport->info.qos) && need_vlan_filter) {
		mlx5_core_warn(esw->dev,
			       "vport[%d] configure ingress rules failed, Cannot enable both VGT+ and VST\n",
			       vport->vport);
		return -EPERM;
	}

	need_acl_table = vport->info.vlan || vport->info.qos ||
			 vport->info.spoofchk || need_vlan_filter;

	esw_acl_ingress_lgcy_rules_destroy(vport);

	esw_acl_ingress_lgcy_cleanup(esw, vport);
	if (!need_acl_table)
		return 0;

	if (MLX5_CAP_ESW_INGRESS_ACL(esw->dev, flow_counter)) {
		counter = mlx5_fc_create(esw->dev, false);
		if (IS_ERR(counter)) {
			esw_warn(esw->dev,
				 "vport[%d] configure ingress drop rule counter failed\n",
				 vport->vport);
			counter = NULL;
		}
		vport->ingress.legacy.drop_counter = counter;
	}

	vport->ingress.acl = esw_acl_table_create(esw, vport,
						  MLX5_FLOW_NAMESPACE_ESW_INGRESS,
						  0, table_size);
	if (IS_ERR_OR_NULL(vport->ingress.acl)) {
		err = PTR_ERR(vport->ingress.acl);
		vport->ingress.acl = NULL;
		return err;
	}

	err = esw_acl_ingress_lgcy_groups_create(esw, vport);
	if (err)
		goto out;

	esw_debug(esw->dev,
		  "vport[%d] configure ingress rules, vlan(%d) qos(%d) vst_mode (%d)\n",
		  vport->vport, vport->info.vlan, vport->info.qos, vst_mode);

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		err = -ENOMEM;
		goto out;
	}

	push_on_any_pkt = (vst_mode != ESW_VST_MODE_BASIC) &&
			  !vport->info.spoofchk && !need_vlan_filter;
	if (!push_on_any_pkt)
		spec->match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;

	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_ALLOW;
	if (vst_mode == ESW_VST_MODE_STEERING &&
	    (vport->info.vlan || vport->info.qos)) {
		flow_act.action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH;
		flow_act.vlan[0].prio = vport->info.qos;
		flow_act.vlan[0].vid = vport->info.vlan;
		flow_act.vlan[0].ethtype = ntohs(vport->info.vlan_proto);
	}

	if (need_vlan_filter || (vst_mode == ESW_VST_MODE_BASIC &&
				 (vport->info.vlan || vport->info.qos)))
		MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.cvlan_tag);

	if (vport->info.spoofchk) {
		MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.smac_47_16);
		MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.smac_15_0);
		smac_v = MLX5_ADDR_OF(fte_match_param,
				      spec->match_value,
				      outer_headers.smac_47_16);
		ether_addr_copy(smac_v, vport->info.mac);
	}

	/* Allow untagged */
	if (!need_vlan_filter ||
	    (need_vlan_filter &&
	     test_bit(0, vport->info.vlan_trunk_8021q_bitmap))) {
		vport->ingress.legacy.allow_untagged_rule =
			mlx5_add_flow_rules(vport->ingress.acl, spec,
					    &flow_act, NULL, 0);
		if (IS_ERR(vport->ingress.legacy.allow_untagged_rule)) {
			err = PTR_ERR(vport->ingress.legacy.allow_untagged_rule);
			esw_warn(esw->dev,
				 "vport[%d] configure ingress allow rule, err(%d)\n",
				 vport->vport, err);
			vport->ingress.legacy.allow_untagged_rule = NULL;
			goto out;
		}
	}

	if (push_on_any_pkt)
		goto out;

	if (!need_vlan_filter)
		goto drop_rule;

	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.cvlan_tag);
	MLX5_SET_TO_ONES(fte_match_param, spec->match_value, outer_headers.cvlan_tag);
	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.first_vid);

	/* VGT+ rules */
	for_each_set_bit(vlan_id, vport->acl_vlan_8021q_bitmap, VLAN_N_VID) {
		trunk_vlan_rule = kzalloc(sizeof(*trunk_vlan_rule), GFP_KERNEL);
		if (!trunk_vlan_rule) {
			err = -ENOMEM;
			goto out;
		}

		MLX5_SET(fte_match_param,
			 spec->match_value, outer_headers.first_vid, vlan_id);
		trunk_vlan_rule->acl_vlan_rule =
			mlx5_add_flow_rules(vport->ingress.acl,
					    spec, &flow_act, NULL, 0);
		if (IS_ERR(trunk_vlan_rule->acl_vlan_rule)) {
			err = PTR_ERR(trunk_vlan_rule->acl_vlan_rule);
			esw_warn(esw->dev,
				 "vport[%d] configure ingress allowed vlan rule failed, err(%d)\n",
				 vport->vport, err);
			trunk_vlan_rule->acl_vlan_rule = NULL;
			goto out;
		}
		list_add(&trunk_vlan_rule->list,
			 &vport->ingress.legacy.allow_vlans_rules);
	}

drop_rule:
	memset(spec, 0, sizeof(*spec));
	memset(&flow_act, 0, sizeof(flow_act));
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_DROP;

	/* Attach drop flow counter */
	if (counter) {
		flow_act.action |= MLX5_FLOW_CONTEXT_ACTION_COUNT;
		drop_ctr_dst.type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
		drop_ctr_dst.counter_id = mlx5_fc_id(counter);
		dst = &drop_ctr_dst;
		dest_num++;
	}
	vport->ingress.legacy.drop_rule =
		mlx5_add_flow_rules(vport->ingress.acl, NULL,
				    &flow_act, dst, dest_num);
	if (IS_ERR(vport->ingress.legacy.drop_rule)) {
		err = PTR_ERR(vport->ingress.legacy.drop_rule);
		esw_warn(esw->dev,
			 "vport[%d] configure ingress drop rule, err(%d)\n",
			 vport->vport, err);
		vport->ingress.legacy.drop_rule = NULL;
		goto out;
	}
	kvfree(spec);
	return 0;

out:
	if (err)
		esw_acl_ingress_lgcy_cleanup(esw, vport);
	kvfree(spec);
	return err;
}

void esw_acl_ingress_lgcy_cleanup(struct mlx5_eswitch *esw,
				  struct mlx5_vport *vport)
{
	if (IS_ERR_OR_NULL(vport->ingress.acl))
		goto clean_drop_counter;

	esw_debug(esw->dev, "Destroy vport[%d] E-Switch ingress ACL\n", vport->vport);

	esw_acl_ingress_lgcy_rules_destroy(vport);
	esw_acl_ingress_lgcy_groups_destroy(vport);
	esw_acl_ingress_table_destroy(vport);

clean_drop_counter:
	if (!IS_ERR_OR_NULL(vport->ingress.legacy.drop_counter)) {
		mlx5_fc_destroy(esw->dev, vport->ingress.legacy.drop_counter);
		vport->ingress.legacy.drop_counter = NULL;
	}
}
