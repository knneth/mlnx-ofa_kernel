// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2021 Mellanox Technologies. */

#include "eswitch.h"
#include "en/flow_meter.h"
#include "esw/acl/helper.h"

enum {
	MLX5_FLOW_METER_BPS_PRIO = 0,
	MLX5_FLOW_METER_PPS_PRIO = 2,
};

static void
esw_acl_destrory_meter(struct mlx5_vport *vport, struct vport_meter *meter)
{
	u64 bytes, packets;

	if (meter->drop_red_rule) {
		mlx5_del_flow_rules(meter->drop_red_rule);
		meter->drop_red_rule = NULL;
	}

	if (meter->fwd_green_rule) {
		mlx5_del_flow_rules(meter->fwd_green_rule);
		meter->fwd_green_rule = NULL;
	}

	if (meter->color_grp) {
		mlx5_destroy_flow_group(meter->color_grp);
		meter->color_grp = NULL;
	}

	if (meter->drop_counter) {
		mlx5_fc_query(vport->dev, meter->drop_counter, &packets, &bytes);
		meter->packets_dropped += packets;
		meter->bytes_dropped += bytes;
		mlx5_fc_destroy(vport->dev, meter->drop_counter);
		meter->drop_counter = NULL;
	}

	if (meter->color_tbl) {
		mlx5_destroy_flow_table(meter->color_tbl);
		meter->color_tbl = NULL;
	}

	if (meter->meter_rule) {
		mlx5_del_flow_rules(meter->meter_rule);
		meter->meter_rule = NULL;
	}

	if (meter->meter_grp) {
		mlx5_destroy_flow_group(meter->meter_grp);
		meter->meter_grp = NULL;
	}

	if (meter->meter_hndl) {
		mlx5e_free_flow_meter(vport->dev, meter->meter_hndl);
		meter->meter_hndl = NULL;
	}

	if (meter->meter_tbl) {
		mlx5_destroy_flow_table(meter->meter_tbl);
		meter->meter_tbl = NULL;
	}
}

int
esw_acl_create_meter(struct mlx5_vport *vport, struct vport_meter *meter,
		     int ns, int prio)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_flow_destination drop_ctr_dst = {};
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_handle *rule;
	void *misc2, *match_criteria;
	struct mlx5_fc *drop_counter;
	struct mlx5_flow_table *tbl;
	struct mlx5_flow_group *grp;
	struct mlx5_flow_spec *spec;
	u32 *flow_group_in;
	int err = 0;

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!flow_group_in)
		return -ENOMEM;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		kfree(flow_group_in);
		return -ENOMEM;
	}

	tbl = esw_acl_table_create(vport->dev->priv.eswitch, vport,
				   ns, prio, 1);
	if (IS_ERR(tbl)) {
		err = PTR_ERR(tbl);
		goto out;
	}
	meter->meter_tbl = tbl;

	/* only one FTE in this group */
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, 0);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, 0);

	grp = mlx5_create_flow_group(meter->meter_tbl, flow_group_in);
	if (IS_ERR(grp)) {
		err = PTR_ERR(grp);
		goto out;
	}
	meter->meter_grp = grp;

	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_NEXT_PRIO |
			  MLX5_FLOW_CONTEXT_ACTION_EXECUTE_ASO;
	flow_act.exe_aso.type = MLX5_EXE_ASO_FLOW_METER;
	flow_act.exe_aso.object_id = meter->meter_hndl->obj_id;
	flow_act.exe_aso.flow_meter.meter_idx = meter->meter_hndl->idx;
	flow_act.exe_aso.flow_meter.init_color = MLX5_FLOW_METER_COLOR_GREEN;
	flow_act.exe_aso.return_reg_id = 5; /* use reg c5 */
	rule = mlx5_add_flow_rules(meter->meter_tbl, NULL, &flow_act, NULL, 0);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		goto out;
	}
	meter->meter_rule = rule;

	tbl = esw_acl_table_create(vport->dev->priv.eswitch, vport,
				   ns, prio + 1, 2);
	if (IS_ERR(tbl)) {
		err = PTR_ERR(tbl);
		goto out;
	}
	meter->color_tbl = tbl;

	MLX5_SET(create_flow_group_in, flow_group_in, match_criteria_enable,
		 MLX5_MATCH_MISC_PARAMETERS_2);
	match_criteria = MLX5_ADDR_OF(create_flow_group_in, flow_group_in,
				      match_criteria);
	misc2 = MLX5_ADDR_OF(fte_match_param, match_criteria, misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc2, metadata_reg_c_5, 0x3);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, 0);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, 1);

	grp = mlx5_create_flow_group(meter->color_tbl, flow_group_in);
	if (IS_ERR(grp)) {
		err = PTR_ERR(grp);
		goto out;
	}
	meter->color_grp = grp;

	memset(&flow_act, 0, sizeof(flow_act));
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_NEXT_PRIO;
	spec->match_criteria_enable = MLX5_MATCH_MISC_PARAMETERS_2;
	misc2 = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
			     misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc2, metadata_reg_c_5, 0x3);
	misc2 = MLX5_ADDR_OF(fte_match_param, spec->match_value, misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc2, metadata_reg_c_5,
		 MLX5_FLOW_METER_COLOR_GREEN);

	rule = mlx5_add_flow_rules(meter->color_tbl, spec, &flow_act, NULL, 0);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		goto out;
	}
	meter->fwd_green_rule = rule;

	drop_counter = mlx5_fc_create(vport->dev, false);
	if (IS_ERR(drop_counter)) {
		err = PTR_ERR(drop_counter);
		goto out;
	}
	meter->drop_counter = drop_counter;

	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_DROP;
	MLX5_SET(fte_match_set_misc2, misc2, metadata_reg_c_5,
		 MLX5_FLOW_METER_COLOR_RED);
	flow_act.action |= MLX5_FLOW_CONTEXT_ACTION_COUNT;
	drop_ctr_dst.type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
	drop_ctr_dst.counter_id = mlx5_fc_id(drop_counter);

	rule = mlx5_add_flow_rules(meter->color_tbl, spec, &flow_act,
				   &drop_ctr_dst, 1);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		goto out;
	}
	meter->drop_red_rule = rule;

out:
	if (err)
		esw_acl_destrory_meter(vport, meter);
	kfree(flow_group_in);
	kfree(spec);
	return err;
}

static struct vport_meter *
esw_acl_get_meter(struct mlx5_vport *vport, int rx_tx, int xps)
{
	if (rx_tx == MLX5_RATE_LIMIT_TX)
		return vport->ingress.offloads.meter_xps[xps];
	else
		return vport->egress.offloads.meter_xps[xps];
}

int
esw_vf_meter_set_rate_limit(struct mlx5_vport *vport, struct vport_meter *meter,
			    int rx_tx, int xps, u64 rate, u64 burst)
{
	struct mlx5_meter_handle *meter_hndl;
	struct mlx5_flow_meter_params params;
	int ns, prio;
	int err;

	if (rate == meter->rate && burst == meter->burst)
		return 0;

	if (rate == 0 || burst == 0) {
		esw_acl_destrory_meter(vport, meter);
		goto update;
	}

	if (!meter->meter_hndl) {
		meter_hndl = mlx5e_alloc_flow_meter(vport->dev);
		if (IS_ERR(meter_hndl))
			return PTR_ERR(meter_hndl);
		meter->meter_hndl = meter_hndl;
	}

	params.mode = xps;
	params.rate = rate;
	params.burst = burst;
	err = mlx5e_aso_send_flow_meter_aso(vport->dev, meter->meter_hndl, &params);
	if (err)
		goto check_and_free_meter_aso;

	if (!meter->meter_tbl) {
		if (rx_tx == MLX5_RATE_LIMIT_TX)
			ns = MLX5_FLOW_NAMESPACE_ESW_INGRESS;
		else
			ns = MLX5_FLOW_NAMESPACE_ESW_EGRESS;

		if (xps == MLX5_RATE_LIMIT_PPS)
			prio = MLX5_FLOW_METER_PPS_PRIO;
		else
			prio = MLX5_FLOW_METER_BPS_PRIO;

		err = esw_acl_create_meter(vport, meter, ns, prio);
		if (err)
			return err;
	}

update:
	meter->rate = rate;
	meter->burst = burst;

	return 0;

check_and_free_meter_aso:
	if (!meter->meter_tbl) {
		mlx5e_free_flow_meter(vport->dev, meter->meter_hndl);
		meter->meter_hndl = NULL;
	}
	return err;
}

void
esw_vf_meter_destroy_meters(struct mlx5_eswitch *esw)
{
	struct mlx5_vport *vport;
	int j;
	unsigned long i;

	mlx5_esw_for_each_vf_vport(esw, i, vport, esw->esw_funcs.num_vfs) {
		for (j = MLX5_RATE_LIMIT_BPS; j <= MLX5_RATE_LIMIT_PPS; j++) {
			kfree(vport->ingress.offloads.meter_xps[j]);
			vport->ingress.offloads.meter_xps[j] = NULL;
			kfree(vport->egress.offloads.meter_xps[j]);
			vport->egress.offloads.meter_xps[j] = NULL;
		}
	}
}

int
esw_vf_meter_create_meters(struct mlx5_eswitch *esw)
{
	struct vport_meter *meter;
	struct mlx5_vport *vport;
	int j;
	unsigned long i;

	mlx5_esw_for_each_vf_vport(esw, i, vport, esw->esw_funcs.num_vfs) {
		for (j = MLX5_RATE_LIMIT_BPS; j <= MLX5_RATE_LIMIT_PPS; j++) {
			meter = kzalloc(sizeof(*meter), GFP_KERNEL);
			if (!meter)
				goto err_out;
			vport->egress.offloads.meter_xps[j] = meter;
		}

		for (j = MLX5_RATE_LIMIT_BPS; j <= MLX5_RATE_LIMIT_PPS; j++) {
			meter = kzalloc(sizeof(*meter), GFP_KERNEL);
			if (!meter)
				goto err_out;
			vport->ingress.offloads.meter_xps[j] = meter;
		}
	}

	return 0;

err_out:
	esw_vf_meter_destroy_meters(esw);

	return -ENOMEM;
}

void
esw_vf_meter_ingress_destroy(struct mlx5_vport *vport)
{
	struct vport_meter *meter;
	int i;

	mutex_lock(&vport->ingress.offloads.vf_meter_lock);
	for (i = MLX5_RATE_LIMIT_BPS; i <= MLX5_RATE_LIMIT_PPS; i++) {
		meter = vport->ingress.offloads.meter_xps[i];
		if (meter) {
			esw_acl_destrory_meter(vport, meter);
			vport->ingress.offloads.meter_xps[i] = NULL;
			kfree(meter);
		}
	}
	mutex_unlock(&vport->ingress.offloads.vf_meter_lock);
}

void
esw_vf_meter_egress_destroy(struct mlx5_vport *vport)
{
	struct vport_meter *meter;
	int i;

	mutex_lock(&vport->egress.offloads.vf_meter_lock);
	for (i = MLX5_RATE_LIMIT_BPS; i <= MLX5_RATE_LIMIT_PPS; i++) {
		meter = vport->egress.offloads.meter_xps[i];
		if (meter) {
			esw_acl_destrory_meter(vport, meter);
			vport->egress.offloads.meter_xps[i] = NULL;
			kfree(meter);
		}
	}
	mutex_unlock(&vport->egress.offloads.vf_meter_lock);
}

void
esw_vf_meter_destroy_all(struct mlx5_eswitch *esw)
{
	struct mlx5_vport *vport;
	unsigned long i;

	mlx5_esw_for_each_vf_vport(esw, i, vport, esw->esw_funcs.num_vfs) {
		esw_vf_meter_egress_destroy(vport);
		esw_vf_meter_ingress_destroy(vport);
	}
}

int
mlx5_eswitch_set_vf_meter_data(struct mlx5_eswitch *esw, int vport_num,
			       int data_type, int rx_tx, int xps, u64 data)
{
	struct vport_meter *meter;
	struct mlx5_vport *vport;

	int err;

	if (esw->mode != MLX5_ESWITCH_OFFLOADS)
		return -EOPNOTSUPP;

	vport = mlx5_eswitch_get_vport(esw, vport_num);
	if (IS_ERR_OR_NULL(vport))
		return -EINVAL;

	meter = esw_acl_get_meter(vport, rx_tx, xps);
	if (!meter)
		return -EOPNOTSUPP;

	if (rx_tx == MLX5_RATE_LIMIT_TX)
		mutex_lock(&vport->ingress.offloads.vf_meter_lock);
	else
		mutex_lock(&vport->egress.offloads.vf_meter_lock);

	switch (data_type) {
	case MLX5_RATE_LIMIT_DATA_RATE:
		err = esw_vf_meter_set_rate_limit(vport, meter, rx_tx, xps,
						  data, meter->burst);
		break;
	case MLX5_RATE_LIMIT_DATA_BURST:
		err = esw_vf_meter_set_rate_limit(vport, meter, rx_tx, xps,
						  meter->rate, data);
		break;
	default:
		err = -EINVAL;
	}

	if (rx_tx == MLX5_RATE_LIMIT_TX)
		mutex_unlock(&vport->ingress.offloads.vf_meter_lock);
	else
		mutex_unlock(&vport->egress.offloads.vf_meter_lock);

	return err;
}

int
mlx5_eswitch_get_vf_meter_data(struct mlx5_eswitch *esw, int vport_num,
			       int data_type, int rx_tx, int xps, u64 *data)
{
	struct vport_meter *meter;
	struct mlx5_vport *vport;
	u64 bytes, packets;

	if (esw->mode != MLX5_ESWITCH_OFFLOADS)
		return -EOPNOTSUPP;

	vport = mlx5_eswitch_get_vport(esw, vport_num);
	if (IS_ERR_OR_NULL(vport))
		return -EINVAL;

	if (rx_tx == MLX5_RATE_LIMIT_TX)
		mutex_lock(&vport->ingress.offloads.vf_meter_lock);
	else
		mutex_lock(&vport->egress.offloads.vf_meter_lock);

	meter = esw_acl_get_meter(vport, rx_tx, xps);
	if (!meter)
		return -EOPNOTSUPP;

	switch (data_type) {
	case MLX5_RATE_LIMIT_DATA_RATE:
		*data  = meter->rate;
		break;
	case MLX5_RATE_LIMIT_DATA_BURST:
		*data  = meter->burst;
		break;
	case MLX5_RATE_LIMIT_DATA_PACKETS_DROPPED:
		if (meter->drop_counter) {
			mlx5_fc_query(vport->dev, meter->drop_counter,
				      &packets, &bytes);
			*data = packets;
		} else {
			*data = 0;
		}
		*data += meter->packets_dropped;
		break;
	case MLX5_RATE_LIMIT_DATA_BYTES_DROPPED:
		if (meter->drop_counter) {
			mlx5_fc_query(vport->dev, meter->drop_counter,
				      &packets, &bytes);
			*data = bytes;
		} else {
			*data = 0;
		}
		*data += meter->bytes_dropped;
		break;
	default:
		return -EINVAL;
	}

	if (rx_tx == MLX5_RATE_LIMIT_TX)
		mutex_unlock(&vport->ingress.offloads.vf_meter_lock);
	else
		mutex_unlock(&vport->egress.offloads.vf_meter_lock);

	return 0;
}
