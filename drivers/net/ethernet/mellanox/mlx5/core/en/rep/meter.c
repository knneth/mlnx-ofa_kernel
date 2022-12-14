// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2021 NVIDIA Corporation. */

#include "en_rep.h"
#include "eswitch.h"
#include "en/flow_meter.h"

void
mlx5_rep_destroy_miss_meter(struct mlx5_core_dev *dev, struct mlx5e_rep_priv *rep_priv)
{
	struct rep_meter *meter = &rep_priv->rep_meter;
	u64 bytes, packets;

	if (meter->drop_red_rule) {
		mlx5_del_flow_rules(meter->drop_red_rule);
		meter->drop_red_rule = NULL;
	}

	if (meter->drop_counter) {
		mlx5_fc_query(dev, meter->drop_counter, &packets, &bytes);
		meter->packets_dropped += packets;
		meter->bytes_dropped += bytes;
		mlx5_fc_destroy(dev, meter->drop_counter);
		meter->drop_counter = NULL;
	}

	if (meter->meter_rule) {
		mlx5_del_flow_rules(meter->meter_rule);
		meter->meter_rule = NULL;
	}

	if (meter->meter_hndl) {
		mlx5e_free_flow_meter(dev, meter->meter_hndl);
		meter->meter_hndl = NULL;
	}
}

static int mlx5_rep_create_miss_meter_rules(struct mlx5_core_dev *dev,
					    struct mlx5e_rep_priv *rep_priv,
					    u16 vport)
{
	struct rep_meter *meter = &rep_priv->rep_meter;
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct mlx5_flow_destination dest = {};
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_handle *rule;
	struct mlx5_fc *drop_counter;
	struct mlx5_flow_table *tbl;
	struct mlx5_flow_spec *spec;
	void *misc2;
	int err = 0;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	tbl = esw->fdb_table.offloads.miss_meter_fdb;

	mlx5_eswitch_set_rule_source_port(esw, spec, esw, NULL, vport);

	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
			  MLX5_FLOW_CONTEXT_ACTION_EXECUTE_ASO;

	flow_act.exe_aso.type = MLX5_EXE_ASO_FLOW_METER;
	flow_act.exe_aso.object_id = meter->meter_hndl->obj_id;
	flow_act.exe_aso.flow_meter.meter_idx = meter->meter_hndl->idx;
	flow_act.exe_aso.return_reg_id = 5; /* use reg c5 */
	flow_act.exe_aso.flow_meter.init_color = MLX5_FLOW_METER_COLOR_GREEN;

	dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest.ft = esw->fdb_table.offloads.post_miss_meter_fdb;
	rule = mlx5_add_flow_rules(tbl, spec, &flow_act, &dest, 1);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		goto out;
	}

	meter->meter_rule = rule;

	/* Post meter rule - add matching on color and add counter*/
	tbl = esw->fdb_table.offloads.post_miss_meter_fdb;

	drop_counter = mlx5_fc_create(dev, false);
	if (IS_ERR(drop_counter)) {
		err = PTR_ERR(drop_counter);
		goto out;
	}
	meter->drop_counter = drop_counter;

	spec->match_criteria_enable |= MLX5_MATCH_MISC_PARAMETERS_2;

	misc2 = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
			     misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc2, metadata_reg_c_5, 0x3);
	misc2 = MLX5_ADDR_OF(fte_match_param, spec->match_value,
			     misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc2, metadata_reg_c_5,
		 MLX5_FLOW_METER_COLOR_RED);

	memset(&flow_act, 0, sizeof(flow_act));
	memset(&dest, 0, sizeof(dest));
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_DROP |
			  MLX5_FLOW_CONTEXT_ACTION_COUNT;
	dest.type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
	dest.counter_id = mlx5_fc_id(drop_counter);

	rule = mlx5_add_flow_rules(tbl, spec, &flow_act,
				   &dest, 1);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		goto out;
	}

	meter->drop_red_rule = rule;

out:

	if (err)
		mlx5_rep_destroy_miss_meter(dev, rep_priv);

	kvfree(spec);

	return err;
}

int
mlx5_rep_set_miss_meter(struct mlx5_core_dev *dev, struct mlx5e_rep_priv *rep_priv,
			u16 vport, u64 rate, u64 burst)
{
	struct rep_meter *meter = &rep_priv->rep_meter;
	struct mlx5_meter_handle *meter_hndl;
	struct mlx5_flow_meter_params params;
	int err;

	if (rate == meter->rate && burst == meter->burst)
		return 0;

	if (rate == 0 || burst == 0) {
		mlx5_rep_destroy_miss_meter(dev, rep_priv);
		goto update;
	}

	if (!meter->meter_hndl) {
		meter_hndl = mlx5e_alloc_flow_meter(dev);
		if (IS_ERR(meter_hndl))
			return PTR_ERR(meter_hndl);
		meter->meter_hndl = meter_hndl;
	}

	params.mode = MLX5_RATE_LIMIT_PPS;
	params.rate = rate;
	params.burst = burst;
	err = mlx5e_aso_send_flow_meter_aso(dev, meter->meter_hndl, &params);
	if (err)
		goto check_and_free_meter_aso;

	if (!meter->meter_rule) {
		err = mlx5_rep_create_miss_meter_rules(dev, rep_priv, vport);
		if (err)
			return err;
	}

update:
	meter->rate = rate;
	meter->burst = burst;

	return 0;

check_and_free_meter_aso:
	if (!meter->meter_rule) {
		mlx5e_free_flow_meter(dev, meter->meter_hndl);
		meter->meter_hndl = NULL;
	}
	return err;
}

int mlx5_rep_get_miss_meter_data(struct mlx5_core_dev *dev, struct mlx5e_rep_priv *rep_priv,
				 int data_type, u64 *data)
{
	struct rep_meter *meter = &rep_priv->rep_meter;
	u64 bytes = 0, packets = 0;

	if (meter->drop_counter)
		mlx5_fc_query(dev, meter->drop_counter, &packets, &bytes);

	if (data_type == MLX5_RATE_LIMIT_DATA_PACKETS_DROPPED) {
		*data = packets;
		*data += meter->packets_dropped;
	} else if (data_type == MLX5_RATE_LIMIT_DATA_BYTES_DROPPED) {
		*data = bytes;
		*data += meter->bytes_dropped;
	} else {
		return -EINVAL;
	}

	return 0;
}
