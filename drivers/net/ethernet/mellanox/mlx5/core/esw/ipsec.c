// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2020 Mellanox Technologies.

#include <linux/mlx5/driver.h>
#include <linux/mlx5/mlx5_ifc.h>
#include <linux/mlx5/fs.h>
#include "lib/fs_chains.h"
#include "esw/ipsec.h"
#include "mlx5_core.h"
#include "accel/ipsec_offload.h"
#include "../fs_core.h"

#define esw_ipsec_priv(esw) ((esw)->fdb_table.offloads.esw_ipsec_priv)
#define esw_ipsec_ft_crypto_rx(esw) (esw_ipsec_priv(esw)->ipsec_fdb_crypto_rx)
#define esw_ipsec_ft_crypto_rx_miss_grp(esw) (esw_ipsec_priv(esw)->ipsec_fdb_crypto_rx_miss_grp)
#define esw_ipsec_ft_crypto_rx_fwd_rule(esw) (esw_ipsec_priv(esw)->ipsec_fdb_crypto_rx_fwd_rule)

#define esw_ipsec_ft_decap_rx(esw) (esw_ipsec_priv(esw)->ipsec_fdb_decap_rx)
#define esw_ipsec_decap_miss_grp(esw) (esw_ipsec_priv(esw)->ipsec_fdb_decap_miss_grp)
#define esw_ipsec_decap_miss_rule(esw) (esw_ipsec_priv(esw)->ipsec_fdb_decap_miss_rule)
#define esw_ipsec_decap_rule(esw) (esw_ipsec_priv(esw)->ipsec_fdb_decap_rule)
#define esw_ipsec_pkt_reformat(esw) (esw_ipsec_priv(esw)->pkt_reformat)
#define esw_ipsec_decap_modify_hdr(esw) (esw_ipsec_priv(esw)->modify_hdr)
#define esw_ipsec_decap_rule_counter(esw) (esw_ipsec_priv(esw)->decap_rule_counter)
#define esw_ipsec_decap_miss_rule_counter(esw) (esw_ipsec_priv(esw)->decap_miss_rule_counter)

#define esw_ipsec_ft_ike_tx(esw) (esw_ipsec_priv(esw)->ipsec_fdb_ike_tx)
#define esw_ipsec_ft_ike_tx_miss_grp(esw) (esw_ipsec_priv(esw)->ipsec_fdb_ike_tx_miss_grp)
#define esw_ipsec_ft_ike_tx_miss_rule(esw) (esw_ipsec_priv(esw)->ipsec_fdb_ike_tx_miss_rule)
#define esw_ipsec_ft_ike_tx_grp(esw) (esw_ipsec_priv(esw)->ipsec_fdb_ike_tx_grp)
#define esw_ipsec_ft_ike_tx_rule(esw) (esw_ipsec_priv(esw)->ipsec_fdb_ike_tx_rule)
#define esw_ipsec_ft_crypto_tx(esw) (esw_ipsec_priv(esw)->ipsec_fdb_crypto_tx)
#define esw_ipsec_ft_crypto_tx_grp(esw) (esw_ipsec_priv(esw)->ipsec_fdb_crypto_tx_grp)
#define esw_ipsec_ft_crypto_tx_miss_rule(esw) (esw_ipsec_priv(esw)->ipsec_fdb_crypto_tx_miss_rule)
#define esw_ipsec_ft_tx_chk(esw) (esw_ipsec_priv(esw)->ipsec_fdb_tx_chk)
#define esw_ipsec_ft_tx_chk_grp(esw) (esw_ipsec_priv(esw)->ipsec_fdb_tx_chk_grp)
#define esw_ipsec_ft_tx_chk_rule(esw) (esw_ipsec_priv(esw)->ipsec_fdb_tx_chk_rule)
#define esw_ipsec_ft_tx_chk_rule_drop(esw) (esw_ipsec_priv(esw)->ipsec_fdb_tx_chk_rule_drop)
#define esw_ipsec_tx_chk_counter(esw) (esw_ipsec_priv(esw)->tx_chk_rule_counter)
#define esw_ipsec_tx_chk_drop_counter(esw) (esw_ipsec_priv(esw)->tx_chk_drop_rule_counter)

#define esw_ipsec_refcnt(esw) (esw_ipsec_priv(esw)->refcnt)
#define NUM_IPSEC_FTE BIT(18)

struct mlx5_esw_ipsec_priv {
	/* Rx tables, groups and miss rules */
	struct mlx5_flow_table *ipsec_fdb_crypto_rx;
	struct mlx5_flow_group *ipsec_fdb_crypto_rx_miss_grp;
	struct mlx5_flow_handle *ipsec_fdb_crypto_rx_fwd_rule;

	struct mlx5_flow_table *ipsec_fdb_decap_rx;
	struct mlx5_flow_group *ipsec_fdb_decap_miss_grp;
	struct mlx5_flow_handle *ipsec_fdb_decap_miss_rule;
	struct mlx5_flow_handle *ipsec_fdb_decap_rule;
	struct mlx5_pkt_reformat *pkt_reformat;
	struct mlx5_modify_hdr *modify_hdr;
	struct mlx5_fc *decap_rule_counter;
	struct mlx5_fc *decap_miss_rule_counter;

	/* Tx tables, groups and default rules */
	struct mlx5_flow_table *ipsec_fdb_ike_tx;
	struct mlx5_flow_group *ipsec_fdb_ike_tx_miss_grp;
	struct mlx5_flow_handle *ipsec_fdb_ike_tx_miss_rule;
	struct mlx5_flow_group *ipsec_fdb_ike_tx_grp;
	struct mlx5_flow_handle *ipsec_fdb_ike_tx_rule;

	struct mlx5_flow_table *ipsec_fdb_crypto_tx;
	struct mlx5_flow_group *ipsec_fdb_crypto_tx_grp;
	struct mlx5_flow_handle *ipsec_fdb_crypto_tx_miss_rule;
	struct mlx5_flow_table *ipsec_fdb_tx_chk;
	struct mlx5_flow_group *ipsec_fdb_tx_chk_grp;
	struct mlx5_flow_handle *ipsec_fdb_tx_chk_rule;
	struct mlx5_flow_handle *ipsec_fdb_tx_chk_rule_drop;
	struct mlx5_fc *tx_chk_rule_counter;
	struct mlx5_fc *tx_chk_drop_rule_counter;

	/* Flow tables refcount */
	atomic_t refcnt;
};

static struct mlx5_flow_table *esw_ipsec_table_create(struct mlx5_flow_namespace *ns,
						      struct mlx5_eswitch *esw, int prio,
						      int level, int num_res,
						      int max_num_groups, int max_fte)
{
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5_flow_table *fdb = NULL;

	/* reserve entry for the match all miss group and rule */
	ft_attr.autogroup.num_reserved_entries = num_res;
	ft_attr.autogroup.max_num_groups = max_num_groups;
	ft_attr.flags = MLX5_FLOW_TABLE_TUNNEL_EN_REFORMAT;
	ft_attr.level = level;
	ft_attr.max_fte = max_fte;
	ft_attr.prio = prio;
	fdb = mlx5_create_auto_grouped_flow_table(ns, &ft_attr);
	if (IS_ERR(fdb)) {
		esw_warn(esw->dev, "Failed to create IPsec Crypto FDB Table, prio %d err %ld\n",
			 prio, PTR_ERR(fdb));
		return fdb;
	}

	return fdb;
}

static void esw_offloads_ipsec_tables_rx_destroy(struct mlx5_eswitch *esw)
{
	if (esw_ipsec_decap_rule(esw)) {
		mlx5_del_flow_rules(esw_ipsec_decap_rule(esw));
		esw_ipsec_decap_rule(esw) = NULL;
	}

	if (esw_ipsec_pkt_reformat(esw)) {
		mlx5_packet_reformat_dealloc(esw->dev, esw_ipsec_pkt_reformat(esw));
		esw_ipsec_pkt_reformat(esw) = NULL;
		mlx5_chains_put_table(esw_chains(esw), 0, 1, 0);
	}

	if (esw_ipsec_decap_modify_hdr(esw)) {
		mlx5_modify_header_dealloc(esw->dev, esw_ipsec_decap_modify_hdr(esw));
		esw_ipsec_decap_modify_hdr(esw) = NULL;
	}

	if (esw_ipsec_decap_rule_counter(esw)) {
		mlx5_fc_destroy(esw->dev, esw_ipsec_decap_rule_counter(esw));
		esw_ipsec_decap_rule_counter(esw) = NULL;
	}

	if (esw_ipsec_decap_miss_rule(esw)) {
		mlx5_del_flow_rules(esw_ipsec_decap_miss_rule(esw));
		esw_ipsec_decap_miss_rule(esw) = NULL;
	}

	if (esw_ipsec_decap_miss_rule_counter(esw)) {
		mlx5_fc_destroy(esw->dev, esw_ipsec_decap_miss_rule_counter(esw));
		esw_ipsec_decap_miss_rule_counter(esw) = NULL;
	}

	if (esw_ipsec_decap_miss_grp(esw)) {
		mlx5_destroy_flow_group(esw_ipsec_decap_miss_grp(esw));
		esw_ipsec_decap_miss_grp(esw) = NULL;
	}

	if (esw_ipsec_ft_decap_rx(esw)) {
		mlx5_destroy_flow_table(esw_ipsec_ft_decap_rx(esw));
		esw_ipsec_ft_decap_rx(esw) = NULL;
	}

	if (esw_ipsec_ft_crypto_rx_fwd_rule(esw)) {
		mlx5_del_flow_rules(esw_ipsec_ft_crypto_rx_fwd_rule(esw));
		esw_ipsec_ft_crypto_rx_fwd_rule(esw) = NULL;
	}

	if (esw_ipsec_ft_crypto_rx_miss_grp(esw)) {
		mlx5_destroy_flow_group(esw_ipsec_ft_crypto_rx_miss_grp(esw));
		esw_ipsec_ft_crypto_rx_miss_grp(esw) = NULL;
		mlx5_chains_put_table(esw_chains(esw), 0, 1, 0);
	}

	if (esw_ipsec_ft_crypto_rx(esw)) {
		mlx5_destroy_flow_table(esw_ipsec_ft_crypto_rx(esw));
		esw_ipsec_ft_crypto_rx(esw) = NULL;
	}
}

static int esw_offloads_ipsec_tables_rx_create(struct mlx5_flow_namespace *ns, struct mlx5_eswitch *esw)
{
	u8 action[MLX5_UN_SZ_BYTES(set_add_copy_action_in_auto)] = {};
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_pkt_reformat_params reformat_params;
	struct mlx5_core_dev *mdev = esw->dev;
	struct mlx5_flow_destination dest[2];
	struct mlx5_modify_hdr *modify_hdr;
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_spec *spec;
	struct mlx5_flow_handle *rule;
	struct mlx5_fc *flow_counter;
	struct mlx5_flow_table *ft;
	struct mlx5_flow_group *g;
	u32 *flow_group_in;
	int err = 0;

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!flow_group_in)
		return -ENOMEM;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		kvfree(flow_group_in);
		return -ENOMEM;
	}

	/* Rx Table 1 */
#define RX_TABLE_LEVEL_1 0
	ft = esw_ipsec_table_create(ns, esw, FDB_CRYPTO_INGRESS, RX_TABLE_LEVEL_1, 1, 2, NUM_IPSEC_FTE);
	if (IS_ERR(ft)) {
		err = PTR_ERR(ft);
		esw_warn(esw->dev, "Failed to create Rx table 1 err(%d)\n", err);
		goto out_err;
	}
	esw_ipsec_ft_crypto_rx(esw) = ft;

	/* Rx Table 1 - match all group create */
	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, esw_ipsec_ft_crypto_rx(esw)->max_fte - 1);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, esw_ipsec_ft_crypto_rx(esw)->max_fte - 1);
	g = mlx5_create_flow_group(esw_ipsec_ft_crypto_rx(esw), flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(esw->dev, "Failed to create Rx table1 default forward flow group err(%d)\n", err);
		goto out_err;
	}
	esw_ipsec_ft_crypto_rx_miss_grp(esw) = g;

	/* Rx Table 1 - default forward rule */
	memset(dest, 0, 2 * sizeof(struct mlx5_flow_destination));
	memset(spec, 0, sizeof(*spec));
	memset(&flow_act, 0, sizeof(flow_act));
	flow_act.flags = FLOW_ACT_NO_APPEND;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	dest[0].type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest[0].ft = mlx5_chains_get_table(esw_chains(esw), 0, 1, 0);
	rule = mlx5_add_flow_rules(esw_ipsec_ft_crypto_rx(esw), spec, &flow_act, dest, 1);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		esw_warn(esw->dev, "Failed to add IPsec Rx crypto forward rule err=%d\n",  err);
		goto out_err;
	}
	esw_ipsec_ft_crypto_rx_fwd_rule(esw) = rule;

	/* Rx Table 2 */
#define RX_TABLE_LEVEL_2 1
	ft = esw_ipsec_table_create(ns, esw, FDB_CRYPTO_INGRESS, RX_TABLE_LEVEL_2, 1, 1, NUM_IPSEC_FTE);
	if (IS_ERR(ft)) {
		err = PTR_ERR(ft);
		esw_warn(esw->dev, "Failed to create Rx table 2 err(%d)\n", err);
		goto out_err;
	}
	esw_ipsec_ft_decap_rx(esw) = ft;

	/* Rx Table 2 - match all group create */
	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, esw_ipsec_ft_decap_rx(esw)->max_fte - 1);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, esw_ipsec_ft_decap_rx(esw)->max_fte - 1);
	g = mlx5_create_flow_group(esw_ipsec_ft_decap_rx(esw), flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(esw->dev, "Failed to create Rx table2 default drop flow group err(%d)\n", err);
		goto out_err;
	}
	esw_ipsec_decap_miss_grp(esw) = g;

	/* Rx Table 2 - add default drop rule */
	flow_counter = mlx5_fc_create(esw->dev, false);
	if (IS_ERR(flow_counter)) {
		esw_warn(esw->dev, "fail to create decap miss rule flow counter err(%ld)\n", PTR_ERR(flow_counter));
		err = PTR_ERR(flow_counter);
		goto out_err;
	}
	esw_ipsec_decap_miss_rule_counter(esw) = flow_counter;

	memset(dest, 0, 2 * sizeof(struct mlx5_flow_destination));
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_DROP | MLX5_FLOW_CONTEXT_ACTION_COUNT;
	dest[0].type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
	dest[0].counter_id = mlx5_fc_id(esw_ipsec_decap_miss_rule_counter(esw));
	spec->flow_context.flow_source = MLX5_FLOW_CONTEXT_FLOW_SOURCE_UPLINK;
	rule = mlx5_add_flow_rules(esw_ipsec_ft_decap_rx(esw),  spec, &flow_act, dest, 1);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		esw_warn(esw->dev, "fs offloads: Failed to add ipsec_fdb_decap_rx default drop rule %d\n", err);
		goto out_err;
	}
	esw_ipsec_decap_miss_rule(esw) = rule;

	/* Rx Table 2 - add decap rule */
	flow_counter = mlx5_fc_create(esw->dev, false);
	if (IS_ERR(flow_counter)) {
		esw_warn(esw->dev, "fail to create decap rule flow counter err(%ld)\n", PTR_ERR(flow_counter));
		err = PTR_ERR(flow_counter);
		goto out_err;
	}
	esw_ipsec_decap_rule_counter(esw) = flow_counter;

	MLX5_SET(set_action_in, action, action_type, MLX5_ACTION_TYPE_SET);
	MLX5_SET(set_action_in, action, field, MLX5_ACTION_IN_FIELD_METADATA_REG_C_1);
	MLX5_SET(set_action_in, action, data, 1);
	MLX5_SET(set_action_in, action, offset, 31);
	MLX5_SET(set_action_in, action, length, 1);
	modify_hdr = mlx5_modify_header_alloc(mdev, MLX5_FLOW_NAMESPACE_FDB, 1, action);
	if (IS_ERR(modify_hdr)) {
		err = PTR_ERR(modify_hdr);
		esw_warn(esw->dev, "fail to alloc ipsec decap set modify_header_id err=%d\n", err);
		goto out_err;
	}
	esw_ipsec_decap_modify_hdr(esw) = modify_hdr;

	/* Rx Table 2 - check ipsec_syndrome and aso_return_reg (set to REG_C_5) */
	memset(dest, 0, 2 * sizeof(struct mlx5_flow_destination));
	memset(spec, 0, sizeof(*spec));
	memset(&flow_act, 0, sizeof(flow_act));

	memset(&reformat_params, 0, sizeof(reformat_params));
	reformat_params.type = MLX5_REFORMAT_TYPE_DEL_ESP_TRANSPORT;
	flow_act.pkt_reformat = mlx5_packet_reformat_alloc(mdev, &reformat_params,
							   MLX5_FLOW_NAMESPACE_FDB);
	if (IS_ERR(flow_act.pkt_reformat)) {
		err = PTR_ERR(flow_act.pkt_reformat);
		esw_warn(esw->dev, "Failed to allocate delete esp reformat, err=%d\n", err);
		goto out_err;
	}
	esw_ipsec_pkt_reformat(esw) = flow_act.pkt_reformat;

	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, misc_parameters_2.ipsec_syndrome);
	MLX5_SET(fte_match_param, spec->match_value, misc_parameters_2.ipsec_syndrome, 0);
	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, misc_parameters_2.metadata_reg_c_4);
	MLX5_SET(fte_match_param, spec->match_value, misc_parameters_2.metadata_reg_c_4, 0);
	spec->flow_context.flow_source = MLX5_FLOW_CONTEXT_FLOW_SOURCE_UPLINK;
	spec->match_criteria_enable = MLX5_MATCH_MISC_PARAMETERS_2;
	flow_act.modify_hdr = modify_hdr;
	flow_act.flags = FLOW_ACT_NO_APPEND;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT |
			  MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
			  MLX5_FLOW_CONTEXT_ACTION_COUNT |
			  MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;
	dest[0].type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest[0].ft = mlx5_chains_get_table(esw_chains(esw), 0, 1, 0);
	dest[1].type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
	dest[1].counter_id = mlx5_fc_id(esw_ipsec_decap_rule_counter(esw));
	rule = mlx5_add_flow_rules(esw_ipsec_ft_decap_rx(esw), spec, &flow_act, dest, 2);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		esw_warn(esw->dev, "Failed to add IPsec Rx decap rule err=%d\n",  err);
		goto out_err;
	}
	esw_ipsec_decap_rule(esw) = rule;

	goto out;

out_err:
	esw_offloads_ipsec_tables_rx_destroy(esw);
out:
	kvfree(spec);
	kvfree(flow_group_in);
	return err;
}

static void esw_offloads_ipsec_tables_tx_destroy(struct mlx5_eswitch *esw)
{
	/* Tx table 3 */
	if (esw_ipsec_ft_tx_chk_rule(esw)) {
		mlx5_del_flow_rules(esw_ipsec_ft_tx_chk_rule(esw));
		esw_ipsec_ft_tx_chk_rule(esw) = NULL;
	}

	if (esw_ipsec_tx_chk_counter(esw)) {
		mlx5_fc_destroy(esw->dev, esw_ipsec_tx_chk_counter(esw));
		esw_ipsec_tx_chk_counter(esw) = NULL;
	}

	if (esw_ipsec_ft_tx_chk_rule_drop(esw)) {
		mlx5_del_flow_rules(esw_ipsec_ft_tx_chk_rule_drop(esw));
		esw_ipsec_ft_tx_chk_rule_drop(esw) = NULL;
	}

	if (esw_ipsec_tx_chk_drop_counter(esw)) {
		mlx5_fc_destroy(esw->dev, esw_ipsec_tx_chk_drop_counter(esw));
		esw_ipsec_tx_chk_drop_counter(esw) = NULL;
	}

	if (esw_ipsec_ft_tx_chk_grp(esw)) {
		mlx5_destroy_flow_group(esw_ipsec_ft_tx_chk_grp(esw));
		esw_ipsec_ft_tx_chk_grp(esw) = NULL;
	}

	if (esw_ipsec_ft_tx_chk(esw)) {
		mlx5_destroy_flow_table(esw_ipsec_ft_tx_chk(esw));
		esw_ipsec_ft_tx_chk(esw) = NULL;
	}

	/* Tx table2 */
	if (esw_ipsec_ft_ike_tx_miss_rule(esw)) {
		mlx5_del_flow_rules(esw_ipsec_ft_ike_tx_miss_rule(esw));
		esw_ipsec_ft_ike_tx_miss_rule(esw) = NULL;
	}

	if (esw_ipsec_ft_crypto_tx_miss_rule(esw)) {
		mlx5_del_flow_rules(esw_ipsec_ft_crypto_tx_miss_rule(esw));
		esw_ipsec_ft_crypto_tx_miss_rule(esw) = NULL;
	}

	if (esw_ipsec_ft_crypto_tx_grp(esw)) {
		mlx5_destroy_flow_group(esw_ipsec_ft_crypto_tx_grp(esw));
		esw_ipsec_ft_crypto_tx_grp(esw) = NULL;
	}

	if (esw_ipsec_ft_crypto_tx(esw)) {
		mlx5_destroy_flow_table(esw_ipsec_ft_crypto_tx(esw));
		esw_ipsec_ft_crypto_tx(esw) = NULL;
	}

	/* Tx table 1 */
	if (esw_ipsec_ft_ike_tx_miss_grp(esw)) {
		mlx5_destroy_flow_group(esw_ipsec_ft_ike_tx_miss_grp(esw));
		esw_ipsec_ft_ike_tx_miss_grp(esw) = NULL;
	}

	if (esw_ipsec_ft_ike_tx_rule(esw)) {
		mlx5_del_flow_rules(esw_ipsec_ft_ike_tx_rule(esw));
		esw_ipsec_ft_ike_tx_rule(esw) = NULL;
	}

	if (esw_ipsec_ft_ike_tx_grp(esw)) {
		mlx5_destroy_flow_group(esw_ipsec_ft_ike_tx_grp(esw));
		esw_ipsec_ft_ike_tx_grp(esw) = NULL;
	}

	if (esw_ipsec_ft_ike_tx(esw)) {
		mlx5_destroy_flow_table(esw_ipsec_ft_ike_tx(esw));
		esw_ipsec_ft_ike_tx(esw) = NULL;
	}

}

#define IKE_UDP_PORT 500
static int esw_offloads_ipsec_tables_tx_create(struct mlx5_flow_namespace *ns, struct mlx5_eswitch *esw)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5_flow_destination dest[2];
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_handle *rule;
	struct mlx5_fc *flow_counter;
	struct mlx5_flow_spec *spec;
	struct mlx5_flow_table *ft;
	struct mlx5_flow_group *g;
	void *match_criteria;
	u32 *flow_group_in;
	int err = 0;

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!flow_group_in)
		return -ENOMEM;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		kvfree(flow_group_in);
		return -ENOMEM;
	}

	/* Tx table 1 */
#define TX_TABLE_LEVEL_1 0
	ft_attr.flags = MLX5_FLOW_TABLE_TUNNEL_EN_REFORMAT;
	ft_attr.level = TX_TABLE_LEVEL_1;
	ft_attr.max_fte = 2;
	ft_attr.prio = FDB_CRYPTO_EGRESS;
	ft = mlx5_create_flow_table(ns, &ft_attr);
	if (IS_ERR(ft)) {
		err = PTR_ERR(ft);
		esw_warn(esw->dev, "Failed to create IPsec IKE Tx table err(%d)\n", err);
		goto out_err;
	}
	esw_ipsec_ft_ike_tx(esw) = ft;

	/* IKE table Exclusion ike group */
	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, match_criteria_enable,
		 MLX5_MATCH_OUTER_HEADERS);
	match_criteria = MLX5_ADDR_OF(create_flow_group_in, flow_group_in,
				      match_criteria.outer_headers);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, match_criteria, udp_dport);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, match_criteria, ip_protocol);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, 0);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, 0);
	g = mlx5_create_flow_group(esw_ipsec_ft_ike_tx(esw), flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(esw->dev, "Failed to IPsec IKE Tx table default flow group err(%d)\n", err);
		goto out_err;
	}
	esw_ipsec_ft_ike_tx_grp(esw) = g;

	/* IKE table Exclusion ike rule */
	memset(spec, 0, sizeof(*spec));
	spec->match_criteria_enable |= MLX5_MATCH_OUTER_HEADERS;
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, spec->match_criteria, udp_dport);
	MLX5_SET(fte_match_set_lyr_2_4, spec->match_value, udp_dport, IKE_UDP_PORT);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, spec->match_criteria, ip_protocol);
	MLX5_SET(fte_match_set_lyr_2_4, spec->match_value, ip_protocol, IPPROTO_UDP);
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	memset(dest, 0, 2 * sizeof(struct mlx5_flow_destination));
	dest[0].type = MLX5_FLOW_DESTINATION_TYPE_VPORT;
	dest[0].vport.num = MLX5_VPORT_UPLINK;
	rule = mlx5_add_flow_rules(esw_ipsec_ft_ike_tx(esw), spec, &flow_act, dest, 1);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		esw_warn(esw->dev, "Failed to add IPsec Tx table exclusion ike rule %d\n", err);
		goto out_err;
	}
	esw_ipsec_ft_ike_tx_rule(esw) = rule;

	/* IKE table default miss group */
	memset(flow_group_in, 0, inlen);
	memset(spec, 0, sizeof(*spec));
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, 1);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, 1);
	g = mlx5_create_flow_group(esw_ipsec_ft_ike_tx(esw), flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(esw->dev, "Failed to IPsec IKE Tx table default flow miss group err(%d)\n", err);
		goto out_err;
	}
	esw_ipsec_ft_ike_tx_miss_grp(esw) = g;

	/* Tx table 2 */
#define TX_TABLE_LEVEL_2 1
	ft = esw_ipsec_table_create(ns, esw, FDB_CRYPTO_EGRESS, TX_TABLE_LEVEL_2, 1, 4, NUM_IPSEC_FTE);
	if (IS_ERR(ft)) {
		err = PTR_ERR(ft);
		esw_warn(esw->dev, "Failed to create IPsec Tx table err(%d)\n", err);
		goto out_err;
	}
	esw_ipsec_ft_crypto_tx(esw) = ft;

	/* default miss group/rule */
	memset(flow_group_in, 0, inlen);
	memset(spec, 0, sizeof(*spec));
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, esw_ipsec_ft_crypto_tx(esw)->max_fte - 1);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, esw_ipsec_ft_crypto_tx(esw)->max_fte - 1);
	g = mlx5_create_flow_group(esw_ipsec_ft_crypto_tx(esw), flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(esw->dev, "Failed to IPsec Tx table default flow group err(%d)\n", err);
		goto out_err;
	}
	esw_ipsec_ft_crypto_tx_grp(esw) = g;

	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	memset(dest, 0, 2 * sizeof(struct mlx5_flow_destination));
	dest[0].type = MLX5_FLOW_DESTINATION_TYPE_VPORT;
	dest[0].vport.num = MLX5_VPORT_UPLINK;
	rule = mlx5_add_flow_rules(esw_ipsec_ft_crypto_tx(esw), spec, &flow_act, dest, 1);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		esw_warn(esw->dev, "Failed to add IPsec Tx table default miss rule %d\n", err);
		goto out_err;
	}
	esw_ipsec_ft_crypto_tx_miss_rule(esw) = rule;

	/* IKE table default miss rule */
	memset(spec, 0, sizeof(*spec));
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	memset(dest, 0, 2 * sizeof(struct mlx5_flow_destination));
	dest[0].type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest[0].ft = esw_ipsec_ft_crypto_tx(esw);
	rule = mlx5_add_flow_rules(esw_ipsec_ft_ike_tx(esw), spec, &flow_act, dest, 1);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		esw_warn(esw->dev, "Failed to add IPsec IKE Tx table default miss rule %d\n", err);
		goto out_err;
	}
	esw_ipsec_ft_ike_tx_miss_rule(esw) = rule;

	/* Tx Table 3 */
#define TX_TABLE_LEVEL_3 2
	ft = esw_ipsec_table_create(ns, esw, FDB_CRYPTO_EGRESS, TX_TABLE_LEVEL_3, 1, 1, 2);
	if (IS_ERR(ft)) {
		err = PTR_ERR(ft);
		esw_warn(esw->dev, "Failed to create Tx table 2 err(%d)\n", err);
		goto out_err;
	}
	esw_ipsec_ft_tx_chk(esw) = ft;

	/* Tx Table 3 - match all group create */
	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, esw_ipsec_ft_tx_chk(esw)->max_fte - 1);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, esw_ipsec_ft_tx_chk(esw)->max_fte - 1);
	g = mlx5_create_flow_group(esw_ipsec_ft_tx_chk(esw), flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(esw->dev, "Failed to create Tx table2 default drop flow group err(%d)\n", err);
		goto out_err;
	}
	esw_ipsec_ft_tx_chk_grp(esw) = g;

	/* Tx Table 3 - add default drop rule */
	flow_counter = mlx5_fc_create(esw->dev, false);
	if (IS_ERR(flow_counter)) {
		esw_warn(esw->dev, "fail to create tx chk drop flow counter err(%ld)\n", PTR_ERR(flow_counter));
		err = PTR_ERR(flow_counter);
		goto out_err;
	}
	esw_ipsec_tx_chk_drop_counter(esw) = flow_counter;

	memset(dest, 0, 2 * sizeof(struct mlx5_flow_destination));
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_DROP | MLX5_FLOW_CONTEXT_ACTION_COUNT;
	dest[0].type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
	dest[0].counter_id = mlx5_fc_id(esw_ipsec_tx_chk_drop_counter(esw));
	spec->flow_context.flow_source = MLX5_FLOW_CONTEXT_FLOW_SOURCE_LOCAL_VPORT;
	rule = mlx5_add_flow_rules(esw_ipsec_ft_tx_chk(esw),  spec, &flow_act, dest, 1);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		esw_warn(esw->dev, "fs offloads: Failed to add tx chk drop rule %d\n", err);
		goto out_err;
	}
	esw_ipsec_ft_tx_chk_rule_drop(esw) = rule;

	/* Tx Table 3 - add tx chk rule */
	flow_counter = mlx5_fc_create(esw->dev, false);
	if (IS_ERR(flow_counter)) {
		esw_warn(esw->dev, "fail to create tx chk rule flow counter err(%ld)\n", PTR_ERR(flow_counter));
		err = PTR_ERR(flow_counter);
		goto out_err;
	}
	esw_ipsec_tx_chk_counter(esw) = flow_counter;

	/* Tx Table 3 - check aso_return_reg (set to REG_C_5) */
	memset(dest, 0, 2 * sizeof(struct mlx5_flow_destination));
	memset(spec, 0, sizeof(*spec));
	memset(&flow_act, 0, sizeof(flow_act));
	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, misc_parameters_2.metadata_reg_c_4);
	MLX5_SET(fte_match_param, spec->match_value, misc_parameters_2.metadata_reg_c_4, 0);
	spec->flow_context.flow_source = MLX5_FLOW_CONTEXT_FLOW_SOURCE_LOCAL_VPORT;
	spec->match_criteria_enable = MLX5_MATCH_MISC_PARAMETERS_2;
	flow_act.flags = FLOW_ACT_NO_APPEND;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST | MLX5_FLOW_CONTEXT_ACTION_COUNT;

	dest[0].type = MLX5_FLOW_DESTINATION_TYPE_VPORT;
	dest[0].vport.num = MLX5_VPORT_UPLINK;
	dest[1].type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
	dest[1].counter_id = mlx5_fc_id(esw_ipsec_tx_chk_counter(esw));

	rule = mlx5_add_flow_rules(esw_ipsec_ft_tx_chk(esw), spec, &flow_act, dest, 2);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		esw_warn(esw->dev, "Failed to add IPsec Tx chk rule err=%d\n",  err);
		goto out_err;
	}
	esw_ipsec_ft_tx_chk_rule(esw) = rule;

	goto out;

out_err:
	esw_offloads_ipsec_tables_tx_destroy(esw);
out:
	kvfree(spec);
	kvfree(flow_group_in);
	return err;
}

int mlx5_esw_ipsec_get_refcnt(struct mlx5_eswitch *esw)
{
	if (esw && esw_ipsec_priv(esw) && !atomic_inc_unless_negative(&esw_ipsec_refcnt(esw)))
		return -EOPNOTSUPP;

	return 0;
}

void mlx5_esw_ipsec_put_refcnt(struct mlx5_eswitch *esw)
{
	if (esw && esw_ipsec_priv(esw))
		atomic_dec(&esw_ipsec_refcnt(esw));
}

struct mlx5_flow_table *mlx5_esw_ipsec_get_table(struct mlx5_eswitch *esw, enum mlx5_esw_ipsec_table_type type)
{
	switch (type) {
	case MLX5_ESW_IPSEC_FT_RX_CRYPTO:
		return esw_ipsec_ft_crypto_rx(esw);
	case MLX5_ESW_IPSEC_FT_RX_DECAP:
		return esw_ipsec_ft_decap_rx(esw);
	case MLX5_ESW_IPSEC_FT_TX_IKE:
		return esw_ipsec_ft_ike_tx(esw);
	case MLX5_ESW_IPSEC_FT_TX_CRYPTO:
		return esw_ipsec_ft_crypto_tx(esw);
	case MLX5_ESW_IPSEC_FT_TX_CHK:
		return esw_ipsec_ft_tx_chk(esw);
	default: return NULL;
	}
}

bool mlx5_esw_ipsec_try_hold(struct mlx5_eswitch *esw)
{
	if (!esw || !esw_ipsec_priv(esw))
		return true;

	return atomic_dec_unless_positive(&esw_ipsec_refcnt(esw));
}

void mlx5_esw_ipsec_release(struct mlx5_eswitch *esw)
{
	if (esw && esw_ipsec_priv(esw))
		atomic_set(&esw_ipsec_refcnt(esw), 0);
}

int mlx5_esw_ipsec_create(struct mlx5_eswitch *esw)
{
	struct mlx5_esw_ipsec_priv *ipsec_priv;
	struct mlx5_flow_namespace *ns;
	int err;

	if (!mlx5_is_ipsec_device(esw->dev))
		return 0;

	if (esw->offloads.ipsec != DEVLINK_ESWITCH_IPSEC_MODE_FULL)
		return 0;

	ipsec_priv = kzalloc(sizeof(*ipsec_priv), GFP_KERNEL);
	if (!ipsec_priv)
		return -ENOMEM;

	esw_ipsec_priv(esw) = ipsec_priv;
	ns = mlx5_get_flow_namespace(esw->dev, MLX5_FLOW_NAMESPACE_FDB);
	err = esw_offloads_ipsec_tables_rx_create(ns, esw);
	if (err) {
		esw_warn(esw->dev, "Failed to create IPsec Rx offloads FDB Tables err %d\n", err);
		goto err_rx_create;
	}

	err = esw_offloads_ipsec_tables_tx_create(ns, esw);
	if (err) {
		esw_warn(esw->dev, "Failed to create IPsec Tx offloads FDB Tables err %d\n", err);
		goto err_tx_create;
	}

	atomic_set(&esw_ipsec_refcnt(esw), 0);
	return 0;

err_tx_create:
	esw_offloads_ipsec_tables_rx_destroy(esw);
err_rx_create:
	kfree(ipsec_priv);
	esw_ipsec_priv(esw) = NULL;
	return err;
}

void mlx5_esw_ipsec_destroy(struct mlx5_eswitch *esw)
{
	if (!mlx5_is_ipsec_device(esw->dev))
		return;

	if (esw->offloads.ipsec != DEVLINK_ESWITCH_IPSEC_MODE_FULL)
		return;

	esw_offloads_ipsec_tables_tx_destroy(esw);
	esw_offloads_ipsec_tables_rx_destroy(esw);
	kfree(esw_ipsec_priv(esw));
	esw_ipsec_priv(esw) = NULL;
}

bool mlx5_esw_ipsec_is_full_initialized (struct mlx5_eswitch *esw)
{
	return esw && esw_ipsec_priv(esw);
}

void mlx5_esw_ipsec_full_offload_get_stats(struct mlx5_eswitch *esw, void *ipsec_stats)
{
	struct mlx5e_ipsec_stats *stats;

	stats = (struct mlx5e_ipsec_stats *)ipsec_stats;

	stats->ipsec_full_rx_pkts = 0;
	stats->ipsec_full_rx_bytes = 0;
	stats->ipsec_full_rx_pkts_drop = 0;
	stats->ipsec_full_rx_bytes_drop = 0;
	stats->ipsec_full_tx_pkts = 0;
	stats->ipsec_full_tx_bytes = 0;
	stats->ipsec_full_tx_pkts_drop = 0;
	stats->ipsec_full_tx_bytes_drop = 0;

	if (!esw || !esw_ipsec_priv(esw))
		return;

	if (!esw_ipsec_decap_rule_counter(esw) ||
	    !esw_ipsec_decap_miss_rule_counter(esw) ||
	    !esw_ipsec_tx_chk_drop_counter(esw) ||
	    !esw_ipsec_tx_chk_counter(esw))
		return;

	mlx5_fc_query(esw->dev, esw_ipsec_decap_rule_counter(esw),
		      &stats->ipsec_full_rx_pkts, &stats->ipsec_full_rx_bytes);

	mlx5_fc_query(esw->dev, esw_ipsec_decap_miss_rule_counter(esw),
		      &stats->ipsec_full_rx_pkts_drop, &stats->ipsec_full_rx_bytes_drop);

	mlx5_fc_query(esw->dev, esw_ipsec_tx_chk_counter(esw),
		      &stats->ipsec_full_tx_pkts, &stats->ipsec_full_tx_bytes);

	mlx5_fc_query(esw->dev, esw_ipsec_tx_chk_drop_counter(esw),
		      &stats->ipsec_full_tx_pkts_drop, &stats->ipsec_full_tx_bytes_drop);
}
