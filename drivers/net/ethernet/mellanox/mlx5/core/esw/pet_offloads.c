// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2021 Mellanox Technologies
#include <linux/etherdevice.h>
#include <linux/idr.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/mlx5_ifc.h>
#include <linux/mlx5/vport.h>
#include <linux/mlx5/fs.h>
#include "mlx5_core.h"
#include <linux/mlx5/eswitch.h>
#include "esw/acl/ofld.h"
#include "accel/ipsec_offload.h"
#include "esw/ipsec.h"
#include "esw/indir_table.h"
#include "rdma.h"
#include "en.h"
#include "fs_core.h"
#include "lib/devcom.h"
#include "lib/eq.h"
#include "lib/fs_chains.h"
#include "en_tc.h"
#include "en_rep.h"

#ifdef CONFIG_MLX5_ESWITCH

bool mlx5_eswitch_pet_insert_allowed(const struct mlx5_eswitch *esw)
{
	return !!(esw->flags & MLX5_ESWITCH_PET_INSERT);
}

bool mlx5e_esw_offloads_pet_supported(const struct mlx5_eswitch *esw)
{
	if (MLX5_CAP_GEN_2(esw->dev, max_reformat_insert_size) &&
	    MLX5_CAP_GEN_2(esw->dev, non_tunnel_reformat))
		return true;

	return false;
}

bool mlx5e_esw_offloads_pet_enabled(const struct mlx5_eswitch *esw)
{
	if (!mlx5_eswitch_pet_insert_allowed(esw))
		return false;

	if (!mlx5_eswitch_vport_match_metadata_enabled(esw))
		return false;

	return true;
}

static int mlx5_pet_create_ft(struct mlx5_eswitch *esw, struct mlx5_flow_table **ft, int size)
{
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5_flow_namespace *ns;
	int err;

	ns = mlx5_get_flow_namespace(esw->dev, MLX5_FLOW_NAMESPACE_KERNEL);
	if (!ns) {
		esw_warn(esw->dev, "Failed to get FDB flow namespace\n");
		return -EOPNOTSUPP;
	}

	ft_attr.max_fte = size;
	ft_attr.prio = 1;

	*ft = mlx5_create_flow_table(ns, &ft_attr);
	if (IS_ERR(*ft)) {
		err = PTR_ERR(*ft);
		*ft = NULL;
		esw_warn(esw->dev, "Failed to create flow table - err %d\n", err);
		return err;
	}

	return 0;
}

static void mlx5_pet_destroy_ft(struct mlx5_eswitch *esw, struct mlx5_flow_table *ft)
{
	if (!ft)
		return;

	mlx5_destroy_flow_table(ft);
}

static int mlx5_pet_create_fg(struct mlx5_eswitch *esw,
			      struct mlx5_flow_table *ft,
			      struct mlx5_flow_group **fg)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	u32 *flow_group_in;
	int err = 0;

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!flow_group_in)
		return -ENOMEM;

	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, 0);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, 1);
	*fg = mlx5_create_flow_group(ft, flow_group_in);
	if (IS_ERR(*fg)) {
		err = PTR_ERR(*fg);
		mlx5_core_warn(esw->dev, "Failed to create flowgroup with err %d\n", err);
		*fg = NULL;
		goto out;
	}

out:
	kvfree(flow_group_in);
	return err;
}

static void mlx5_pet_destroy_fg(struct mlx5_eswitch *esw, struct mlx5_flow_group *fg)
{
	if (!fg)
		return;
	mlx5_destroy_flow_group(fg);
}

int mlx5_pet_push_hdr_ft(struct mlx5_eswitch *esw)
{
	int err;

	err = mlx5_pet_create_ft(esw,
				 &esw->offloads.pet_vport_action.push_pet_hdr.ft, 2);
	if (err) {
		mlx5_core_warn(esw->dev, "failed with err %d\n", err);
		return err;
	}

	return 0;
}

void mlx5_pet_push_hdr_ft_cleanup(struct mlx5_eswitch *esw)
{
	mlx5_pet_destroy_ft(esw, esw->offloads.pet_vport_action.push_pet_hdr.ft);
}

int mlx5_pet_push_hdr_rule(struct mlx5_eswitch *esw)
{
	struct mlx5_flow_table *ft = esw->offloads.pet_vport_action.push_pet_hdr.ft;
	int mlnx_ether = htons(MLX5_CAP_GEN(esw->dev, mlnx_tag_ethertype));
	struct mlx5_flow_destination dest = {};
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_handle *flow_rule;
	struct mlx5_flow_spec spec = {};
	struct mlx5_flow_group *fg;
	int reformat_type;
	char *reformat_buf;
	int buf_offset = 12;
	int buf_size = 8;
	int err;

	reformat_buf = kzalloc(buf_size, GFP_KERNEL);
	if (!reformat_buf)
		return -ENOMEM;

	err = mlx5_pet_create_fg(esw, ft, &fg);
	if (err) {
		mlx5_core_warn(esw->dev, "failed with err %d\n", err);
		goto err_create_group;
	}

	dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest.ft = esw->offloads.pet_vport_action.copy_data_to_pet_hdr.ft;

	flow_act.flags |= FLOW_ACT_IGNORE_FLOW_LEVEL;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
			  MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT;
	reformat_type = MLX5_REFORMAT_TYPE_INSERT_HDR;

	memcpy(reformat_buf, &mlnx_ether, 2);
	flow_act.pkt_reformat = mlx5_packet_reformat_alloc(esw->dev, reformat_type,
							   MLX5_REFORMAT_CONTEXT_ANCHOR_MAC_START,
							   buf_offset, buf_size, reformat_buf,
							   MLX5_FLOW_NAMESPACE_KERNEL);
	if (IS_ERR(flow_act.pkt_reformat)) {
		err = PTR_ERR(flow_act.pkt_reformat);
		mlx5_core_err(esw->dev, "packet reformat alloc err %d\n", err);
		goto err_pkt_reformat;
	}

	flow_rule = mlx5_add_flow_rules(ft, &spec, &flow_act, &dest, 1);
	if (IS_ERR(flow_rule)) {
		err = PTR_ERR(flow_rule);
		mlx5_core_err(esw->dev, "Failed to add flow rule for insert header, err %d\n", err);
		goto err_flow_rule;
	}

	esw->offloads.pet_vport_action.push_pet_hdr.fg = fg;
	esw->offloads.pet_vport_action.push_pet_hdr.rule = flow_rule;
	esw->offloads.pet_vport_action.push_pet_hdr.pkt_reformat = flow_act.pkt_reformat;
	kvfree(reformat_buf);
	return 0;

err_flow_rule:
	mlx5_packet_reformat_dealloc(esw->dev, flow_act.pkt_reformat);
err_pkt_reformat:
	mlx5_pet_destroy_fg(esw, fg);
err_create_group:
	kvfree(reformat_buf);
	return err;
}

void mlx5_pet_push_hdr_rule_cleanup(struct mlx5_eswitch *esw)
{
	struct mlx5_pet_actions pet_action = esw->offloads.pet_vport_action.push_pet_hdr;

	if (!pet_action.rule)
		return;

	mlx5_del_flow_rules(pet_action.rule);
	mlx5_packet_reformat_dealloc(esw->dev, pet_action.pkt_reformat);
	mlx5_pet_destroy_fg(esw, pet_action.fg);
}

int mlx5_pet_copy_data_ft(struct mlx5_eswitch *esw)
{
	int err;

	err = mlx5_pet_create_ft(esw, &esw->offloads.pet_vport_action.copy_data_to_pet_hdr.ft, 2);
	if (err) {
		mlx5_core_warn(esw->dev, "failed with err %d\n", err);
		return err;
	}

	return 0;
}

void mlx5_pet_copy_data_ft_cleanup(struct mlx5_eswitch *esw)
{
	mlx5_pet_destroy_ft(esw, esw->offloads.pet_vport_action.copy_data_to_pet_hdr.ft);
}

int mlx5_pet_copy_data_rule(struct mlx5_eswitch *esw, struct mlx5_flow_table *dest_ft)
{
	struct mlx5_flow_table *ft = esw->offloads.pet_vport_action.copy_data_to_pet_hdr.ft;
	u8 action[MLX5_UN_SZ_BYTES(set_add_copy_action_in_auto)] = {};
	struct mlx5_flow_destination dest = {};
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_handle *flow_rule;
	struct mlx5_modify_hdr *modify_hdr;
	struct mlx5_flow_spec spec = {};
	struct mlx5_flow_group *fg;
	int err;

	err = mlx5_pet_create_fg(esw, ft, &fg);
	if (err) {
		mlx5_core_warn(esw->dev, "failed with err %d\n", err);
		goto err_create_group;
	}

	MLX5_SET(copy_action_in, action, action_type, MLX5_ACTION_TYPE_COPY);
	MLX5_SET(copy_action_in, action, src_field, MLX5_ACTION_IN_FIELD_METADATA_REG_C_0);
	MLX5_SET(copy_action_in, action, src_offset, 16);
	MLX5_SET(copy_action_in, action, dst_field, MLX5_ACTION_IN_FIELD_OUT_EMD_47_32);
	MLX5_SET(copy_action_in, action, dst_offset, 0);
	MLX5_SET(copy_action_in, action, length, 16);

	modify_hdr = mlx5_modify_header_alloc(esw->dev, MLX5_FLOW_NAMESPACE_KERNEL,
					      1, action);
	if (IS_ERR(modify_hdr)) {
		err = PTR_ERR(modify_hdr);
		mlx5_core_warn(esw->dev, "modify header alloc failed with err %d\n", err);
		modify_hdr = NULL;
		goto header_alloc_fail;
	}

	dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest.ft = dest_ft;
	flow_act.flags |= FLOW_ACT_IGNORE_FLOW_LEVEL;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_MOD_HDR | MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	flow_act.modify_hdr = modify_hdr;

	flow_rule = mlx5_add_flow_rules(ft, &spec, &flow_act, &dest, 1);
	if (IS_ERR(flow_rule)) {
		err = PTR_ERR(flow_rule);
		mlx5_core_warn(esw->dev, "add rule failed with err %d\n", err);
		flow_rule = NULL;
		goto add_flow_rule_fail;
	}

	esw->offloads.pet_vport_action.copy_data_to_pet_hdr.fg = fg;
	esw->offloads.pet_vport_action.copy_data_to_pet_hdr.hdr = modify_hdr;
	esw->offloads.pet_vport_action.copy_data_to_pet_hdr.rule = flow_rule;

	return 0;

add_flow_rule_fail:
	mlx5_modify_header_dealloc(esw->dev, modify_hdr);
header_alloc_fail:
	mlx5_pet_destroy_fg(esw, fg);
err_create_group:
	return err;
}

void mlx5_pet_copy_data_rule_cleanup(struct mlx5_eswitch *esw)
{
	struct mlx5_pet_actions pet_action = esw->offloads.pet_vport_action.copy_data_to_pet_hdr;

	if (!pet_action.rule)
		return;

	mlx5_del_flow_rules(pet_action.rule);
	mlx5_modify_header_dealloc(esw->dev, pet_action.hdr);
	pet_action.rule = NULL;

	mlx5_pet_destroy_fg(esw, pet_action.fg);
}

/* Setup 2 flowtables - One to insert PET header. this will
 * be a 8 byte buffer with first 2 bytes containg
 * FW provided ethertype as part of it. Second flowtable
 * to copy vport id from reg_c_0 right after the FW
 * provided ethertype. All packets going thru FDB slow path
 * will be tagged with this header.
 */
int mlx5e_esw_offloads_pet_setup(struct mlx5_eswitch *esw, struct mlx5_flow_table *ft)
{
	int err;

	if (!mlx5e_esw_offloads_pet_enabled(esw))
		return 0;

	err = mlx5_pet_push_hdr_ft(esw);
	if (err)
		return err;

	err = mlx5_pet_copy_data_ft(esw);
	if (err)
		goto err_copy_data_ft;

	err = mlx5_pet_push_hdr_rule(esw);
	if (err)
		goto err_push_hdr_rule;

	err = mlx5_pet_copy_data_rule(esw, ft);
	if (err)
		goto err_copy_data_rule;

	return 0;

err_copy_data_rule:
	mlx5_pet_push_hdr_rule_cleanup(esw);
err_push_hdr_rule:
	mlx5_pet_copy_data_ft_cleanup(esw);
err_copy_data_ft:
	mlx5_pet_push_hdr_ft_cleanup(esw);
	return err;
}

void mlx5e_esw_offloads_pet_cleanup(struct mlx5_eswitch *esw)
{
	if (!mlx5e_esw_offloads_pet_enabled(esw))
		return;

	mlx5_pet_copy_data_rule_cleanup(esw);
	mlx5_pet_push_hdr_rule_cleanup(esw);

	mlx5_pet_copy_data_ft_cleanup(esw);
	mlx5_pet_push_hdr_ft_cleanup(esw);
}

int mlx5_esw_offloads_pet_insert_set(struct mlx5_eswitch *esw, bool enable)
{
	int err = 0;

	mutex_lock(&esw->mode_lock);
	if (esw->mode >= MLX5_ESWITCH_OFFLOADS) {
		err = -EOPNOTSUPP;
		goto done;
	}
	if (!mlx5e_esw_offloads_pet_supported(esw)) {
		err = -EOPNOTSUPP;
		goto done;
	}
	if (enable)
		esw->flags |= MLX5_ESWITCH_PET_INSERT;
	else
		esw->flags &= ~MLX5_ESWITCH_PET_INSERT;

done:
	mutex_unlock(&esw->mode_lock);
	return err;
}
#endif /* CONFIG_MLX5_ESWITCH */
