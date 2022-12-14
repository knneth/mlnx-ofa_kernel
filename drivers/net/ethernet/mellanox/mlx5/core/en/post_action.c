// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include "en_tc.h"
#include "lib/fs_chains.h"
#include "post_action.h"
#include "mlx5_core.h"

struct mlx5_post_action {
	enum mlx5_flow_namespace_type ns_type;
	struct mlx5_fs_chains *chains;
	struct mlx5_flow_table *ft;
	struct mlx5e_priv *priv;
	struct xarray ids;
};

struct mlx5_post_action_handle {
	enum mlx5_flow_namespace_type ns_type;
	struct mlx5_flow_attr *attr;
	struct mlx5_flow_handle *rule;
	u32 id;
};

#define MLX5_POST_ACTION_BITS (mlx5e_tc_attr_to_reg_mappings[FTEID_TO_REG].mlen * 8)
#define MLX5_POST_ACTION_MAX GENMASK(MLX5_POST_ACTION_BITS - 1, 0)
#define MLX5_POST_ACTION_MASK MLX5_POST_ACTION_MAX

struct mlx5_post_action *
mlx5_post_action_init(struct mlx5_fs_chains *chains, struct mlx5_core_dev *dev,
		      enum mlx5_flow_namespace_type ns_type)
{
	struct mlx5_post_action *post_action;
	int err;

	if (ns_type == MLX5_FLOW_NAMESPACE_FDB &&
	    !MLX5_CAP_ESW_FLOWTABLE_FDB(dev, ignore_flow_level)) {
		mlx5_core_warn(dev, "firmware level support is missing\n");
		err = -EOPNOTSUPP;
		goto err_check;
	} else if (!MLX5_CAP_FLOWTABLE_NIC_RX(dev, ignore_flow_level)) {
		mlx5_core_warn(dev, "firmware level support is missing\n");
		err = -EOPNOTSUPP;
		goto err_check;
	}

	post_action = kzalloc(sizeof(*post_action), GFP_KERNEL);
	if (!post_action) {
		err = -ENOMEM;
		goto err_check;
	}
	post_action->ft = mlx5_chains_create_global_table(chains);
	if (IS_ERR(post_action->ft)) {
		err = PTR_ERR(post_action->ft);
		mlx5_core_warn(dev, "failed to create post action table, err: %d\n", err);
		goto err_ft;
	}
	post_action->chains = chains;
	post_action->ns_type = ns_type;
	xa_init_flags(&post_action->ids, XA_FLAGS_ALLOC1);
	return post_action;

err_ft:
	kfree(post_action);
err_check:
	return ERR_PTR(err);
}

void
mlx5_post_action_destroy(struct mlx5_post_action *post_action)
{
	if (IS_ERR_OR_NULL(post_action))
		return;

	xa_destroy(&post_action->ids);
	mlx5_chains_destroy_global_table(post_action->chains, post_action->ft);
	kfree(post_action);
}

struct mlx5_post_action_handle *
mlx5_post_action_add(struct mlx5e_priv *priv, struct mlx5_post_action *post_action,
		     struct mlx5_flow_attr *attr)
{
	u32 attr_sz = ns_to_attr_sz(post_action->ns_type);
	struct mlx5_post_action_handle *handle = NULL;
	struct mlx5_flow_attr *post_attr = NULL;
	struct mlx5_flow_spec *spec = NULL;
	int err;

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	post_attr = mlx5_alloc_flow_attr(post_action->ns_type);
	if (!handle || !spec || !post_attr) {
		kfree(post_attr);
		kvfree(spec);
		kfree(handle);
		return ERR_PTR(-ENOMEM);
	}

	memcpy(post_attr, attr, attr_sz);
	post_attr->chain = 0;
	post_attr->prio = 0;
	post_attr->ft = post_action->ft;
	post_attr->inner_match_level = MLX5_MATCH_NONE;
	post_attr->outer_match_level = MLX5_MATCH_NONE;
	post_attr->action &= ~(MLX5_FLOW_CONTEXT_ACTION_DECAP);

	handle->ns_type = post_action->ns_type;
	/* Splits were handled before post action */
	if (handle->ns_type == MLX5_FLOW_NAMESPACE_FDB)
		post_attr->esw_attr->split_count = 0;

	err = xa_alloc(&post_action->ids, &handle->id, post_attr,
		       XA_LIMIT(1, MLX5_POST_ACTION_MAX), GFP_KERNEL);
	if (err)
		goto err_xarray;

	/* Post action rule matches on fte_id and executes original rule's
	 * tc rule action
	 */
	mlx5e_tc_match_to_reg_match(spec, FTEID_TO_REG,
				    handle->id, MLX5_POST_ACTION_MASK);

	handle->rule = mlx5_tc_rule_insert(priv, spec, post_attr);
	if (IS_ERR(handle->rule)) {
		err = PTR_ERR(handle->rule);
		netdev_warn(priv->netdev, "Failed to add post action rule");
		goto err_rule;
	}
	handle->attr = post_attr;

	kvfree(spec);
	return handle;

err_rule:
	xa_erase(&post_action->ids, handle->id);
err_xarray:
	kfree(post_attr);
	kvfree(spec);
	kfree(handle);
	return ERR_PTR(err);
}

void
mlx5_post_action_del(struct mlx5e_priv *priv, struct mlx5_post_action *post_action,
		     struct mlx5_post_action_handle *handle)
{
	mlx5_tc_rule_delete(priv, handle->rule, handle->attr);

	if (handle->attr->action & MLX5_FLOW_CONTEXT_ACTION_EXECUTE_ASO) {
		mlx5_modify_header_dealloc(priv->mdev, handle->attr->modify_hdr);
		mlx5e_put_flow_meter(priv->mdev, handle->attr->meter_attr.meters[0].handle);
	}

	xa_erase(&post_action->ids, handle->id);
	kfree(handle->attr);
	kfree(handle);
}

struct mlx5_flow_table *
mlx5_post_action_get_ft(struct mlx5_post_action *post_action)
{
	return post_action->ft;
}

/* Allocate a header modify action to write the post action handle fte id to a register. */
int
mlx5_post_action_set_handle(struct mlx5_core_dev *dev,
			    struct mlx5_post_action_handle *handle,
			    struct mlx5e_tc_mod_hdr_acts *acts)
{
	return mlx5e_tc_match_to_reg_set(dev, acts, handle->ns_type, FTEID_TO_REG, handle->id);
}
