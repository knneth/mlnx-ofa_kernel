/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2020 Mellanox Technologies */

#ifndef __MLX5_COMPAT__
#define __MLX5_COMPAT__

#ifdef CONFIG_MLX5_ESWITCH
bool
mlx5e_tc_act_reorder_flow_actions(struct flow_action **flow_action_reorder,
				  struct flow_action **flow_action_before);
bool
mlx5e_tc_act_verify_actions(struct flow_action *flow_action);

#if defined(HAVE_SWITCHDEV_OPS)
int mlx5e_attr_get(struct net_device *dev, struct switchdev_attr *attr);
#endif
#if IS_ENABLED(CONFIG_MLX5_CLS_ACT) && defined(HAVE_TC_SETUP_CB_EGDEV_REGISTER)
int mlx5e_vport_rep_load_compat(struct mlx5e_priv *priv);
void mlx5e_vport_rep_unload_compat(struct mlx5e_priv *priv);
#endif
#endif /* CONFIG_MLX5_ESWITCH */

#endif /* __MLX5_COMPAT__ */
