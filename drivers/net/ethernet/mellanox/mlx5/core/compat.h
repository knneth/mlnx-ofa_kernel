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

#endif /* CONFIG_MLX5_ESWITCH */

#endif /* __MLX5_COMPAT__ */
