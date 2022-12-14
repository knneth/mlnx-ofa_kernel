/*
 * Copyright (c) 2017, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __MLX5_IB_REP_H__
#define __MLX5_IB_REP_H__

#include <linux/mlx5/eswitch.h>
#include "mlx5_ib.h"

#ifdef CONFIG_MLX5_ESWITCH
u8 mlx5_ib_eswitch_mode(struct mlx5_eswitch *esw);
struct mlx5_eswitch_rep *mlx5_ib_vport_rep(struct mlx5_eswitch *esw,
					   int vport_index);
void mlx5_ib_register_vport_reps(struct mlx5_ib_dev *dev);
void mlx5_ib_unregister_vport_reps(struct mlx5_ib_dev *dev);
int create_flow_rule_vport_sq(struct mlx5_ib_dev *dev,
			      struct mlx5_ib_sq *sq);
struct net_device *mlx5_ib_get_rep_netdev(struct mlx5_eswitch *esw,
					  int vport_index);
#else /* CONFIG_MLX5_ESWITCH */
static inline u8 mlx5_ib_eswitch_mode(struct mlx5_eswitch *esw) { return SRIOV_NONE; }
static inline
struct mlx5_eswitch_rep *mlx5_ib_vport_rep(struct mlx5_eswitch *esw,
					   int vport_index) { return NULL; }
static inline void mlx5_ib_register_vport_reps(struct mlx5_ib_dev *dev) {}
static inline void mlx5_ib_unregister_vport_reps(struct mlx5_ib_dev *dev) {}
static inline int create_flow_rule_vport_sq(struct mlx5_ib_dev *dev,
					    struct mlx5_ib_sq *sq) { return 0; }
static inline struct net_device *mlx5_ib_get_rep_netdev(struct mlx5_eswitch *esw,
							int vport_index) { return NULL; }
#endif

static inline
struct mlx5_ib_dev *mlx5_ib_rep_to_dev(struct mlx5_eswitch_rep *rep)
{
	return (struct mlx5_ib_dev *)rep->rep_if[REP_IB].ptr;
}
#endif /* __MLX5_IB_REP_H__ */
