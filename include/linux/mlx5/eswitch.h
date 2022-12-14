/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
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

#ifndef _MLX5_ESWITCH_
#define _MLX5_ESWITCH_

#include <linux/mlx5/driver.h>

enum {
	SRIOV_NONE,
	SRIOV_LEGACY,
	SRIOV_OFFLOADS
};

enum {
	REP_ETH,
	REP_IB,
	NUM_REP_TYPES,
};

struct mlx5_eswitch_rep;
struct mlx5_eswitch_rep_if {
	int		       (*load)(struct mlx5_core_dev *dev,
				       struct mlx5_eswitch_rep *rep);
	void		       (*unload)(struct mlx5_eswitch_rep *rep);
	void			*ptr;
	bool		       valid;
};

struct mlx5_eswitch_rep {
	struct mlx5_eswitch_rep_if rep_if[NUM_REP_TYPES];
	u16		       vport;
	u8		       hw_id[ETH_ALEN];
};

u8 mlx5_eswitch_mode(struct mlx5_eswitch *esw);
struct mlx5_eswitch_rep *mlx5_eswitch_vport_rep(struct mlx5_eswitch *esw,
						int vport_index);
int mlx5_eswitch_register_vport_rep(struct mlx5_eswitch *esw,
				    int vport_index,
				    struct mlx5_eswitch_rep_if *rep_if,
				    u8 rep_type);
void mlx5_eswitch_unregister_vport_rep(struct mlx5_eswitch *esw,
				       int vport_index,
				       u8 rep_type);
struct mlx5_flow_handle *
mlx5_eswitch_add_send_to_vport_rule(struct mlx5_eswitch *esw,
				    int vport,
				    u32 sqn);
struct net_device *mlx5_eswitch_get_rep_netdev(struct mlx5_eswitch *esw,
					       int vport_index);
#endif
