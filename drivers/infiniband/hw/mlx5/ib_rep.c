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

#include "ib_rep.h"

static int
mlx5_ib_nic_rep_load(struct mlx5_core_dev *dev, struct mlx5_eswitch_rep *rep)
{
	return 0;
}

static void
mlx5_ib_nic_rep_unload(struct mlx5_eswitch_rep *rep)
{
	rep->rep_if[REP_IB].ptr = NULL;
}

static int
mlx5_ib_vport_rep_load(struct mlx5_core_dev *dev, struct mlx5_eswitch_rep *rep)
{
	struct mlx5_ib_dev *ibdev;

	ibdev = (struct mlx5_ib_dev *)ib_alloc_device(sizeof(*ibdev));
	if (!ibdev)
		return -ENOMEM;

	ibdev->rep = rep;
	if (!__mlx5_ib_add(dev, ibdev, true))
		return -EINVAL;

	rep->rep_if[REP_IB].ptr = ibdev;

	return 0;
}

static void
mlx5_ib_vport_rep_unload(struct mlx5_eswitch_rep *rep)
{
	struct mlx5_ib_dev *dev;

	if (!rep->rep_if[REP_IB].ptr)
		return;

	dev = mlx5_ib_rep_to_dev(rep);
	__mlx5_ib_remove(dev->mdev, rep->rep_if[REP_IB].ptr, true);
	rep->rep_if[REP_IB].ptr = NULL;
}

static void mlx5_ib_rep_register_vf_vports(struct mlx5_ib_dev *dev)
{
	struct mlx5_core_dev *mdev = dev->mdev;
	struct mlx5_eswitch *esw   = mdev->priv.eswitch;
	int total_vfs = MLX5_TOTAL_VPORTS(mdev);
	int vport;

	for (vport = 1; vport < total_vfs; vport++) {
		struct mlx5_eswitch_rep_if rep_if = {};

		rep_if.load = mlx5_ib_vport_rep_load;
		rep_if.unload = mlx5_ib_vport_rep_unload;
		mlx5_eswitch_register_vport_rep(esw, vport, &rep_if, REP_IB);
	}
}

static void mlx5_ib_rep_unregister_vf_vports(struct mlx5_ib_dev *dev)
{
	struct mlx5_core_dev *mdev = dev->mdev;
	struct mlx5_eswitch *esw = mdev->priv.eswitch;
	int total_vfs = MLX5_TOTAL_VPORTS(mdev);
	int vport;

	for (vport = 1; vport < total_vfs; vport++)
		mlx5_eswitch_unregister_vport_rep(esw, vport, REP_IB);
}

void mlx5_ib_register_vport_reps(struct mlx5_ib_dev *dev)
{
	struct mlx5_core_dev *mdev = dev->mdev;
	struct mlx5_eswitch *esw = mdev->priv.eswitch;
	struct mlx5_eswitch_rep_if rep_if;

	rep_if.load = mlx5_ib_nic_rep_load;
	rep_if.unload = mlx5_ib_nic_rep_unload;
	rep_if.ptr = dev;

	mlx5_eswitch_register_vport_rep(esw, 0, &rep_if, REP_IB);

	mlx5_ib_rep_register_vf_vports(dev);
}

void mlx5_ib_unregister_vport_reps(struct mlx5_ib_dev *dev)
{
	struct mlx5_core_dev *mdev = dev->mdev;
	struct mlx5_eswitch *esw   = mdev->priv.eswitch;

	mlx5_ib_rep_unregister_vf_vports(dev); /* VFs vports */
	mlx5_eswitch_unregister_vport_rep(esw, 0, REP_IB); /* UPLINK PF*/
}

u8 mlx5_ib_eswitch_mode(struct mlx5_eswitch *esw)
{
	return mlx5_eswitch_mode(esw);
}

struct mlx5_eswitch_rep *mlx5_ib_vport_rep(struct mlx5_eswitch *esw,
					   int vport_index)
{
	return mlx5_eswitch_vport_rep(esw, vport_index);
}

int create_flow_rule_vport_sq(struct mlx5_ib_dev *dev,
			      struct mlx5_ib_sq *sq)
{
	struct mlx5_flow_handle *flow_rule;
	struct mlx5_eswitch *esw = dev->mdev->priv.eswitch;

	if (dev->rep) {
		flow_rule =
			mlx5_eswitch_add_send_to_vport_rule(esw,
							    dev->rep->vport,
							    sq->base.mqp.qpn);
		if (IS_ERR(flow_rule))
			return PTR_ERR(flow_rule);
		sq->flow_rule = flow_rule;
	}
	return 0;
}

struct net_device *mlx5_ib_get_rep_netdev(struct mlx5_eswitch *esw,
					  int vport_index)
{
	return mlx5_eswitch_get_rep_netdev(esw, vport_index);
}
