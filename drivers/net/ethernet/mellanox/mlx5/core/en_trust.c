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
#include "en_trust.h"

static void mlx5e_trust_update_txsq_inline_mode(struct mlx5e_priv *priv)
{
	struct mlx5e_channels new_channels = {};

	mutex_lock(&priv->state_lock);

	new_channels.params = priv->channels.params;
	if (mlx5e_open_channels(priv, &new_channels))
		goto out;
	mlx5e_switch_priv_channels(priv, &new_channels, NULL);

out:
	mutex_unlock(&priv->state_lock);
}

int mlx5e_set_trust_state(struct mlx5e_priv *priv, u8 trust_state)
{
	int err;

	err =  mlx5_set_trust_state(priv->mdev, trust_state);
	if (err)
		return err;
	priv->trust_state = trust_state;
	mlx5e_trust_update_txsq_inline_mode(priv);

	return err;
}

int mlx5e_set_dscp2prio(struct mlx5e_priv *priv, u8 dscp, u8 prio)
{
	int err;

	err = mlx5_set_dscp2prio(priv->mdev, dscp, prio);
	if (err)
		return err;

	priv->dscp2prio[dscp] = prio;
	return err;
}

int mlx5e_trust_initialize(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	int err;

	if (!MLX5_DSCP_SUPPORTED(mdev))
		return 0;

	err = mlx5_query_trust_state(priv->mdev, &priv->trust_state);
	if (err)
		return err;

	err = mlx5_query_dscp2prio(priv->mdev, priv->dscp2prio);
	if (err)
		return err;

	return 0;
}

u8 mlx5e_trust_get_txsq_inline_mode(struct mlx5e_priv *priv)
{
	struct mlx5e_params *params = &priv->channels.params;

	if ((priv->trust_state == MLX5_QPTS_TRUST_DSCP) &&
	    (params->tx_min_inline_mode == MLX5_INLINE_MODE_L2))
		return MLX5_INLINE_MODE_IP;
	else
		return params->tx_min_inline_mode;
}
