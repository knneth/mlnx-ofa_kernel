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
#ifndef __MLX5_EN_TRUST_H__
#define __MLX5_EN_TRUST_H__
#include "en.h"

#define MLX5_DSCP_SUPPORTED(mdev) (MLX5_CAP_GEN(mdev, qcam_reg)  && \
				   MLX5_CAP_QCAM_REG(mdev, qpts) && \
				   MLX5_CAP_QCAM_REG(mdev, qpdpm))

int mlx5e_trust_initialize(struct mlx5e_priv *priv);
int mlx5e_set_trust_state(struct mlx5e_priv *priv, u8 trust_state);
int mlx5e_set_dscp2prio(struct mlx5e_priv *priv, u8 dscp, u8 prio);
u8 mlx5e_trust_get_txsq_inline_mode(struct mlx5e_priv *priv);

#endif
