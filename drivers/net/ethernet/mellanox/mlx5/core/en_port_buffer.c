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
#include "en_port_buffer.h"

#define MLX5E_MAX_PORT_MTU  9216

int mlx5_query_buffer_configuration(struct net_device *dev,
				    struct mlx5e_port_buffer *port_buffer)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;
	int sz = MLX5_ST_SZ_BYTES(pbmc_reg);
	u32 total_used = 0;
	void *buffer_reg;
	void *out;
	int err;
	int i;

	out = kzalloc(sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	err = mlx5_query_port_pbmc(mdev, out);
	if (err)
		goto out;

	for (i = 0; i < MLX5E_MAX_BUFFER; i++) {
		buffer_reg = MLX5_ADDR_OF(pbmc_reg, out, buff[i]);
		port_buffer->buffer[i].lossy =
			MLX5_GET(buffer_reg, buffer_reg, lossy);
		port_buffer->buffer[i].epsb =
			MLX5_GET(buffer_reg, buffer_reg, epsb);
		port_buffer->buffer[i].size =
			MLX5_GET(buffer_reg, buffer_reg, size) << MLX5E_BUFFER_CELL_SHIFT;
		port_buffer->buffer[i].xon =
			MLX5_GET(buffer_reg, buffer_reg, xon_threshold) << MLX5E_BUFFER_CELL_SHIFT;
		port_buffer->buffer[i].xoff =
			MLX5_GET(buffer_reg, buffer_reg, xoff_threshold) << MLX5E_BUFFER_CELL_SHIFT;

		total_used += port_buffer->buffer[i].size;
	}

	port_buffer->port_buffer_size =
		MLX5_GET(pbmc_reg, out, port_buffer_size) << MLX5E_BUFFER_CELL_SHIFT;
	port_buffer->spare_buffer_size =
		port_buffer->port_buffer_size - total_used;

out:
	kfree(out);
	return err;
}

static int mlx5_set_buffer_configuration(struct net_device *dev,
					 struct mlx5e_port_buffer *port_buffer)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;
	int sz = MLX5_ST_SZ_BYTES(pbmc_reg);
	void *buff;
	void *in;
	int err;
	int i;

	in = kzalloc(sz, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	err = mlx5_query_port_pbmc(mdev, in);
	if (err)
		goto out;

	for (i = 0; i < MLX5E_MAX_BUFFER; i++) {
		buff = MLX5_ADDR_OF(pbmc_reg, in, buff[i]);

		MLX5_SET(buffer_reg, buff, size,
			 port_buffer->buffer[i].size >> MLX5E_BUFFER_CELL_SHIFT);
		MLX5_SET(buffer_reg, buff, lossy,
			 port_buffer->buffer[i].lossy);
		MLX5_SET(buffer_reg, buff, xoff_threshold,
			 port_buffer->buffer[i].xoff >> MLX5E_BUFFER_CELL_SHIFT);
		MLX5_SET(buffer_reg, buff, xon_threshold,
			 port_buffer->buffer[i].xon >> MLX5E_BUFFER_CELL_SHIFT);
	}

	err = mlx5_set_port_pbmc(mdev, in);
out:
	kfree(in);
	return err;
}

static int mlx5_num_pfc_prio(struct ieee_pfc *pfc)
{
	u8 tmp = pfc->pfc_en;
	int count = 0;
	u8 i;

	for (i = 0; i < 8; i++) {
		count += tmp & 0x1;
		tmp = tmp >> 1;
	}

	return count;
}

/* xoff = ((301+2.16 * len [m]) * speed [Gbps] + 2.72 MTU [B]) */
static u32 mlx5_calculate_xoff(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	u32 speed;
	u32 xoff;
	int err;

	err = mlx5e_get_port_speed(priv, &speed);
	if (err)
		speed = SPEED_40000;
	speed = max_t(u32, speed, SPEED_40000);

	xoff = (301 + 216 * priv->dcbx.cable_len / 100) * speed / 1000 + 272 * dev->mtu / 100;

	mlx5e_dbg(HW, priv, "%s: xoff=%d\n", __func__, xoff);

	return xoff;
}

/* Two equal buffers.
 * Buffer 0/1 is for lossy/lossless priority respectively
 */
static void mlx5_default_buffer(struct net_device *dev,
				struct mlx5e_port_buffer *port_buffer,
				u8 *buffer,
				struct ieee_pfc *pfc)
{
	int i;

	for (i = 2; i < MLX5E_MAX_BUFFER; i++) {
		port_buffer->buffer[i].size  = 0;
		port_buffer->buffer[i].lossy = 1;
		port_buffer->buffer[i].xon   = 0;
		port_buffer->buffer[i].xoff  = 0;
	}

	port_buffer->buffer[0].size  = port_buffer->port_buffer_size / 2;
	port_buffer->buffer[0].lossy = 1;
	port_buffer->buffer[0].xoff  = 0;
	port_buffer->buffer[0].xon   = 0;

	port_buffer->buffer[1].size  = port_buffer->port_buffer_size / 2;
	port_buffer->buffer[1].lossy = 0;
	port_buffer->buffer[1].xoff  = port_buffer->port_buffer_size / 4;
	port_buffer->buffer[1].xon   =
		port_buffer->buffer[1].xoff - MLX5E_MAX_PORT_MTU;

	for (i = 0; i < MLX5E_MAX_PRIORITY; i++)
		buffer[i] = (pfc->pfc_en & (1 << i)) ? 1 : 0;
}

/* IFB = 8 * MTU
 * xoff = ((301+2.16 * len [m]) * speed [Gbps] + 2.72 MTU [B])
 *
 * N = Maximum num_lossless_buffer = (port_buffer_size – IFB) / (xoff + IFB)
 * n = Number of lossless buffer = min (N, num_lossless_prio)
 *
 * spare = (port_buffer_size – n * (xoff + IFB)) / (n + 1)
 *
 * lossless_buf_size = xoff + IFB + spare
 * lossy_buf_size = IFB + spare
 * xoff_threshold = lossless_buf_size - xoff
 * xon_threshold = xoff_threshold - MLX5E_MAX_PORT_MTU
 *
 * set buffer n as lossy
 * set buffers [0,n-1] as lossless
 *
 * Distribute lossless prios to lossless buffers
 *   If there are 5 lossless buffers [0,4] and 7 lossy priorities [0,6], the distribution is:
 *     Prio --> Buffer
 *     0    --> 4
 *     1    --> 3
 *     2    --> 2
 *     3,4  --> 1
 *     5,6  --> 0
 */

int mlx5_auto_buffer_configuration(struct net_device *dev, struct ieee_pfc *pfc, bool change)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int num_pfc_prio = mlx5_num_pfc_prio(pfc);
	struct mlx5e_port_buffer port_buffer;
	u8 buffer[MLX5E_MAX_PRIORITY];
	u32 xoff = mlx5_calculate_xoff(dev);
	u32 ifb_size = 8 * dev->mtu;
	u32 lossless_buffer_size;
	u32 lossy_buffer_size;
	u32 xoff_threshold;
	u32 xon_threshold;
	u32 spare;
	u8 remainder;
	u8 ratio;
	u8 cur;
	int max_buffers;
	int buf_index;
	int prio;
	int err;
	int n;
	int i;

	/* Verify input */
	if (!change && xoff == priv->dcbx.xoff)
		return 0;
	priv->dcbx.xoff = xoff;

	/* Initialize the settings */
	err = mlx5_query_buffer_configuration(dev, &port_buffer);
	if (err)
		return err;

	mlx5_default_buffer(dev, &port_buffer, buffer, pfc);

	if (!num_pfc_prio)
		goto set_setting;

	/* Find number of lossless n */
	if (num_pfc_prio == MLX5E_MAX_PRIORITY)
		max_buffers = port_buffer.port_buffer_size / (xoff + ifb_size);
	else
		max_buffers = (port_buffer.port_buffer_size - ifb_size) / (xoff + ifb_size);

	if (max_buffers < 1)
		goto set_setting;
	n = min_t(int, num_pfc_prio, max_buffers);

	/* Calculate buffer configuration */
	if (num_pfc_prio == MLX5E_MAX_PRIORITY) {
		spare = (port_buffer.port_buffer_size - n * (xoff + ifb_size)) / n;
		lossy_buffer_size = 0;
	} else {
		spare = (port_buffer.port_buffer_size - n * (xoff + ifb_size) - ifb_size) / (n + 1);
		lossy_buffer_size = ifb_size + spare;
	}

	lossless_buffer_size = xoff + ifb_size + spare;
	xoff_threshold = lossless_buffer_size - xoff;
	xon_threshold = xoff_threshold - MLX5E_MAX_PORT_MTU;
	if (xon_threshold < (1 << MLX5E_BUFFER_CELL_SHIFT))
		goto set_setting;

	/* Lossless buffers */
	for (i = 0; i < n; i++) {
		port_buffer.buffer[i].size  = lossless_buffer_size;
		port_buffer.buffer[i].lossy = 0;
		port_buffer.buffer[i].xon   = xon_threshold;
		port_buffer.buffer[i].xoff  = xoff_threshold;
	}

	/* Lossy buffer */
	if (lossy_buffer_size) {
		port_buffer.buffer[n].size  = lossy_buffer_size;
		port_buffer.buffer[n].lossy = 1;
		port_buffer.buffer[n].xon   = 0;
		port_buffer.buffer[n].xoff  = 0;
	}

	/* Distribute lossless prio to lossless buffer */
	buf_index = -1;
	ratio = num_pfc_prio / n;
	remainder = num_pfc_prio % n;
	cur = 0;
	for (prio = (MLX5E_MAX_PRIORITY - 1); prio >= 0; prio--) {
		if (pfc->pfc_en & (1 << prio)) {
			if (!cur) {
				buf_index++;
				if (remainder) {
					remainder--;
					cur = ratio + 1;
				} else {
					cur = ratio;
				}
			}

			buffer[prio] = buf_index;
			cur--;
		} else {
			buffer[prio] = n;
		}
	}

	/* Apply the settings */
set_setting:
	err = mlx5_set_buffer_configuration(dev, &port_buffer);
	if (err)
		return err;

	err = mlx5_set_port_priority2buffer(priv->mdev, buffer);

	return err;
}

static int mlx5e_update_xoff_threshold(struct mlx5e_port_buffer *port_buffer,
				       u32 xoff)
{
	int i;

	for (i = 0; i < MLX5E_MAX_BUFFER; i++) {
		if (port_buffer->buffer[i].lossy) {
			port_buffer->buffer[i].xoff = 0;
			port_buffer->buffer[i].xon  = 0;
			continue;
		}

		if (port_buffer->buffer[i].size <
		    (xoff + MLX5E_MAX_PORT_MTU +
		     (1 << MLX5E_BUFFER_CELL_SHIFT)))
			return -ENOMEM;

		port_buffer->buffer[i].xoff = port_buffer->buffer[i].size - xoff;
		port_buffer->buffer[i].xon  =
			port_buffer->buffer[i].xoff - MLX5E_MAX_PORT_MTU;
	}

	return 0;
}

/* change buffer to:
 *   lossless if there is at least one PFC enabled priority mapped to this buffer
 *   lossy if all priorities mapped to this buffer are PFC disabled
 */
static int mlx5_update_buffer_lossy(struct net_device *dev, u8 pfc_en, u8 *buffer, u32 xoff,
				    struct mlx5e_port_buffer *port_buffer, bool *change)
{
	bool changed = false;
	u8 lossy_count;
	u8 prio_count;
	u8 lossy;
	int prio;
	int err;
	int i;

	for (i = 0; i < MLX5E_MAX_BUFFER; i++) {
		prio_count = 0;
		lossy_count = 0;

		for (prio = 0; prio < MLX5E_MAX_PRIORITY; prio++) {
			if (buffer[prio] != i)
				continue;

			prio_count++;
			lossy_count += !(pfc_en & (1 << prio));
		}

		if (lossy_count == prio_count)
			lossy = 1;
		else /* lossy_count < prio_count */
			lossy = 0;

		if (lossy != port_buffer->buffer[i].lossy) {
			port_buffer->buffer[i].lossy = lossy;
			changed = true;
		}
	}

	if (changed) {
		err = mlx5e_update_xoff_threshold(port_buffer, xoff);
		if (err)
			return err;

		*change = true;
	}

	return 0;
}

int mlx5e_manual_buffer_configuration(struct net_device *dev, u32 change,
				      struct ieee_pfc *pfc,
				      u32 *buffer_size,
				      u8 *prio2buffer)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_port_buffer port_buffer;
	u32 xoff = mlx5_calculate_xoff(dev);
	u32 total_used = 0;
	bool update_prio2buffer = false;
	bool update_buffer = false;
	u8 buffer[MLX5E_MAX_PRIORITY];
	u8 curr_pfc_en;
	int err;
	int i;

	mlx5e_dbg(HW, priv, "%s: change=%x\n", __func__, change);

	priv->dcbx.manual_buffer = true;

	err = mlx5_query_buffer_configuration(dev, &port_buffer);
	if (err)
		return err;

	if (change & MLX5E_BUFFER_CABLE_LEN) {
		update_buffer = true;
		err = mlx5e_update_xoff_threshold(&port_buffer, xoff);
		if (err)
			return err;
	}

	if (change & MLX5E_BUFFER_PFC) {
		err = mlx5_query_port_priority2buffer(priv->mdev, buffer);
		if (err)
			return err;

		err = mlx5_update_buffer_lossy(dev, pfc->pfc_en, buffer, xoff,
					       &port_buffer, &update_buffer);
		if (err)
			return err;
	}

	if (change & MLX5E_BUFFER_PRIO2BUFFER) {
		update_prio2buffer = true;
		err = mlx5_query_port_pfc(priv->mdev, &curr_pfc_en, NULL);
		if (err)
			return err;

		err = mlx5_update_buffer_lossy(dev, curr_pfc_en, prio2buffer, xoff,
					       &port_buffer, &update_buffer);
		if (err)
			return err;
	}

	if (change & MLX5E_BUFFER_SIZE) {
		for (i = 0; i < MLX5E_MAX_BUFFER; i++) {
			mlx5e_dbg(HW, priv, "%s: buffer[%d]=%d\n", __func__, i, buffer_size[i]);
			if (!port_buffer.buffer[i].lossy && !buffer_size[i]) {
				mlx5e_dbg(HW, priv, "%s: lossless buffer[%d] size cannot be zero\n",
					  __func__, i);
				return -EINVAL;
			}

			port_buffer.buffer[i].size = buffer_size[i];
			total_used += buffer_size[i];
		}

		mlx5e_dbg(HW, priv, "%s: total buffer requested=%d\n", __func__, total_used);

		if (total_used > port_buffer.port_buffer_size)
			return -EINVAL;

		update_buffer = true;
		err = mlx5e_update_xoff_threshold(&port_buffer, xoff);
		if (err)
			return err;
	}

	if (!update_buffer && xoff == priv->dcbx.xoff) {
		update_buffer = true;
		err = mlx5e_update_xoff_threshold(&port_buffer, xoff);
		if (err)
			return err;
	}
	priv->dcbx.xoff = xoff;

	/* Apply the settings */
	if (update_buffer) {
		err = mlx5_set_buffer_configuration(dev, &port_buffer);
		if (err)
			return err;
	}

	if (update_prio2buffer) {
		err = mlx5_set_port_priority2buffer(priv->mdev, prio2buffer);
		if (err)
			return err;
	}

	return 0;
}
