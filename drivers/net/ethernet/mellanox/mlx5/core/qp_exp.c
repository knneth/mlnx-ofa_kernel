/*
 * Copyright (c) 2016, Mellanox Technologies. All rights reserved.
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

#include <linux/mlx5/qp.h>
#include <linux/mlx5/qp_exp.h>
#include <linux/mlx5/driver.h>
#include "mlx5_core.h"

void mlx5_init_dct_table(struct mlx5_core_dev *dev)
{
	mlx5_dct_debugfs_init(dev);
}

void mlx5_cleanup_dct_table(struct mlx5_core_dev *dev)
{
	mlx5_dct_debugfs_cleanup(dev);
}

int mlx5_core_create_dct(struct mlx5_core_dev *dev,
			 struct mlx5_core_dct *dct,
			 u32 *in)
{
	struct mlx5_qp_table *table = &dev->priv.qp_table;
	u32 out[MLX5_ST_SZ_DW(create_dct_out)]   = {0};
	u32 dout[MLX5_ST_SZ_DW(destroy_dct_out)] = {0};
	u32 din[MLX5_ST_SZ_DW(destroy_dct_in)]   = {0};
	int inlen = MLX5_ST_SZ_BYTES(create_dct_in);
	int err;

	init_completion(&dct->drained);
	MLX5_SET(create_dct_in, in, opcode, MLX5_CMD_OP_CREATE_DCT);

	err = mlx5_cmd_exec(dev, in, inlen, &out, sizeof(out));
	if (err) {
		mlx5_core_warn(dev, "create DCT failed, ret %d", err);
		return err;
	}

	dct->dctn = MLX5_GET(create_dct_out, out, dctn);

	dct->common.res = MLX5_RES_DCT;
	spin_lock_irq(&table->lock);
	err = radix_tree_insert(&table->tree, dct->dctn, dct);
	spin_unlock_irq(&table->lock);
	if (err) {
		mlx5_core_warn(dev, "err %d", err);
		goto err_cmd;
	}

	err = mlx5_debug_dct_add(dev, dct);
	if (err)
		mlx5_core_dbg(dev, "failed adding DCT 0x%x to debug file system\n",
			      dct->dctn);

	dct->pid = current->pid;
	atomic_set(&dct->common.refcount, 1);
	init_completion(&dct->common.free);

	return 0;

err_cmd:
	MLX5_SET(destroy_dct_in, din, opcode, MLX5_CMD_OP_DESTROY_DCT);
	MLX5_SET(destroy_dct_in, din, dctn, dct->dctn);
	mlx5_cmd_exec(dev, &din, sizeof(din), &out, sizeof(dout));

	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_create_dct);

static int mlx5_core_drain_dct(struct mlx5_core_dev *dev,
			       struct mlx5_core_dct *dct)
{
	u32 out[MLX5_ST_SZ_DW(drain_dct_out)] = {0};
	u32 in[MLX5_ST_SZ_DW(drain_dct_in)]   = {0};

	MLX5_SET(drain_dct_in, in, opcode, MLX5_CMD_OP_DRAIN_DCT);
	MLX5_SET(drain_dct_in, in, dctn, dct->dctn);
	return mlx5_cmd_exec(dev, (void *)&in, sizeof(in),
			     (void *)&out, sizeof(out));
}

int mlx5_core_destroy_dct(struct mlx5_core_dev *dev,
			  struct mlx5_core_dct *dct)
{
	struct mlx5_qp_table *table = &dev->priv.qp_table;
	u32 out[MLX5_ST_SZ_DW(destroy_dct_out)] = {0};
	u32 in[MLX5_ST_SZ_DW(destroy_dct_in)]   = {0};
	unsigned long flags;
	int err;

	err = mlx5_core_drain_dct(dev, dct);
	if (err) {
		if (dev->state == MLX5_DEVICE_STATE_INTERNAL_ERROR) {
			goto free_dct;
		} else {
			mlx5_core_warn(dev, "failed drain DCT 0x%x with error 0x%x\n", dct->dctn, err);
			return err;
		}
	}

	wait_for_completion(&dct->drained);

free_dct:
	mlx5_debug_dct_remove(dev, dct);

	spin_lock_irqsave(&table->lock, flags);
	if (radix_tree_delete(&table->tree, dct->dctn) != dct)
		mlx5_core_warn(dev, "dct delete differs\n");
	spin_unlock_irqrestore(&table->lock, flags);

	if (atomic_dec_and_test(&dct->common.refcount))
		complete(&dct->common.free);
	wait_for_completion(&dct->common.free);

	MLX5_SET(destroy_dct_in, in, opcode, MLX5_CMD_OP_DESTROY_DCT);
	MLX5_SET(destroy_dct_in, in, dctn, dct->dctn);
	return mlx5_cmd_exec(dev, (void *)&in, sizeof(in),
			     (void *)&out, sizeof(out));
}
EXPORT_SYMBOL_GPL(mlx5_core_destroy_dct);

int mlx5_core_dct_query(struct mlx5_core_dev *dev, struct mlx5_core_dct *dct,
			u32 *out, int outlen)
{
	u32 in[MLX5_ST_SZ_DW(query_dct_in)] = {0};

	MLX5_SET(query_dct_in, in, opcode, MLX5_CMD_OP_QUERY_DCT);
	MLX5_SET(query_dct_in, in, dctn, dct->dctn);

	return mlx5_cmd_exec(dev, (void *)&in, sizeof(in),
			     (void *)out, outlen);
}
EXPORT_SYMBOL_GPL(mlx5_core_dct_query);

int mlx5_core_arm_dct(struct mlx5_core_dev *dev, struct mlx5_core_dct *dct)
{
	u32 out[MLX5_ST_SZ_DW(arm_dct_out)] = {0};
	u32 in[MLX5_ST_SZ_DW(arm_dct_in)]   = {0};

	MLX5_SET(arm_dct_in, in, opcode, MLX5_CMD_OP_ARM_DCT_FOR_KEY_VIOLATION);
	MLX5_SET(arm_dct_in, in, dct_number, dct->dctn);
	return mlx5_cmd_exec(dev, (void *)&in, sizeof(in),
			     (void *)&out, sizeof(out));
}
EXPORT_SYMBOL_GPL(mlx5_core_arm_dct);
