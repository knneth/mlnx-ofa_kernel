// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2020 Mellanox Technologies Ltd */

#include <linux/mlx5/driver.h>
#include "priv.h"

/* Follow backport should be moved to backports in next rebase
   as a result of CONFIG_MLX5_SF_MANAGER is set we need to block it
   to allow compilation without backports on base kernel 5.9
   */
int mlx5_cmd_alloc_sf(struct mlx5_core_dev *dev, u16 function_id)
{
	u32 out[MLX5_ST_SZ_DW(alloc_sf_out)] = {};
	u32 in[MLX5_ST_SZ_DW(alloc_sf_in)] = {};

	MLX5_SET(alloc_sf_in, in, opcode, MLX5_CMD_OP_ALLOC_SF);
	MLX5_SET(alloc_sf_in, in, function_id, function_id);

	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
}

int mlx5_cmd_dealloc_sf(struct mlx5_core_dev *dev, u16 function_id)
{
	u32 out[MLX5_ST_SZ_DW(dealloc_sf_out)] = {};
	u32 in[MLX5_ST_SZ_DW(dealloc_sf_in)] = {};

	MLX5_SET(dealloc_sf_in, in, opcode, MLX5_CMD_OP_DEALLOC_SF);
	MLX5_SET(dealloc_sf_in, in, function_id, function_id);

	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
}

int mlx5_cmd_sf_enable_hca(struct mlx5_core_dev *dev, u16 func_id)
{
	u32 out[MLX5_ST_SZ_DW(enable_hca_out)] = {};
	u32 in[MLX5_ST_SZ_DW(enable_hca_in)] = {};

	MLX5_SET(enable_hca_in, in, opcode, MLX5_CMD_OP_ENABLE_HCA);
	MLX5_SET(enable_hca_in, in, function_id, func_id);
	MLX5_SET(enable_hca_in, in, embedded_cpu_function, 0);
	return mlx5_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
}

int mlx5_cmd_sf_disable_hca(struct mlx5_core_dev *dev, u16 func_id)
{
	u32 out[MLX5_ST_SZ_DW(disable_hca_out)] = {};
	u32 in[MLX5_ST_SZ_DW(disable_hca_in)] = {};

	MLX5_SET(disable_hca_in, in, opcode, MLX5_CMD_OP_DISABLE_HCA);
	MLX5_SET(disable_hca_in, in, function_id, func_id);
	MLX5_SET(enable_hca_in, in, embedded_cpu_function, 0);
	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
}
