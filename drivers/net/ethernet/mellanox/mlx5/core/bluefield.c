/*
 * Copyright (c) 2013-2015, Mellanox Technologies, Ltd.  All rights reserved.
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

#include <linux/module.h>
#include <linux/mlx5/driver.h>
#include "mlx5_core.h"

int mlx5_query_ec_params(struct mlx5_core_dev *dev, int *num_vf)
{
	int outlen = MLX5_ST_SZ_BYTES(query_ec_params_out);
	u32 in[MLX5_ST_SZ_DW(query_ec_params_in)] = {0};
	void *out;
	void *ctx;
	int err;

	out = kvzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	MLX5_SET(query_ec_params_in, in, opcode, MLX5_CMD_OP_QUERY_EC_PARAMS);

	err = mlx5_cmd_exec(dev, in, sizeof(in), out, outlen);
	if (err) {
		mlx5_core_warn(dev, "err = %d\n", err);
		goto error1;
	}

	ctx = MLX5_ADDR_OF(query_ec_params_out, out, context);
	mlx5_core_warn(dev, "host_number %d\n", MLX5_GET(ec_params_context, ctx, host_number));
	mlx5_core_warn(dev, "host_num_of_vfs %d\n", MLX5_GET(ec_params_context, ctx, host_num_of_vfs));
	mlx5_core_warn(dev, "host_pci_bus %d\n", MLX5_GET(ec_params_context, ctx, host_pci_bus));
	mlx5_core_warn(dev, "host_pci_device %d\n", MLX5_GET(ec_params_context, ctx, host_pci_device));
	mlx5_core_warn(dev, "host_pci_function %d\n", MLX5_GET(ec_params_context, ctx, host_pci_function));
	*num_vf = MLX5_GET(ec_params_context, ctx, host_num_of_vfs);

error1:
	kvfree(out);
	return err;
}
