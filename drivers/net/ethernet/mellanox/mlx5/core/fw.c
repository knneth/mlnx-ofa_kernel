/*
 * Copyright (c) 2013-2015, Mellanox Technologies. All rights reserved.
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

#include <linux/mlx5/driver.h>
#include <linux/mlx5/cmd.h>
#include <linux/module.h>
#include "mlx5_core.h"

static int mlx5_cmd_query_adapter(struct mlx5_core_dev *dev, u32 *out,
				  int outlen)
{
	u32 in[MLX5_ST_SZ_DW(query_adapter_in)] = {0};

	MLX5_SET(query_adapter_in, in, opcode, MLX5_CMD_OP_QUERY_ADAPTER);
	return mlx5_cmd_exec(dev, in, sizeof(in), out, outlen);
}

int mlx5_query_board_id(struct mlx5_core_dev *dev)
{
	u32 *out;
	int outlen = MLX5_ST_SZ_BYTES(query_adapter_out);
	int err;

	out = kzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	err = mlx5_cmd_query_adapter(dev, out, outlen);
	if (err)
		goto out;

	memcpy(dev->board_id,
	       MLX5_ADDR_OF(query_adapter_out, out,
			    query_adapter_struct.vsd_contd_psid),
	       MLX5_FLD_SZ_BYTES(query_adapter_out,
				 query_adapter_struct.vsd_contd_psid));

out:
	kfree(out);
	return err;
}

int mlx5_core_query_vendor_id(struct mlx5_core_dev *mdev, u32 *vendor_id)
{
	u32 *out;
	int outlen = MLX5_ST_SZ_BYTES(query_adapter_out);
	int err;

	out = kzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	err = mlx5_cmd_query_adapter(mdev, out, outlen);
	if (err)
		goto out;

	*vendor_id = MLX5_GET(query_adapter_out, out,
			      query_adapter_struct.ieee_vendor_id);
out:
	kfree(out);
	return err;
}
EXPORT_SYMBOL(mlx5_core_query_vendor_id);

static int mlx5_get_pcam_reg(struct mlx5_core_dev *dev)
{
	return mlx5_query_pcam_reg(dev, dev->caps.pcam,
				   MLX5_PCAM_FEATURE_ENHANCED_FEATURES,
				   MLX5_PCAM_REGS_5000_TO_507F);
}

static int mlx5_get_mcam_reg(struct mlx5_core_dev *dev)
{
	return mlx5_query_mcam_reg(dev, dev->caps.mcam,
				   MLX5_MCAM_FEATURE_ENHANCED_FEATURES,
				   MLX5_MCAM_REGS_FIRST_128);
}

int mlx5_query_hca_caps(struct mlx5_core_dev *dev)
{
	int err;

	err = mlx5_core_get_caps(dev, MLX5_CAP_GENERAL);
	if (err)
		return err;

	if (MLX5_CAP_GEN(dev, eth_net_offloads)) {
		err = mlx5_core_get_caps(dev, MLX5_CAP_ETHERNET_OFFLOADS);
		if (err)
			return err;
	}

	if (MLX5_CAP_GEN(dev, pg)) {
		err = mlx5_core_get_caps(dev, MLX5_CAP_ODP);
		if (err)
			return err;
	}

	if (MLX5_CAP_GEN(dev, atomic)) {
		err = mlx5_core_get_caps(dev, MLX5_CAP_ATOMIC);
		if (err)
			return err;
	}

	if (MLX5_CAP_GEN(dev, roce)) {
		err = mlx5_core_get_caps(dev, MLX5_CAP_ROCE);
		if (err)
			return err;
	}

	if (MLX5_CAP_GEN(dev, nic_flow_table)) {
		err = mlx5_core_get_caps(dev, MLX5_CAP_FLOW_TABLE);
		if (err)
			return err;
	}

	if (MLX5_CAP_GEN(dev, vport_group_manager) &&
	    MLX5_CAP_GEN(dev, eswitch_flow_table)) {
		err = mlx5_core_get_caps(dev, MLX5_CAP_ESWITCH_FLOW_TABLE);
		if (err)
			return err;
	}

	if (MLX5_CAP_GEN(dev, eswitch_flow_table)) {
		err = mlx5_core_get_caps(dev, MLX5_CAP_ESWITCH);
		if (err)
			return err;
	}

	if (MLX5_CAP_GEN(dev, vector_calc)) {
		err = mlx5_core_get_caps(dev, MLX5_CAP_VECTOR_CALC);
		if (err)
			return err;
	}

	if (MLX5_CAP_GEN(dev, qos)) {
		err = mlx5_core_get_caps(dev, MLX5_CAP_QOS);
		if (err)
			return err;
	}

	if (MLX5_CAP_GEN(dev, vector_calc)) {
		err = mlx5_core_get_caps(dev, MLX5_CAP_VECTOR_CALC);
		if (err)
			return err;
	}

	err = mlx5_core_query_special_contexts(dev);
	if (err)
		return err;

	if (MLX5_CAP_GEN(dev, pcam_reg))
		mlx5_get_pcam_reg(dev);

	if (MLX5_CAP_GEN(dev, mcam_reg))
		mlx5_get_mcam_reg(dev);

	return 0;
}

int mlx5_cmd_init_hca(struct mlx5_core_dev *dev)
{
	u32 out[MLX5_ST_SZ_DW(init_hca_out)] = {0};
	u32 in[MLX5_ST_SZ_DW(init_hca_in)]   = {0};

	MLX5_SET(init_hca_in, in, opcode, MLX5_CMD_OP_INIT_HCA);
	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
}

int mlx5_cmd_teardown_hca(struct mlx5_core_dev *dev)
{
	u32 out[MLX5_ST_SZ_DW(teardown_hca_out)] = {0};
	u32 in[MLX5_ST_SZ_DW(teardown_hca_in)]   = {0};

	MLX5_SET(teardown_hca_in, in, opcode, MLX5_CMD_OP_TEARDOWN_HCA);
	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
}

static int query_other_hca_cap(struct mlx5_core_dev *mdev,
			       int function_id, void *out)
{
	int out_sz = MLX5_ST_SZ_BYTES(query_other_hca_cap_out);
	int in_sz = MLX5_ST_SZ_BYTES(query_other_hca_cap_in);
	void *in;
	int err;

	in = kzalloc(in_sz, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	MLX5_SET(query_other_hca_cap_in, in, opcode,
		 MLX5_CMD_OP_QUERY_OTHER_HCA_CAP);
	MLX5_SET(query_other_hca_cap_in, in, function_id, function_id);

	err = mlx5_cmd_exec(mdev, in, in_sz, out, out_sz);

	kfree(in);
	return err;
}

static int modify_other_hca_cap(struct mlx5_core_dev *mdev,
				int function_id, void *in)
{
	int out_sz = MLX5_ST_SZ_BYTES(modify_other_hca_cap_out);
	int in_sz = MLX5_ST_SZ_BYTES(modify_other_hca_cap_in);
	void *out;
	int err;

	out = kzalloc(out_sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	MLX5_SET(modify_other_hca_cap_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_OTHER_HCA_CAP);
	MLX5_SET(modify_other_hca_cap_in, in, function_id, function_id);

	err = mlx5_cmd_exec(mdev, in, in_sz, out, out_sz);

	kfree(out);
	return err;
}

int mlx5_get_other_hca_cap_roce(struct mlx5_core_dev *mdev,
				int function_id, bool *value)
{
	int out_sz = MLX5_ST_SZ_BYTES(query_other_hca_cap_out);
	void *out;
	void *other_capability;
	int err;

	out = kzalloc(out_sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	err = query_other_hca_cap(mdev, function_id, out);
	if (err)
		goto out;

	other_capability = MLX5_ADDR_OF(query_other_hca_cap_out,
					out, other_capability);
	*value = MLX5_GET(other_hca_cap, other_capability, roce);

out:
	kfree(out);
	return err;
}

int mlx5_modify_other_hca_cap_roce(struct mlx5_core_dev *mdev,
				   int function_id, bool value)
{
	int in_sz = MLX5_ST_SZ_BYTES(modify_other_hca_cap_in);
	struct mlx5_ifc_other_hca_cap_bits *other_capability;
	void *in;
	int err;

	in = kzalloc(in_sz, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	MLX5_SET(modify_other_hca_cap_in, in, field_select, ROCE_SELECT);
	other_capability = (struct mlx5_ifc_other_hca_cap_bits *)
				MLX5_ADDR_OF(modify_other_hca_cap_in,
					     in, other_capability);
	MLX5_SET(other_hca_cap, other_capability, roce, value);

	err = modify_other_hca_cap(mdev, function_id, in);

	kfree(in);
	return err;
}
