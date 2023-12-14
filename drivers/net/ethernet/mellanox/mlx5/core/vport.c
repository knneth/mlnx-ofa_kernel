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

#include <linux/export.h>
#include <linux/etherdevice.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/vport.h>
#include <linux/mlx5/eswitch.h>
#include "mlx5_core.h"
#include "sf/sf.h"

/* Mutex to hold while enabling or disabling RoCE */
static DEFINE_MUTEX(mlx5_roce_en_lock);

int mlx5_get_max_alloc_icm_th(struct mlx5_core_dev *mdev, u16 vhca_id, u32 *max_alloc_icm_th)
{
	u32 in[MLX5_ST_SZ_DW(vhca_icm_ctrl_reg)] = {};
	u32 out[MLX5_ST_SZ_DW(vhca_icm_ctrl_reg)] = {};
	int err;

	MLX5_SET(vhca_icm_ctrl_reg, in, vhca_id_valid, 1);
	MLX5_SET(vhca_icm_ctrl_reg, in, vhca_id, vhca_id);

	err =  mlx5_core_access_reg(mdev, in, sizeof(in), out, sizeof(out),
				    MLX5_REG_VHCA_ICM_CTRL, 0, 0);
	if (err)
		return err;

	*max_alloc_icm_th = MLX5_GET(vhca_icm_ctrl_reg, out,max_alloc_icm_th);

	return 0;
}

static int mlx5_get_total_icm(struct mlx5_core_dev *mdev, u32* total_icm)
{
	u32 in[MLX5_ST_SZ_DW(nic_cap_reg)] = {};
	u32 out[MLX5_ST_SZ_DW(nic_cap_reg)] = {};
	int err;

	err =  mlx5_core_access_reg(mdev, in, sizeof(in), out, sizeof(out),
				    MLX5_REG_NIC_CAP_REG, 0, 0);
	if (err)
		return err;

	*total_icm = MLX5_GET(nic_cap_reg, out, total_icm);

	return 0;
}

int mlx5_set_max_alloc_icm_th(struct mlx5_core_dev *mdev, u16 vhca_id, u32 max_alloc_icm_th)
{
	u32 in[MLX5_ST_SZ_DW(vhca_icm_ctrl_reg)] = {};
	u32 out[MLX5_ST_SZ_DW(vhca_icm_ctrl_reg)] = {};
	u32 total_icm;
	int err;

	err = mlx5_get_total_icm(mdev, &total_icm);
	if (err)
		return err;

	if (max_alloc_icm_th > total_icm) {
		mlx5_core_err(mdev, "Requested page limit %u is invalid, maximum limit %u\n",
			      max_alloc_icm_th, total_icm);
		return -EINVAL;
	}

	MLX5_SET(vhca_icm_ctrl_reg, in, vhca_id_valid, 1);
	MLX5_SET(vhca_icm_ctrl_reg, in, vhca_id, vhca_id);
	MLX5_SET(vhca_icm_ctrl_reg, in, max_alloc_icm_th_mask, 1);
	MLX5_SET(vhca_icm_ctrl_reg, in, max_alloc_icm_th, max_alloc_icm_th);

	return mlx5_core_access_reg(mdev, in, sizeof(in), out, sizeof(out),
				    MLX5_REG_VHCA_ICM_CTRL, 0, 1);
}

bool mlx5_vhca_icm_ctrl_supported(struct mlx5_core_dev *mdev)
{
	u32 in[MLX5_ST_SZ_DW(nic_cap_reg)] = {};
	u32 out[MLX5_ST_SZ_DW(nic_cap_reg)] = {};
	int err;

	if (MLX5_CAP_GEN(mdev, nic_cap_reg)) {
		err = mlx5_core_access_reg(mdev, in, sizeof(in), out, sizeof(out),
					   MLX5_REG_NIC_CAP_REG, 0, 0);
		if (err)
			return false;

		return !!MLX5_GET(nic_cap_reg, out, vhca_icm_ctrl);
	}

	return false;
}

u8 mlx5_query_vport_state(struct mlx5_core_dev *mdev, u8 opmod, u16 vport)
{
	u32 out[MLX5_ST_SZ_DW(query_vport_state_out)] = {};
	u32 in[MLX5_ST_SZ_DW(query_vport_state_in)] = {};
	int err;

	MLX5_SET(query_vport_state_in, in, opcode,
		 MLX5_CMD_OP_QUERY_VPORT_STATE);
	MLX5_SET(query_vport_state_in, in, op_mod, opmod);
	MLX5_SET(query_vport_state_in, in, vport_number, vport);
	if (vport)
		MLX5_SET(query_vport_state_in, in, other_vport, 1);

	err = mlx5_cmd_exec_inout(mdev, query_vport_state, in, out);
	if (err)
		return 0;

	return MLX5_GET(query_vport_state_out, out, state);
}

int mlx5_modify_vport_admin_state(struct mlx5_core_dev *mdev, u8 opmod,
				  u16 vport, u8 other_vport, u8 state)
{
	u32 in[MLX5_ST_SZ_DW(modify_vport_state_in)] = {};

	MLX5_SET(modify_vport_state_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_VPORT_STATE);
	MLX5_SET(modify_vport_state_in, in, op_mod, opmod);
	MLX5_SET(modify_vport_state_in, in, vport_number, vport);
	MLX5_SET(modify_vport_state_in, in, other_vport, other_vport);
	MLX5_SET(modify_vport_state_in, in, admin_state, state);

	return mlx5_cmd_exec_in(mdev, modify_vport_state, in);
}

static int mlx5_query_nic_vport_context(struct mlx5_core_dev *mdev, u16 vport,
					u32 *out)
{
	u32 in[MLX5_ST_SZ_DW(query_nic_vport_context_in)] = {};

	MLX5_SET(query_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_QUERY_NIC_VPORT_CONTEXT);
	MLX5_SET(query_nic_vport_context_in, in, vport_number, vport);
	if (vport)
		MLX5_SET(query_nic_vport_context_in, in, other_vport, 1);

	return mlx5_cmd_exec_inout(mdev, query_nic_vport_context, in, out);
}

int mlx5_query_nic_vport_min_inline(struct mlx5_core_dev *mdev,
				    u16 vport, u8 *min_inline)
{
	u32 out[MLX5_ST_SZ_DW(query_nic_vport_context_out)] = {};
	int err;

	err = mlx5_query_nic_vport_context(mdev, vport, out);
	if (!err)
		*min_inline = MLX5_GET(query_nic_vport_context_out, out,
				       nic_vport_context.min_wqe_inline_mode);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_nic_vport_min_inline);

void mlx5_query_min_inline(struct mlx5_core_dev *mdev,
			   u8 *min_inline_mode)
{
	switch (MLX5_CAP_ETH(mdev, wqe_inline_mode)) {
	case MLX5_CAP_INLINE_MODE_VPORT_CONTEXT:
		if (!mlx5_query_nic_vport_min_inline(mdev, 0, min_inline_mode))
			break;
		fallthrough;
	case MLX5_CAP_INLINE_MODE_L2:
		*min_inline_mode = MLX5_INLINE_MODE_L2;
		break;
	case MLX5_CAP_INLINE_MODE_NOT_REQUIRED:
		*min_inline_mode = MLX5_INLINE_MODE_NONE;
		break;
	}
}
EXPORT_SYMBOL_GPL(mlx5_query_min_inline);

int mlx5_modify_nic_vport_min_inline(struct mlx5_core_dev *mdev,
				     u16 vport, u8 min_inline)
{
	u32 in[MLX5_ST_SZ_DW(modify_nic_vport_context_in)] = {};
	void *nic_vport_ctx;

	MLX5_SET(modify_nic_vport_context_in, in,
		 field_select.min_inline, 1);
	MLX5_SET(modify_nic_vport_context_in, in, vport_number, vport);
	MLX5_SET(modify_nic_vport_context_in, in, other_vport, 1);

	nic_vport_ctx = MLX5_ADDR_OF(modify_nic_vport_context_in,
				     in, nic_vport_context);
	MLX5_SET(nic_vport_context, nic_vport_ctx,
		 min_wqe_inline_mode, min_inline);
	MLX5_SET(modify_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT);

	return mlx5_cmd_exec_in(mdev, modify_nic_vport_context, in);
}

int mlx5_query_nic_vport_mac_address(struct mlx5_core_dev *mdev,
				     u16 vport, bool other, u8 *addr)
{
	u32 out[MLX5_ST_SZ_DW(query_nic_vport_context_out)] = {};
	u32 in[MLX5_ST_SZ_DW(query_nic_vport_context_in)] = {};
	u8 *out_addr;
	int err;

	out_addr = MLX5_ADDR_OF(query_nic_vport_context_out, out,
				nic_vport_context.permanent_address);

	MLX5_SET(query_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_QUERY_NIC_VPORT_CONTEXT);
	MLX5_SET(query_nic_vport_context_in, in, vport_number, vport);
	MLX5_SET(query_nic_vport_context_in, in, other_vport, other);

	err = mlx5_cmd_exec_inout(mdev, query_nic_vport_context, in, out);
	if (!err)
		ether_addr_copy(addr, &out_addr[2]);

	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_nic_vport_mac_address);

int mlx5_query_mac_address(struct mlx5_core_dev *mdev, u8 *addr)
{
	return mlx5_query_nic_vport_mac_address(mdev, 0, false, addr);
}
EXPORT_SYMBOL_GPL(mlx5_query_mac_address);

int mlx5_modify_nic_vport_mac_address(struct mlx5_core_dev *mdev,
				      u16 vport, const u8 *addr)
{
	void *in;
	int inlen = MLX5_ST_SZ_BYTES(modify_nic_vport_context_in);
	int err;
	void *nic_vport_ctx;
	u8 *perm_mac;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	MLX5_SET(modify_nic_vport_context_in, in,
		 field_select.permanent_address, 1);
	MLX5_SET(modify_nic_vport_context_in, in, vport_number, vport);
	MLX5_SET(modify_nic_vport_context_in, in, other_vport, 1);

	nic_vport_ctx = MLX5_ADDR_OF(modify_nic_vport_context_in,
				     in, nic_vport_context);
	perm_mac = MLX5_ADDR_OF(nic_vport_context, nic_vport_ctx,
				permanent_address);

	ether_addr_copy(&perm_mac[2], addr);
	MLX5_SET(modify_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT);

	err = mlx5_cmd_exec_in(mdev, modify_nic_vport_context, in);

	kvfree(in);

	return err;
}
EXPORT_SYMBOL_GPL(mlx5_modify_nic_vport_mac_address);

int mlx5_query_nic_vport_mtu(struct mlx5_core_dev *mdev, u16 *mtu)
{
	int outlen = MLX5_ST_SZ_BYTES(query_nic_vport_context_out);
	u32 *out;
	int err;

	out = kvzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	err = mlx5_query_nic_vport_context(mdev, 0, out);
	if (!err)
		*mtu = MLX5_GET(query_nic_vport_context_out, out,
				nic_vport_context.mtu);

	kvfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_nic_vport_mtu);

int mlx5_modify_nic_vport_mtu(struct mlx5_core_dev *mdev, u16 mtu)
{
	int inlen = MLX5_ST_SZ_BYTES(modify_nic_vport_context_in);
	void *in;
	int err;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	MLX5_SET(modify_nic_vport_context_in, in, field_select.mtu, 1);
	MLX5_SET(modify_nic_vport_context_in, in, nic_vport_context.mtu, mtu);
	MLX5_SET(modify_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT);

	err = mlx5_cmd_exec_in(mdev, modify_nic_vport_context, in);

	kvfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_modify_nic_vport_mtu);

int mlx5_query_nic_vport_mac_list(struct mlx5_core_dev *dev,
				  u16 vport,
				  enum mlx5_list_type list_type,
				  u8 addr_list[][ETH_ALEN],
				  int *list_size)
{
	u32 in[MLX5_ST_SZ_DW(query_nic_vport_context_in)] = {0};
	void *nic_vport_ctx;
	int max_list_size;
	int req_list_size;
	int out_sz;
	void *out;
	int err;
	int i;

	req_list_size = *list_size;

	max_list_size = list_type == MLX5_NVPRT_LIST_TYPE_UC ?
		1 << MLX5_CAP_GEN(dev, log_max_current_uc_list) :
		1 << MLX5_CAP_GEN(dev, log_max_current_mc_list);

	if (req_list_size > max_list_size) {
		mlx5_core_warn(dev, "Requested list size (%d) > (%d) max_list_size\n",
			       req_list_size, max_list_size);
		req_list_size = max_list_size;
	}

	out_sz = MLX5_ST_SZ_BYTES(query_nic_vport_context_in) +
			req_list_size * MLX5_ST_SZ_BYTES(mac_address_layout);

	out = kvzalloc(out_sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	MLX5_SET(query_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_QUERY_NIC_VPORT_CONTEXT);
	MLX5_SET(query_nic_vport_context_in, in, allowed_list_type, list_type);
	MLX5_SET(query_nic_vport_context_in, in, vport_number, vport);
	if (vport || mlx5_core_is_ecpf(dev))
		MLX5_SET(query_nic_vport_context_in, in, other_vport, 1);

	err = mlx5_cmd_exec(dev, in, sizeof(in), out, out_sz);
	if (err)
		goto out;

	nic_vport_ctx = MLX5_ADDR_OF(query_nic_vport_context_out, out,
				     nic_vport_context);
	req_list_size = MLX5_GET(nic_vport_context, nic_vport_ctx,
				 allowed_list_size);

	*list_size = req_list_size;
	for (i = 0; i < req_list_size; i++) {
		u8 *mac_addr = MLX5_ADDR_OF(nic_vport_context,
					nic_vport_ctx,
					current_uc_mac_address[i]) + 2;
		ether_addr_copy(addr_list[i], mac_addr);
	}
out:
	kvfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_nic_vport_mac_list);

int mlx5_modify_nic_vport_mac_list(struct mlx5_core_dev *dev,
				   enum mlx5_list_type list_type,
				   u8 addr_list[][ETH_ALEN],
				   int list_size)
{
	u32 out[MLX5_ST_SZ_DW(modify_nic_vport_context_out)] = {};
	void *nic_vport_ctx;
	int max_list_size;
	int in_sz;
	void *in;
	int err;
	int i;

	max_list_size = list_type == MLX5_NVPRT_LIST_TYPE_UC ?
		 1 << MLX5_CAP_GEN(dev, log_max_current_uc_list) :
		 1 << MLX5_CAP_GEN(dev, log_max_current_mc_list);

	if (list_size > max_list_size)
		return -ENOSPC;

	in_sz = MLX5_ST_SZ_BYTES(modify_nic_vport_context_in) +
		list_size * MLX5_ST_SZ_BYTES(mac_address_layout);

	in = kvzalloc(in_sz, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	MLX5_SET(modify_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT);
	MLX5_SET(modify_nic_vport_context_in, in,
		 field_select.addresses_list, 1);

	nic_vport_ctx = MLX5_ADDR_OF(modify_nic_vport_context_in, in,
				     nic_vport_context);

	MLX5_SET(nic_vport_context, nic_vport_ctx,
		 allowed_list_type, list_type);
	MLX5_SET(nic_vport_context, nic_vport_ctx,
		 allowed_list_size, list_size);

	for (i = 0; i < list_size; i++) {
		u8 *curr_mac = MLX5_ADDR_OF(nic_vport_context,
					    nic_vport_ctx,
					    current_uc_mac_address[i]) + 2;
		ether_addr_copy(curr_mac, addr_list[i]);
	}

	err = mlx5_cmd_exec(dev, in, in_sz, out, sizeof(out));
	kvfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_modify_nic_vport_mac_list);

int mlx5_query_nic_vport_vlans(struct mlx5_core_dev *dev, u32 vport,
			       unsigned long *vlans)
{
	u32 in[MLX5_ST_SZ_DW(query_nic_vport_context_in)];
	void *nic_vport_ctx;
	int req_list_size;
	int out_sz;
	void *out;
	int err;
	int i;

	req_list_size = 1 << MLX5_CAP_GEN(dev, log_max_vlan_list);
	out_sz = MLX5_ST_SZ_BYTES(modify_nic_vport_context_in) +
		req_list_size * MLX5_ST_SZ_BYTES(vlan_layout);

	memset(in, 0, sizeof(in));
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	MLX5_SET(query_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_QUERY_NIC_VPORT_CONTEXT);
	MLX5_SET(query_nic_vport_context_in, in, allowed_list_type,
		 MLX5_NVPRT_LIST_TYPE_VLAN);
	MLX5_SET(query_nic_vport_context_in, in, vport_number, vport);

	if (vport)
		MLX5_SET(query_nic_vport_context_in, in, other_vport, 1);

	err = mlx5_cmd_exec(dev, in, sizeof(in), out, out_sz);
	if (err)
		goto out;

	nic_vport_ctx = MLX5_ADDR_OF(query_nic_vport_context_out, out,
				     nic_vport_context);
	req_list_size = MLX5_GET(nic_vport_context, nic_vport_ctx,
				 allowed_list_size);

	for (i = 0; i < req_list_size; i++) {
		void *vlan_addr = MLX5_ADDR_OF(nic_vport_context,
				nic_vport_ctx,
				current_uc_mac_address[i]);
		bitmap_set(vlans, MLX5_GET(vlan_layout, vlan_addr, vlan), 1);
	}
out:
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_nic_vport_vlans);

int mlx5_modify_nic_vport_vlans(struct mlx5_core_dev *dev,
				u16 vlans[],
				int list_size)
{
	u32 out[MLX5_ST_SZ_DW(modify_nic_vport_context_out)];
	void *nic_vport_ctx;
	int max_list_size;
	int in_sz;
	void *in;
	int err;
	int i;

	max_list_size = 1 << MLX5_CAP_GEN(dev, log_max_vlan_list);

	if (list_size > max_list_size)
		return -ENOSPC;

	in_sz = MLX5_ST_SZ_BYTES(modify_nic_vport_context_in) +
		list_size * MLX5_ST_SZ_BYTES(vlan_layout);

	memset(out, 0, sizeof(out));
	in = kvzalloc(in_sz, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	MLX5_SET(modify_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT);
	MLX5_SET(modify_nic_vport_context_in, in,
		 field_select.addresses_list, 1);

	nic_vport_ctx = MLX5_ADDR_OF(modify_nic_vport_context_in, in,
				     nic_vport_context);

	MLX5_SET(nic_vport_context, nic_vport_ctx,
		 allowed_list_type, MLX5_NVPRT_LIST_TYPE_VLAN);
	MLX5_SET(nic_vport_context, nic_vport_ctx,
		 allowed_list_size, list_size);

	for (i = 0; i < list_size; i++) {
		void *vlan_addr = MLX5_ADDR_OF(nic_vport_context,
					       nic_vport_ctx,
					       current_uc_mac_address[i]);
		MLX5_SET(vlan_layout, vlan_addr, vlan, vlans[i]);
	}

	err = mlx5_cmd_exec(dev, in, in_sz, out, sizeof(out));
	kvfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_modify_nic_vport_vlans);

int mlx5_query_nic_vport_system_image_guid(struct mlx5_core_dev *mdev,
					   u64 *system_image_guid)
{
	u32 *out;
	int outlen = MLX5_ST_SZ_BYTES(query_nic_vport_context_out);
	int err;

	out = kvzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	err = mlx5_query_nic_vport_context(mdev, 0, out);
	if (err)
		goto out;

	*system_image_guid = MLX5_GET64(query_nic_vport_context_out, out,
					nic_vport_context.system_image_guid);
out:
	kvfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_nic_vport_system_image_guid);

int mlx5_query_nic_vport_node_guid(struct mlx5_core_dev *mdev, u32 vport,
				   u64 *node_guid)
{
	u32 *out;
	int outlen = MLX5_ST_SZ_BYTES(query_nic_vport_context_out);

	out = kvzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	mlx5_query_nic_vport_context(mdev, vport, out);

	*node_guid = MLX5_GET64(query_nic_vport_context_out, out,
				nic_vport_context.node_guid);

	kvfree(out);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_nic_vport_node_guid);

int mlx5_modify_nic_vport_node_guid(struct mlx5_core_dev *mdev,
				    u16 vport, u64 node_guid)
{
	int inlen = MLX5_ST_SZ_BYTES(modify_nic_vport_context_in);
	void *nic_vport_context;
	void *in;
	int err;

	if (!MLX5_CAP_GEN(mdev, vport_group_manager))
		return -EACCES;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	MLX5_SET(modify_nic_vport_context_in, in,
		 field_select.node_guid, 1);
	MLX5_SET(modify_nic_vport_context_in, in, vport_number, vport);
	MLX5_SET(modify_nic_vport_context_in, in, other_vport, 1);

	nic_vport_context = MLX5_ADDR_OF(modify_nic_vport_context_in,
					 in, nic_vport_context);
	MLX5_SET64(nic_vport_context, nic_vport_context, node_guid, node_guid);
	MLX5_SET(modify_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT);

	err = mlx5_cmd_exec_in(mdev, modify_nic_vport_context, in);

	kvfree(in);

	return err;
}

int mlx5_query_nic_vport_qkey_viol_cntr(struct mlx5_core_dev *mdev,
					u16 *qkey_viol_cntr)
{
	u32 *out;
	int outlen = MLX5_ST_SZ_BYTES(query_nic_vport_context_out);

	out = kvzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	mlx5_query_nic_vport_context(mdev, 0, out);

	*qkey_viol_cntr = MLX5_GET(query_nic_vport_context_out, out,
				   nic_vport_context.qkey_violation_counter);

	kvfree(out);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_nic_vport_qkey_viol_cntr);

int mlx5_query_hca_vport_gid(struct mlx5_core_dev *dev, u8 other_vport,
			     u8 port_num, u16  vf_num, u16 gid_index,
			     union ib_gid *gid)
{
	int in_sz = MLX5_ST_SZ_BYTES(query_hca_vport_gid_in);
	int out_sz = MLX5_ST_SZ_BYTES(query_hca_vport_gid_out);
	int is_group_manager;
	void *out = NULL;
	void *in = NULL;
	union ib_gid *tmp;
	int tbsz;
	int nout;
	int err;

	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);
	tbsz = mlx5_get_gid_table_len(MLX5_CAP_GEN(dev, gid_table_size));
	mlx5_core_dbg(dev, "vf_num %d, index %d, gid_table_size %d\n",
		      vf_num, gid_index, tbsz);

	if (gid_index > tbsz && gid_index != 0xffff)
		return -EINVAL;

	if (gid_index == 0xffff)
		nout = tbsz;
	else
		nout = 1;

	out_sz += nout * sizeof(*gid);

	in = kvzalloc(in_sz, GFP_KERNEL);
	out = kvzalloc(out_sz, GFP_KERNEL);
	if (!in || !out) {
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(query_hca_vport_gid_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_VPORT_GID);
	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(query_hca_vport_gid_in, in, vport_number, vf_num);
			MLX5_SET(query_hca_vport_gid_in, in, other_vport, 1);
		} else {
			err = -EPERM;
			goto out;
		}
	}
	MLX5_SET(query_hca_vport_gid_in, in, gid_index, gid_index);

	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(query_hca_vport_gid_in, in, port_num, port_num);

	err = mlx5_cmd_exec(dev, in, in_sz, out, out_sz);
	if (err)
		goto out;

	tmp = out + MLX5_ST_SZ_BYTES(query_hca_vport_gid_out);
	gid->global.subnet_prefix = tmp->global.subnet_prefix;
	gid->global.interface_id = tmp->global.interface_id;

out:
	kvfree(in);
	kvfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_hca_vport_gid);

int mlx5_query_hca_vport_pkey(struct mlx5_core_dev *dev, u8 other_vport,
			      u8 port_num, u16 vf_num, u16 pkey_index,
			      u16 *pkey)
{
	int in_sz = MLX5_ST_SZ_BYTES(query_hca_vport_pkey_in);
	int out_sz = MLX5_ST_SZ_BYTES(query_hca_vport_pkey_out);
	int is_group_manager;
	void *out = NULL;
	void *in = NULL;
	void *pkarr;
	int nout;
	int tbsz;
	int err;
	int i;

	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);

	tbsz = mlx5_to_sw_pkey_sz(MLX5_CAP_GEN(dev, pkey_table_size));
	if (pkey_index > tbsz && pkey_index != 0xffff)
		return -EINVAL;

	if (pkey_index == 0xffff)
		nout = tbsz;
	else
		nout = 1;

	out_sz += nout * MLX5_ST_SZ_BYTES(pkey);

	in = kvzalloc(in_sz, GFP_KERNEL);
	out = kvzalloc(out_sz, GFP_KERNEL);
	if (!in || !out) {
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(query_hca_vport_pkey_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_VPORT_PKEY);
	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(query_hca_vport_pkey_in, in, vport_number, vf_num);
			MLX5_SET(query_hca_vport_pkey_in, in, other_vport, 1);
		} else {
			err = -EPERM;
			goto out;
		}
	}
	MLX5_SET(query_hca_vport_pkey_in, in, pkey_index, pkey_index);

	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(query_hca_vport_pkey_in, in, port_num, port_num);

	err = mlx5_cmd_exec(dev, in, in_sz, out, out_sz);
	if (err)
		goto out;

	pkarr = MLX5_ADDR_OF(query_hca_vport_pkey_out, out, pkey);
	for (i = 0; i < nout; i++, pkey++, pkarr += MLX5_ST_SZ_BYTES(pkey))
		*pkey = MLX5_GET_PR(pkey, pkarr, pkey);

out:
	kvfree(in);
	kvfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_hca_vport_pkey);

int mlx5_query_hca_vport_context(struct mlx5_core_dev *dev,
				 u8 other_vport, u8 port_num,
				 u16 vf_num,
				 struct mlx5_hca_vport_context *rep)
{
	int out_sz = MLX5_ST_SZ_BYTES(query_hca_vport_context_out);
	int in[MLX5_ST_SZ_DW(query_hca_vport_context_in)] = {};
	int is_group_manager;
	void *out;
	void *ctx;
	int err;

	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);

	out = kvzalloc(out_sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	MLX5_SET(query_hca_vport_context_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_VPORT_CONTEXT);

	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(query_hca_vport_context_in, in, other_vport, 1);
			MLX5_SET(query_hca_vport_context_in, in, vport_number, vf_num);
		} else {
			err = -EPERM;
			goto ex;
		}
	}

	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(query_hca_vport_context_in, in, port_num, port_num);

	err = mlx5_cmd_exec_inout(dev, query_hca_vport_context, in, out);
	if (err)
		goto ex;

	ctx = MLX5_ADDR_OF(query_hca_vport_context_out, out, hca_vport_context);
	rep->field_select = MLX5_GET_PR(hca_vport_context, ctx, field_select);
	rep->sm_virt_aware = MLX5_GET_PR(hca_vport_context, ctx, sm_virt_aware);
	rep->has_smi = MLX5_GET_PR(hca_vport_context, ctx, has_smi);
	rep->has_raw = MLX5_GET_PR(hca_vport_context, ctx, has_raw);
	rep->policy = MLX5_GET_PR(hca_vport_context, ctx, vport_state_policy);
	rep->phys_state = MLX5_GET_PR(hca_vport_context, ctx,
				      port_physical_state);
	rep->vport_state = MLX5_GET_PR(hca_vport_context, ctx, vport_state);
	rep->port_physical_state = MLX5_GET_PR(hca_vport_context, ctx,
					       port_physical_state);
	rep->port_guid = MLX5_GET64_PR(hca_vport_context, ctx, port_guid);
	rep->node_guid = MLX5_GET64_PR(hca_vport_context, ctx, node_guid);
	rep->cap_mask1 = MLX5_GET_PR(hca_vport_context, ctx, cap_mask1);
	rep->cap_mask1_perm = MLX5_GET_PR(hca_vport_context, ctx,
					  cap_mask1_field_select);
	rep->cap_mask2 = MLX5_GET_PR(hca_vport_context, ctx, cap_mask2);
	rep->cap_mask2_perm = MLX5_GET_PR(hca_vport_context, ctx,
					  cap_mask2_field_select);
	rep->lid = MLX5_GET_PR(hca_vport_context, ctx, lid);
	rep->init_type_reply = MLX5_GET_PR(hca_vport_context, ctx,
					   init_type_reply);
	rep->lmc = MLX5_GET_PR(hca_vport_context, ctx, lmc);
	rep->subnet_timeout = MLX5_GET_PR(hca_vport_context, ctx,
					  subnet_timeout);
	rep->sm_lid = MLX5_GET_PR(hca_vport_context, ctx, sm_lid);
	rep->sm_sl = MLX5_GET_PR(hca_vport_context, ctx, sm_sl);
	rep->qkey_violation_counter = MLX5_GET_PR(hca_vport_context, ctx,
						  qkey_violation_counter);
	rep->pkey_violation_counter = MLX5_GET_PR(hca_vport_context, ctx,
						  pkey_violation_counter);
	rep->grh_required = MLX5_GET_PR(hca_vport_context, ctx, grh_required);
	rep->sys_image_guid = MLX5_GET64_PR(hca_vport_context, ctx,
					    system_image_guid);

ex:
	kvfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_hca_vport_context);

int mlx5_query_hca_vport_system_image_guid(struct mlx5_core_dev *dev,
					   u64 *sys_image_guid)
{
	struct mlx5_hca_vport_context *rep;
	int err;

	rep = kvzalloc(sizeof(*rep), GFP_KERNEL);
	if (!rep)
		return -ENOMEM;

	err = mlx5_query_hca_vport_context(dev, 0, 1, 0, rep);
	if (!err)
		*sys_image_guid = rep->sys_image_guid;

	kvfree(rep);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_hca_vport_system_image_guid);

int mlx5_query_hca_vport_node_guid(struct mlx5_core_dev *dev,
				   u64 *node_guid)
{
	struct mlx5_hca_vport_context *rep;
	int err;

	rep = kvzalloc(sizeof(*rep), GFP_KERNEL);
	if (!rep)
		return -ENOMEM;

	err = mlx5_query_hca_vport_context(dev, 0, 1, 0, rep);
	if (!err)
		*node_guid = rep->node_guid;

	kvfree(rep);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_hca_vport_node_guid);

int mlx5_query_nic_vport_promisc(struct mlx5_core_dev *mdev,
				 u16 vport,
				 int *promisc_uc,
				 int *promisc_mc,
				 int *promisc_all)
{
	u32 *out;
	int outlen = MLX5_ST_SZ_BYTES(query_nic_vport_context_out);
	int err;

	out = kvzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	err = mlx5_query_nic_vport_context(mdev, vport, out);
	if (err)
		goto out;

	*promisc_uc = MLX5_GET(query_nic_vport_context_out, out,
			       nic_vport_context.promisc_uc);
	*promisc_mc = MLX5_GET(query_nic_vport_context_out, out,
			       nic_vport_context.promisc_mc);
	*promisc_all = MLX5_GET(query_nic_vport_context_out, out,
				nic_vport_context.promisc_all);

out:
	kvfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_nic_vport_promisc);

int mlx5_modify_nic_vport_promisc(struct mlx5_core_dev *mdev,
				  int promisc_uc,
				  int promisc_mc,
				  int promisc_all)
{
	void *in;
	int inlen = MLX5_ST_SZ_BYTES(modify_nic_vport_context_in);
	int err;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	MLX5_SET(modify_nic_vport_context_in, in, field_select.promisc, 1);
	MLX5_SET(modify_nic_vport_context_in, in,
		 nic_vport_context.promisc_uc, promisc_uc);
	MLX5_SET(modify_nic_vport_context_in, in,
		 nic_vport_context.promisc_mc, promisc_mc);
	MLX5_SET(modify_nic_vport_context_in, in,
		 nic_vport_context.promisc_all, promisc_all);
	MLX5_SET(modify_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT);

	err = mlx5_cmd_exec_in(mdev, modify_nic_vport_context, in);

	kvfree(in);

	return err;
}
EXPORT_SYMBOL_GPL(mlx5_modify_nic_vport_promisc);

enum {
	UC_LOCAL_LB,
	MC_LOCAL_LB
};

int mlx5_nic_vport_update_local_lb(struct mlx5_core_dev *mdev, bool enable)
{
	int inlen = MLX5_ST_SZ_BYTES(modify_nic_vport_context_in);
	bool disable_local_lb;
	void *in;
	int err;

	if (!MLX5_CAP_GEN(mdev, disable_local_lb_mc) &&
	    !MLX5_CAP_GEN(mdev, disable_local_lb_uc))
		return 0;

	mdev->local_lb.driver_state = enable;
	disable_local_lb = mdev->local_lb.user_force_disable || !enable;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	MLX5_SET(modify_nic_vport_context_in, in,
		 nic_vport_context.disable_mc_local_lb, disable_local_lb);
	MLX5_SET(modify_nic_vport_context_in, in,
		 nic_vport_context.disable_uc_local_lb, disable_local_lb);

	if (MLX5_CAP_GEN(mdev, disable_local_lb_mc))
		MLX5_SET(modify_nic_vport_context_in, in,
			 field_select.disable_mc_local_lb, 1);

	if (MLX5_CAP_GEN(mdev, disable_local_lb_uc))
		MLX5_SET(modify_nic_vport_context_in, in,
			 field_select.disable_uc_local_lb, 1);
	MLX5_SET(modify_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT);

	err = mlx5_cmd_exec_in(mdev, modify_nic_vport_context, in);

	if (!err)
		mlx5_core_dbg(mdev, "%s local_lb\n",
			      enable ? "enable" : "disable");

	kvfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_nic_vport_update_local_lb);

int mlx5_nic_vport_query_local_lb(struct mlx5_core_dev *mdev, bool *status)
{
	int outlen = MLX5_ST_SZ_BYTES(query_nic_vport_context_out);
	u32 *out;
	int value;
	int err;

	out = kvzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	err = mlx5_query_nic_vport_context(mdev, 0, out);
	if (err)
		goto out;

	value = MLX5_GET(query_nic_vport_context_out, out,
			 nic_vport_context.disable_mc_local_lb) << MC_LOCAL_LB;

	value |= MLX5_GET(query_nic_vport_context_out, out,
			  nic_vport_context.disable_uc_local_lb) << UC_LOCAL_LB;

	*status = !value;

out:
	kvfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_nic_vport_query_local_lb);

enum mlx5_vport_roce_state {
	MLX5_VPORT_ROCE_DISABLED = 0,
	MLX5_VPORT_ROCE_ENABLED  = 1,
};

static int mlx5_nic_vport_update_roce_state(struct mlx5_core_dev *mdev,
					    enum mlx5_vport_roce_state state)
{
	void *in;
	int inlen = MLX5_ST_SZ_BYTES(modify_nic_vport_context_in);
	int err;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	MLX5_SET(modify_nic_vport_context_in, in, field_select.roce_en, 1);
	MLX5_SET(modify_nic_vport_context_in, in, nic_vport_context.roce_en,
		 state);
	MLX5_SET(modify_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT);

	err = mlx5_cmd_exec_in(mdev, modify_nic_vport_context, in);

	kvfree(in);

	return err;
}

int mlx5_nic_vport_enable_roce(struct mlx5_core_dev *mdev)
{
	int err = 0;

	mutex_lock(&mlx5_roce_en_lock);
	if (!mdev->roce.roce_en)
		err = mlx5_nic_vport_update_roce_state(mdev, MLX5_VPORT_ROCE_ENABLED);

	if (!err)
		mdev->roce.roce_en++;
	mutex_unlock(&mlx5_roce_en_lock);

	return err;
}
EXPORT_SYMBOL_GPL(mlx5_nic_vport_enable_roce);

int mlx5_nic_vport_disable_roce(struct mlx5_core_dev *mdev)
{
	int err = 0;

	mutex_lock(&mlx5_roce_en_lock);
	if (mdev->roce.roce_en) {
		mdev->roce.roce_en--;
		if (mdev->roce.roce_en == 0)
			err = mlx5_nic_vport_update_roce_state(mdev, MLX5_VPORT_ROCE_DISABLED);

		if (err)
			mdev->roce.roce_en++;
	}
	mutex_unlock(&mlx5_roce_en_lock);
	return err;
}
EXPORT_SYMBOL(mlx5_nic_vport_disable_roce);

int mlx5_core_query_vport_counter(struct mlx5_core_dev *dev, u8 other_vport,
				  int vf, u8 port_num, void *out)
{
	int in_sz = MLX5_ST_SZ_BYTES(query_vport_counter_in);
	int is_group_manager;
	void *in;
	int err;

	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);
	in = kvzalloc(in_sz, GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		return err;
	}

	MLX5_SET(query_vport_counter_in, in, opcode,
		 MLX5_CMD_OP_QUERY_VPORT_COUNTER);
	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(query_vport_counter_in, in, other_vport, 1);
			MLX5_SET(query_vport_counter_in, in, vport_number, vf + 1);
		} else {
			err = -EPERM;
			goto free;
		}
	}
	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(query_vport_counter_in, in, port_num, port_num);

	err = mlx5_cmd_exec_inout(dev, query_vport_counter, in, out);
free:
	kvfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_query_vport_counter);

int mlx5_query_vport_down_stats(struct mlx5_core_dev *mdev, u16 vport,
				u8 other_vport, u64 *rx_discard_vport_down,
				u64 *tx_discard_vport_down)
{
	u32 out[MLX5_ST_SZ_DW(query_vnic_env_out)] = {};
	u32 in[MLX5_ST_SZ_DW(query_vnic_env_in)] = {};
	int err;

	MLX5_SET(query_vnic_env_in, in, opcode,
		 MLX5_CMD_OP_QUERY_VNIC_ENV);
	MLX5_SET(query_vnic_env_in, in, op_mod, 0);
	MLX5_SET(query_vnic_env_in, in, vport_number, vport);
	MLX5_SET(query_vnic_env_in, in, other_vport, other_vport);

	err = mlx5_cmd_exec_inout(mdev, query_vnic_env, in, out);
	if (err)
		return err;

	*rx_discard_vport_down = MLX5_GET64(query_vnic_env_out, out,
					    vport_env.receive_discard_vport_down);
	*tx_discard_vport_down = MLX5_GET64(query_vnic_env_out, out,
					    vport_env.transmit_discard_vport_down);
	return 0;
}

int mlx5_core_modify_hca_vport_context(struct mlx5_core_dev *dev,
				       u8 other_vport, u8 port_num,
				       int vf,
				       struct mlx5_hca_vport_context *req)
{
	int in_sz = MLX5_ST_SZ_BYTES(modify_hca_vport_context_in);
	int is_group_manager;
	void *ctx;
	void *in;
	int err;

	mlx5_core_dbg(dev, "vf %d\n", vf);
	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);
	in = kvzalloc(in_sz, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	MLX5_SET(modify_hca_vport_context_in, in, opcode, MLX5_CMD_OP_MODIFY_HCA_VPORT_CONTEXT);
	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(modify_hca_vport_context_in, in, other_vport, 1);
			MLX5_SET(modify_hca_vport_context_in, in, vport_number, vf);
		} else {
			err = -EPERM;
			goto ex;
		}
	}

	if (MLX5_CAP_GEN(dev, num_ports) > 1)
		MLX5_SET(modify_hca_vport_context_in, in, port_num, port_num);

	ctx = MLX5_ADDR_OF(modify_hca_vport_context_in, in, hca_vport_context);
	MLX5_SET(hca_vport_context, ctx, field_select, req->field_select);
	if (req->field_select & MLX5_HCA_VPORT_SEL_STATE_POLICY)
		MLX5_SET(hca_vport_context, ctx, vport_state_policy,
			 req->policy);
	if (req->field_select & MLX5_HCA_VPORT_SEL_PORT_GUID)
		MLX5_SET64(hca_vport_context, ctx, port_guid, req->port_guid);
	if (req->field_select & MLX5_HCA_VPORT_SEL_NODE_GUID)
		MLX5_SET64(hca_vport_context, ctx, node_guid, req->node_guid);
	MLX5_SET(hca_vport_context, ctx, cap_mask1, req->cap_mask1);
	MLX5_SET(hca_vport_context, ctx, cap_mask1_field_select,
		 req->cap_mask1_perm);
	err = mlx5_cmd_exec_in(dev, modify_hca_vport_context, in);
ex:
	kvfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_modify_hca_vport_context);

int mlx5_nic_vport_affiliate_multiport(struct mlx5_core_dev *master_mdev,
				       struct mlx5_core_dev *port_mdev)
{
	int inlen = MLX5_ST_SZ_BYTES(modify_nic_vport_context_in);
	void *in;
	int err;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	err = mlx5_nic_vport_enable_roce(port_mdev);
	if (err)
		goto free;

	MLX5_SET(modify_nic_vport_context_in, in, field_select.affiliation, 1);
	if (MLX5_CAP_GEN_2(master_mdev, sw_vhca_id_valid)) {
		MLX5_SET(modify_nic_vport_context_in, in,
			 nic_vport_context.vhca_id_type, VHCA_ID_TYPE_SW);
		MLX5_SET(modify_nic_vport_context_in, in,
			 nic_vport_context.affiliated_vhca_id,
			 MLX5_CAP_GEN_2(master_mdev, sw_vhca_id));
	} else {
		MLX5_SET(modify_nic_vport_context_in, in,
			 nic_vport_context.affiliated_vhca_id,
			 MLX5_CAP_GEN(master_mdev, vhca_id));
	}
	MLX5_SET(modify_nic_vport_context_in, in,
		 nic_vport_context.affiliation_criteria,
		 MLX5_CAP_GEN(port_mdev, affiliate_nic_vport_criteria));
	MLX5_SET(modify_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT);

	err = mlx5_cmd_exec_in(port_mdev, modify_nic_vport_context, in);
	if (err)
		mlx5_nic_vport_disable_roce(port_mdev);

free:
	kvfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_nic_vport_affiliate_multiport);

int mlx5_nic_vport_unaffiliate_multiport(struct mlx5_core_dev *port_mdev)
{
	int inlen = MLX5_ST_SZ_BYTES(modify_nic_vport_context_in);
	void *in;
	int err;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	MLX5_SET(modify_nic_vport_context_in, in, field_select.affiliation, 1);
	MLX5_SET(modify_nic_vport_context_in, in,
		 nic_vport_context.affiliated_vhca_id, 0);
	MLX5_SET(modify_nic_vport_context_in, in,
		 nic_vport_context.affiliation_criteria, 0);
	MLX5_SET(modify_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT);

	err = mlx5_cmd_exec_in(port_mdev, modify_nic_vport_context, in);
	if (!err)
		mlx5_nic_vport_disable_roce(port_mdev);

	kvfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_nic_vport_unaffiliate_multiport);

u64 mlx5_query_nic_system_image_guid(struct mlx5_core_dev *mdev)
{
	int port_type_cap = MLX5_CAP_GEN(mdev, port_type);
	u64 tmp;
	int err;

	if (mdev->sys_image_guid)
		return mdev->sys_image_guid;

	if (port_type_cap == MLX5_CAP_PORT_TYPE_ETH)
		err = mlx5_query_nic_vport_system_image_guid(mdev, &tmp);
	else
		err = mlx5_query_hca_vport_system_image_guid(mdev, &tmp);

	mdev->sys_image_guid = err ? 0 : tmp;

	return mdev->sys_image_guid;
}
EXPORT_SYMBOL_GPL(mlx5_query_nic_system_image_guid);

int mlx5_vport_get_other_func_cap(struct mlx5_core_dev *dev, u16 vport, void *out,
				  u16 opmod)
{
	bool ec_vf_func = mlx5_core_is_ec_vf_vport(dev, vport);
	u8 in[MLX5_ST_SZ_BYTES(query_hca_cap_in)] = {};

	opmod = (opmod << 1) | (HCA_CAP_OPMOD_GET_MAX & 0x01);
	MLX5_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	MLX5_SET(query_hca_cap_in, in, op_mod, opmod);
	MLX5_SET(query_hca_cap_in, in, function_id, mlx5_vport_to_func_id(dev, vport, ec_vf_func));
	MLX5_SET(query_hca_cap_in, in, other_function, true);
	MLX5_SET(query_hca_cap_in, in, ec_vf_function, ec_vf_func);
	return mlx5_cmd_exec_inout(dev, query_hca_cap, in, out);
}
EXPORT_SYMBOL_GPL(mlx5_vport_get_other_func_cap);

int mlx5_vport_set_other_func_cap(struct mlx5_core_dev *dev, const void *hca_cap,
				  u16 vport, u16 opmod)
{
	bool ec_vf_func = mlx5_core_is_ec_vf_vport(dev, vport);
	int set_sz = MLX5_ST_SZ_BYTES(set_hca_cap_in);
	void *set_hca_cap;
	void *set_ctx;
	int ret;

	set_ctx = kzalloc(set_sz, GFP_KERNEL);
	if (!set_ctx)
		return -ENOMEM;

	MLX5_SET(set_hca_cap_in, set_ctx, opcode, MLX5_CMD_OP_SET_HCA_CAP);
	MLX5_SET(set_hca_cap_in, set_ctx, op_mod, opmod << 1);
	set_hca_cap = MLX5_ADDR_OF(set_hca_cap_in, set_ctx, capability);
	memcpy(set_hca_cap, hca_cap, MLX5_ST_SZ_BYTES(cmd_hca_cap));
	MLX5_SET(set_hca_cap_in, set_ctx, function_id,
		 mlx5_vport_to_func_id(dev, vport, ec_vf_func));
	MLX5_SET(set_hca_cap_in, set_ctx, other_function, true);
	MLX5_SET(set_hca_cap_in, set_ctx, ec_vf_function, ec_vf_func);
	ret = mlx5_cmd_exec_in(dev, set_hca_cap, set_ctx);

	kfree(set_ctx);
	return ret;
}
