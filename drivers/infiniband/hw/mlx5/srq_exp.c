/*
 * Copyright (c) 2017 Mellanox Technologies. All rights reserved.
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
#include <rdma/ib_verbs_exp.h>

#include "mlx5_ib.h"
#include "user_exp.h"

int mlx5_ib_exp_create_srq_user(struct mlx5_ib_dev *dev,
				struct mlx5_srq_attr *in,
				struct ib_udata *udata,
				struct mlx5_ib_create_srq *ucmd)
{
	struct mlx5_ib_exp_create_srq ucmd_exp = {};
	size_t ucmdlen;

	ucmdlen = min(udata->inlen, sizeof(ucmd_exp));
	if (ib_copy_from_udata(&ucmd_exp, udata, ucmdlen)) {
		mlx5_ib_dbg(dev, "failed copy udata\n");
		return -EFAULT;
	}

	if (ucmd_exp.reserved0 || ucmd_exp.reserved1 ||
	    ucmd_exp.comp_mask >= MLX5_EXP_CREATE_SRQ_MASK_RESERVED)
		return -EINVAL;

	if (in->type == IB_EXP_SRQT_TAG_MATCHING) {
		if (!ucmd_exp.max_num_tags)
			return -EINVAL;
		in->tm_log_list_size = ilog2(ucmd_exp.max_num_tags) + 1;
		if (in->tm_log_list_size >
		    MLX5_CAP_GEN(dev->mdev, log_tag_matching_list_sz)) {
			mlx5_ib_dbg(dev, "TM SRQ max_num_tags exceeding limit\n");
			return -EINVAL;
		}
		in->flags |= MLX5_SRQ_FLAG_RNDV;

		if (ucmd_exp.comp_mask & MLX5_EXP_CREATE_SRQ_MASK_DC_OP) {
			in->dc_op.pkey_index = ucmd_exp.dc_op.pkey_index;
			in->dc_op.path_mtu = ucmd_exp.dc_op.path_mtu;
			in->dc_op.sl = ucmd_exp.dc_op.sl;
			in->dc_op.max_rd_atomic = ucmd_exp.dc_op.max_rd_atomic;
			in->dc_op.min_rnr_timer = ucmd_exp.dc_op.min_rnr_timer;
			in->dc_op.timeout = ucmd_exp.dc_op.timeout;
			in->dc_op.retry_cnt = ucmd_exp.dc_op.retry_cnt;
			in->dc_op.rnr_retry = ucmd_exp.dc_op.rnr_retry;
			in->dc_op.dct_key = ucmd_exp.dc_op.dct_key;
			in->dc_op.ooo_caps = ucmd_exp.dc_op.ooo_caps;
			in->flags |= MLX5_SRQ_FLAG_SET_DC_OP;
		}
	}

	ucmdlen = offsetof(typeof(*ucmd), reserved1) + sizeof(ucmd->reserved1);
	ucmdlen = min(udata->inlen, ucmdlen);
	memcpy(ucmd, &ucmd_exp, ucmdlen);

	return 0;
}

static int mlx5_ib_check_nvmf_srq_attrs(struct ib_srq_init_attr *init_attr)
{
	switch (init_attr->ext.nvmf.type) {
	case IB_NVMF_WRITE_OFFLOAD:
	case IB_NVMF_READ_OFFLOAD:
	case IB_NVMF_READ_WRITE_OFFLOAD:
	case IB_NVMF_READ_WRITE_FLUSH_OFFLOAD:
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/* Must be called after checking that offload type values are valid */
static enum mlx5_nvmf_offload_type to_mlx5_nvmf_offload_type(enum ib_nvmf_offload_type type)
{
	switch (type) {
	case IB_NVMF_WRITE_OFFLOAD:
		return MLX5_NVMF_WRITE_OFFLOAD;
	case IB_NVMF_READ_OFFLOAD:
		return MLX5_NVMF_READ_OFFLOAD;
	case IB_NVMF_READ_WRITE_OFFLOAD:
		return MLX5_NVMF_READ_WRITE_OFFLOAD;
	case IB_NVMF_READ_WRITE_FLUSH_OFFLOAD:
		return MLX5_NVMF_READ_WRITE_FLUSH_OFFLOAD;
	default:
		return -EINVAL;
	}
}

int mlx5_ib_exp_set_nvmf_srq_attrs(struct mlx5_nvmf_attr *nvmf,
				   struct ib_srq_init_attr *init_attr)
{
	int err;

	err = mlx5_ib_check_nvmf_srq_attrs(init_attr);
	if (err)
		return -EINVAL;

	nvmf->type = to_mlx5_nvmf_offload_type(init_attr->ext.nvmf.type);
	nvmf->log_max_namespace = init_attr->ext.nvmf.log_max_namespace;
	nvmf->offloaded_capsules_count = init_attr->ext.nvmf.offloaded_capsules_count;
	nvmf->ioccsz = init_attr->ext.nvmf.cmd_size;
	nvmf->icdoff = init_attr->ext.nvmf.data_offset;
	nvmf->log_max_io_size = init_attr->ext.nvmf.log_max_io_size;
	nvmf->nvme_memory_log_page_size = init_attr->ext.nvmf.nvme_memory_log_page_size;
	nvmf->staging_buffer_log_page_size = init_attr->ext.nvmf.staging_buffer_log_page_size;
	nvmf->staging_buffer_number_of_pages = init_attr->ext.nvmf.staging_buffer_number_of_pages;
	nvmf->staging_buffer_page_offset = init_attr->ext.nvmf.staging_buffer_page_offset;
	nvmf->nvme_queue_size = init_attr->ext.nvmf.nvme_queue_size;
	nvmf->staging_buffer_pas = init_attr->ext.nvmf.staging_buffer_pas;

	return err;
}
