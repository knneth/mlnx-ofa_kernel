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
#include <rdma/ib_verbs_nvmf.h>

#include "mlx5_ib.h"
#include "srq_nvmf.h"

int get_nvmf_pas_size(struct mlx5_nvmf_attr *nvmf)
{
	return nvmf->staging_buffer_number_of_pages * sizeof(u64);
}

void set_nvmf_srq_pas(struct mlx5_nvmf_attr *nvmf, __be64 *pas)
{
	int i;

	for (i = 0; i < nvmf->staging_buffer_number_of_pages; i++)
		pas[i] = cpu_to_be64(nvmf->staging_buffer_pas[i]);
}

void set_nvmf_xrq_context(struct mlx5_nvmf_attr *nvmf, void *xrqc)
{
	u16 nvme_queue_size;

        /*
         * According to the PRM, nvme_queue_size is a 16 bit field and
         * setting it to 0 means setting size to 2^16 (The maximum queue size
         * possible for an NVMe device).
         */
	if (nvmf->nvme_queue_size < 0x10000)
		nvme_queue_size = nvmf->nvme_queue_size;
	else
		nvme_queue_size = 0;


	MLX5_SET(xrqc, xrqc,
			nvme_offload_context.nvmf_offload_type,
			nvmf->type);
	MLX5_SET(xrqc, xrqc,
			nvme_offload_context.log_max_namespace,
			nvmf->log_max_namespace);
	MLX5_SET(xrqc, xrqc,
		 nvme_offload_context.ioccsz,
		 nvmf->ioccsz);
	MLX5_SET(xrqc, xrqc,
			nvme_offload_context.icdoff,
			nvmf->icdoff);
	MLX5_SET(xrqc, xrqc,
			nvme_offload_context.log_max_io_size,
			nvmf->log_max_io_size);
	MLX5_SET(xrqc, xrqc,
			nvme_offload_context.nvme_memory_log_page_size,
			nvmf->nvme_memory_log_page_size);
	MLX5_SET(xrqc, xrqc,
			nvme_offload_context.staging_buffer_log_page_size,
			nvmf->staging_buffer_log_page_size);
	MLX5_SET(xrqc, xrqc,
			nvme_offload_context.staging_buffer_number_of_pages,
			nvmf->staging_buffer_number_of_pages);
	MLX5_SET(xrqc, xrqc,
			nvme_offload_context.staging_buffer_page_offset,
			nvmf->staging_buffer_page_offset);
	MLX5_SET(xrqc, xrqc,
			nvme_offload_context.nvme_queue_size,
			nvmf->nvme_queue_size);
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
