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

#include <linux/mlx5/driver.h>
#include <linux/mlx5/srq.h>
#include "srq_exp.h"

int get_nvmf_pas_size(struct mlx5_nvmf_attr *nvmf)
{
	return nvmf->staging_buffer_number_of_pages * MLX5_PAS_ALIGN;
}

void set_nvmf_srq_pas(struct mlx5_nvmf_attr *nvmf,
			     void *start,
			     int align)
{
	int i;
	dma_addr_t dma_addr_be;

	for (i = 0; i < nvmf->staging_buffer_number_of_pages; i++) {
		dma_addr_be = cpu_to_be64(nvmf->staging_buffer_pas[i]);
		memcpy(start + i * align, &dma_addr_be, sizeof(u64));
	}
}

void set_nvmf_xrq_context(struct mlx5_nvmf_attr *nvmf, void *xrqc)
{
	MLX5_SET(xrqc, xrqc,
		 nvme_offload_context.nvmf_offload_type,
		 nvmf->type);
	MLX5_SET(xrqc, xrqc,
		 nvme_offload_context.log_max_namespace,
		 nvmf->log_max_namespace);
	MLX5_SET(xrqc, xrqc,
		 nvme_offload_context.offloaded_capsules_count,
		 nvmf->offloaded_capsules_count);
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

