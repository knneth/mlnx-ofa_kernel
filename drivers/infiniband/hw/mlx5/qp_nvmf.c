/*
 * Copyright (c) 2016 Mellanox Technologies. All rights reserved.
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

#include "mlx5_ib.h"
#include <linux/mlx5/qp.h>
#include <rdma/ib_verbs_nvmf.h>

int mlx5_ib_set_qp_offload_type(void *qpc, struct ib_qp *qp,
		enum ib_qp_offload_type offload_type)
{
	switch (offload_type) {
		case IB_QP_OFFLOAD_NVMF:
			if (qp->srq &&
					qp->srq->srq_type == IB_EXP_SRQT_NVMF) {
				MLX5_SET(qpc, qpc, offload_type, MLX5_QPC_OFFLOAD_TYPE_NVMF);
				break;
			}
			/* Fall through */
		default:
			return -EINVAL;
	}

	return 0;
}

int mlx5_ib_set_qp_srqn(void *qpc, struct ib_qp *qp,
			u32 srqn)
{
	struct mlx5_ib_dev *dev = to_mdev(qp->device);
	struct mlx5_srq_table *table = &dev->srq_table;
	struct mlx5_core_srq *msrq;

	if (to_mqp(qp)->rq_type != MLX5_SRQ_RQ)
		return -EINVAL;

	xa_lock(&table->array);
	msrq = xa_load(&table->array, srqn);
	xa_unlock(&table->array);
	if (!msrq)
		return -EINVAL;

	qp->srq = &to_mibsrq(msrq)->ibsrq;
	MLX5_SET(qpc, qpc, srqn_rmpn_xrqn, srqn);

	return 0;
}
