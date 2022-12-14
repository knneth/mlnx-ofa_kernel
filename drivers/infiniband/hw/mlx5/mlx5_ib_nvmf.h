/*
 * Copyright (c) 2013-2016, Mellanox Technologies. All rights reserved.
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

#ifndef MLX5_IB_EXP_H
#define MLX5_IB_EXP_H

#include <rdma/ib_verbs.h>
#include <linux/mlx5/nvmf.h>
#include "srq.h"

int mlx5_ib_set_qp_offload_type(void *qpc, struct ib_qp *qp,             
		enum ib_qp_offload_type offload_type); 

int mlx5_ib_exp_set_nvmf_srq_attrs(struct mlx5_nvmf_attr *nvmf,
	       	struct ib_srq_init_attr *init_attr);
int mlx5_ib_set_qp_srqn(void *qpc, struct ib_qp *qp,
		                        u32 srqn);
void mlx5_ib_internal_fill_nvmf_caps(struct mlx5_ib_dev *dev);
struct mlx5_ib_nvmf_be_ctrl {
	struct ib_nvmf_ctrl         ibctrl;
	struct mlx5_core_nvmf_be_ctrl      mctrl;
};

struct mlx5_ib_nvmf_ns {
	struct ib_nvmf_ns           ibns;
	struct mlx5_core_nvmf_ns    mns;
};

static inline struct mlx5_ib_nvmf_be_ctrl *
to_mibctrl(struct mlx5_core_nvmf_be_ctrl *mctrl)
{
	return container_of(mctrl, struct mlx5_ib_nvmf_be_ctrl, mctrl);
}

static inline struct mlx5_ib_nvmf_be_ctrl *to_mctrl(struct ib_nvmf_ctrl *ibctrl)
{
	return container_of(ibctrl, struct mlx5_ib_nvmf_be_ctrl, ibctrl);
}

static inline struct mlx5_ib_nvmf_ns *to_mns(struct ib_nvmf_ns *ibns)
{
	return container_of(ibns, struct mlx5_ib_nvmf_ns, ibns);
}

struct ib_nvmf_ctrl *mlx5_ib_create_nvmf_backend_ctrl(struct ib_srq *srq,
		struct ib_nvmf_backend_ctrl_init_attr *init_attr);
int mlx5_ib_destroy_nvmf_backend_ctrl(struct ib_nvmf_ctrl *ctrl);
struct ib_nvmf_ns *mlx5_ib_attach_nvmf_ns(struct ib_nvmf_ctrl *ctrl,
		struct ib_nvmf_ns_init_attr *init_attr);
int mlx5_ib_detach_nvmf_ns(struct ib_nvmf_ns *ns);
int mlx5_ib_query_nvmf_ns(struct ib_nvmf_ns *ns,
		struct ib_nvmf_ns_attr *ns_attr);



#endif
