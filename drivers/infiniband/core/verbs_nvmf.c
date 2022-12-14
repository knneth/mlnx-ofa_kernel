/*
 * Copyright (c) 2015 Mellanox Technologies Ltd.  All rights reserved.
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

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/string.h>
#include <linux/slab.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_addr.h>

#include "core_priv.h"
/* NVMEoF target offload */
int ib_query_nvmf_ns(struct ib_nvmf_ns *ns, struct ib_nvmf_ns_attr *ns_attr)
{
	return ns->ctrl->srq->device->ops.query_nvmf_ns ?
		ns->ctrl->srq->device->ops.query_nvmf_ns(ns, ns_attr) : -ENOSYS;
}
EXPORT_SYMBOL(ib_query_nvmf_ns);

struct ib_mr *ib_get_dma_mr(struct ib_pd *pd, int mr_access_flags)
{
	struct ib_mr *mr;
	int err;

	err = ib_check_mr_access(mr_access_flags);
	if (err)
		return ERR_PTR(err);

	mr = pd->device->ops.get_dma_mr(pd, mr_access_flags);

	if (!IS_ERR(mr)) {
		mr->device  = pd->device;
		mr->pd      = pd;
		mr->uobject = NULL;
		atomic_inc(&pd->usecnt);
		mr->need_inval = false;
	}

	return mr;
}
EXPORT_SYMBOL(ib_get_dma_mr);

/* NVMEoF target offload */
struct ib_nvmf_ctrl *ib_create_nvmf_backend_ctrl(struct ib_srq *srq,
			struct ib_nvmf_backend_ctrl_init_attr *init_attr)
{
	struct ib_nvmf_ctrl *ctrl;

	if (!srq->device->ops.create_nvmf_backend_ctrl)
		return ERR_PTR(-ENOSYS);
	if (srq->srq_type != IB_EXP_SRQT_NVMF)
		return ERR_PTR(-EINVAL);

	ctrl = srq->device->ops.create_nvmf_backend_ctrl(srq, init_attr);
	if (!IS_ERR(ctrl)) {
		atomic_set(&ctrl->usecnt, 0);
		ctrl->srq = srq;
		ctrl->event_handler = init_attr->event_handler;
		ctrl->be_context = init_attr->be_context;
		atomic_inc(&srq->usecnt);
	}

	return ctrl;
}
EXPORT_SYMBOL_GPL(ib_create_nvmf_backend_ctrl);

int ib_destroy_nvmf_backend_ctrl(struct ib_nvmf_ctrl *ctrl)
{
	struct ib_srq *srq = ctrl->srq;
	int ret;

	if (atomic_read(&ctrl->usecnt))
		return -EBUSY;

	ret = srq->device->ops.destroy_nvmf_backend_ctrl(ctrl);
	if (!ret)
		atomic_dec(&srq->usecnt);

	return ret;
}
EXPORT_SYMBOL_GPL(ib_destroy_nvmf_backend_ctrl);

struct ib_nvmf_ns *ib_attach_nvmf_ns(struct ib_nvmf_ctrl *ctrl,
			struct ib_nvmf_ns_init_attr *init_attr)
{
	struct ib_srq *srq = ctrl->srq;
	struct ib_nvmf_ns *ns;

	if (!srq->device->ops.attach_nvmf_ns)
		return ERR_PTR(-ENOSYS);
	if (srq->srq_type != IB_EXP_SRQT_NVMF)
		return ERR_PTR(-EINVAL);

	ns = srq->device->ops.attach_nvmf_ns(ctrl, init_attr);
	if (!IS_ERR(ns)) {
		ns->ctrl   = ctrl;
		atomic_inc(&ctrl->usecnt);
	}

	return ns;
}
EXPORT_SYMBOL_GPL(ib_attach_nvmf_ns);

int ib_detach_nvmf_ns(struct ib_nvmf_ns *ns)
{
	struct ib_nvmf_ctrl *ctrl = ns->ctrl;
	struct ib_srq *srq = ctrl->srq;
	int ret;

	ret = srq->device->ops.detach_nvmf_ns(ns);
	if (!ret)
		atomic_dec(&ctrl->usecnt);

	return ret;
}
EXPORT_SYMBOL_GPL(ib_detach_nvmf_ns);
