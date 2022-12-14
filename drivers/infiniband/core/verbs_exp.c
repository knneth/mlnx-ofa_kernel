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

struct ib_dct *ib_exp_create_dct(struct ib_pd *pd, struct ib_dct_init_attr *attr,
				 struct ib_udata *udata)
{
	struct ib_dct *dct;

	if (!pd->device->exp_create_dct)
		return ERR_PTR(-ENOSYS);

	dct = pd->device->exp_create_dct(pd, attr, udata);
	if (!IS_ERR(dct)) {
		dct->pd = pd;
		dct->srq = attr->srq;
		dct->cq = attr->cq;
		atomic_inc(&dct->srq->usecnt);
		atomic_inc(&dct->cq->usecnt);
		atomic_inc(&dct->pd->usecnt);
	}

	return dct;
}
EXPORT_SYMBOL(ib_exp_create_dct);

int ib_exp_destroy_dct(struct ib_dct *dct)
{
	struct ib_srq *srq;
	struct ib_cq *cq;
	struct ib_pd *pd;
	int err;

	if (!dct->device->exp_destroy_dct)
		return -ENOSYS;

	srq = dct->srq;
	cq = dct->cq;
	pd = dct->pd;
	err = dct->device->exp_destroy_dct(dct);
	if (!err) {
		atomic_dec(&srq->usecnt);
		atomic_dec(&cq->usecnt);
		atomic_dec(&pd->usecnt);
	}

	return err;
}
EXPORT_SYMBOL(ib_exp_destroy_dct);

int ib_exp_query_dct(struct ib_dct *dct, struct ib_dct_attr *attr)
{
	if (!dct->device->exp_query_dct)
		return -ENOSYS;

	return dct->device->exp_query_dct(dct, attr);
}
EXPORT_SYMBOL(ib_exp_query_dct);

int ib_exp_arm_dct(struct ib_dct *dct)
{
	if (!dct->device->exp_arm_dct)
		return -ENOSYS;

	return dct->device->exp_arm_dct(dct, NULL);
}
EXPORT_SYMBOL(ib_exp_arm_dct);

int ib_exp_modify_cq(struct ib_cq *cq,
		 struct ib_cq_attr *cq_attr,
		 int cq_attr_mask)
{
	return cq->device->exp_modify_cq ?
		cq->device->exp_modify_cq(cq, cq_attr, cq_attr_mask) : -ENOSYS;
}
EXPORT_SYMBOL(ib_exp_modify_cq);

int ib_exp_query_device(struct ib_device *device,
			struct ib_exp_device_attr *device_attr,
			struct ib_udata *uhw)
{
	return device->exp_query_device(device, device_attr, uhw);
}
EXPORT_SYMBOL(ib_exp_query_device);

int ib_exp_query_mkey(struct ib_mr *mr, u64 mkey_attr_mask,
		  struct ib_mkey_attr *mkey_attr)
{
	return mr->device->exp_query_mkey ?
		mr->device->exp_query_mkey(mr, mkey_attr_mask, mkey_attr) : -ENOSYS;
}
EXPORT_SYMBOL(ib_exp_query_mkey);
