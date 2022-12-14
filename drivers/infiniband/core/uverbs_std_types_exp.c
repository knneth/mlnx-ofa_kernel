
/*
 * Copyright (c) 2017, Mellanox Technologies inc.  All rights reserved.
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

#include <rdma/uverbs_std_types.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_verbs.h>
#include <linux/bug.h>
#include <linux/file.h>
#include "rdma_core.h"
#include "uverbs.h"
#include "uverbs_exp.h"

static int uverbs_exp_free_dm(struct ib_uobject *uobject,
			      enum rdma_remove_reason why)
{
	return ib_exp_free_dm((struct ib_dm *)uobject->object);
}

static int uverbs_exp_free_dct(struct ib_uobject *uobject,
			       enum rdma_remove_reason why)
{
	struct ib_dct  *dct = uobject->object;
	struct ib_udct_object *udct =
		container_of(uobject, struct ib_udct_object, uevent.uobject);
	int ret;

	ret = ib_exp_destroy_dct(dct);
	if (ret && why == RDMA_REMOVE_DESTROY)
		return ret;

	ib_uverbs_release_uevent(uobject->context->ufile, &udct->uevent);

	return ret;
}

const struct uverbs_obj_idr_type uverbs_type_attrs_dm = {
	/* 2 is used in order to free the DM after MRs */
	.type = UVERBS_TYPE_ALLOC_IDR(2),
	.destroy_object = uverbs_exp_free_dm,
};

const struct uverbs_obj_idr_type uverbs_type_attrs_dct = {
	.type = UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_udct_object), 0),
	.destroy_object = uverbs_exp_free_dct,
};
