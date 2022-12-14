// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include "nvme.h"
#include "passthru.h"

static int __nvme_execute_rq(struct gendisk *disk, struct request *rq,
			     bool at_head)
{
	blk_status_t status;

	status = blk_execute_rq(disk, rq, at_head);
	if (nvme_req(rq)->flags & NVME_REQ_CANCELLED)
		return -EINTR;
	if (nvme_req(rq)->status)
		return nvme_req(rq)->status;
	return blk_status_to_errno(status);
}

int nvme_admin_passthru_sync(struct nvme_ctrl *ctrl, struct nvme_command *cmd,
			     void *buffer, unsigned int bufflen,
			     unsigned int timeout_ms)
{
	struct request *req;
	int ret;

	req = nvme_alloc_request(ctrl->admin_q, cmd, 0);
	if (IS_ERR(req))
		return PTR_ERR(req);

	if (timeout_ms)
		req->timeout = msecs_to_jiffies(timeout_ms);
	nvme_req(req)->flags |= NVME_REQ_USERCMD;

	if (buffer && bufflen) {
		ret = blk_rq_map_kern(ctrl->admin_q, req, buffer, bufflen,
				      GFP_KERNEL);
		if (ret)
			goto out;
	}

	ret = __nvme_execute_rq(NULL, req, false);

out:
	blk_mq_free_request(req);
	return ret;
}
