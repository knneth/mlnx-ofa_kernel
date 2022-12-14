/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#ifndef _NVME_PASSTHRU_H
#define _NVME_PASSTHRU_H

#include <linux/nvme-pci.h>

int nvme_admin_passthru_sync(struct nvme_ctrl *ctrl, struct nvme_command *cmd,
			     void *buffer, unsigned int bufflen,
			     unsigned int timeout_ms);

#endif /* _NVME_PASSTHRU_H */
