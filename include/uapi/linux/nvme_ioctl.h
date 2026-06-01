/*
 * Definitions for the NVM Express ioctl interface
 * Copyright (c) 2011-2014, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef _COMPAT_UAPI_LINUX_NVME_IOCTL_H
#define _COMPAT_UAPI_LINUX_NVME_IOCTL_H

#include "../../../compat/config.h"

#include_next <uapi/linux/nvme_ioctl.h>


#ifndef HAVE_UAPI_LINUX_NVME_NVME_URING_CMD_ADMIN
#define NVME_URING_CMD_ADMIN	_IOWR('N', 0x82, struct nvme_uring_cmd)
#define NVME_URING_CMD_ADMIN_VEC _IOWR('N', 0x83, struct nvme_uring_cmd)
#endif

#endif /* _COMPAT_UAPI_LINUX_NVME_IOCTL_H */
