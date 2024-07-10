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

#ifndef HAVE_UAPI_LINUX_NVME_PASSTHRU_CMD64
struct nvme_passthru_cmd64 {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd1;
	__u32	nsid;
	__u32	cdw2;
	__u32	cdw3;
	__u64	metadata;
	__u64	addr;
	__u32	metadata_len;
	__u32	data_len;
	__u32	cdw10;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
	__u32	timeout_ms;
	__u32   rsvd2;
	__u64	result;
};

#define NVME_IOCTL_ADMIN64_CMD	_IOWR('N', 0x47, struct nvme_passthru_cmd64)
#define NVME_IOCTL_IO64_CMD	_IOWR('N', 0x48, struct nvme_passthru_cmd64)
#endif /* HAVE_UAPI_LINUX_NVME_PASSTHRU_CMD64 */

#ifndef HAVE_UAPI_LINUX_NVME_NVME_URING_CMD_ADMIN
#define NVME_URING_CMD_ADMIN	_IOWR('N', 0x82, struct nvme_uring_cmd)
#define NVME_URING_CMD_ADMIN_VEC _IOWR('N', 0x83, struct nvme_uring_cmd)
#endif

#endif /* _COMPAT_UAPI_LINUX_NVME_IOCTL_H */
