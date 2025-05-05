/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */

#ifndef _UAPI_LINUX_VIRTIO_FS_H
#define _UAPI_LINUX_VIRTIO_FS_H

#include <linux/types.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_types.h>

struct virtio_fs_config {
	/* Filesystem name (UTF-8, not NUL-terminated, padded with NULs) */
	__u8 tag[36];

	/* Number of request queues */
	__le32 num_request_queues;

	/* Minimum number of bytes required for each buffer in the notification queue */
	__le32 notify_buf_size;
} __attribute__((packed));

/* Feature bits */
enum {
	VIRTIO_FS_F_NOTIFICATION
};

/* For the id field in virtio_pci_shm_cap */
#define VIRTIO_FS_SHMCAP_ID_CACHE 0

#endif /* _UAPI_LINUX_VIRTIO_FS_H */
