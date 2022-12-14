/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#ifndef _LINUX_NVME_PCI_H
#define _LINUX_NVME_PCI_H

#include <linux/nvme.h>

int nvme_pdev_admin_passthru_sync(struct pci_dev *pdev,
				  struct nvme_command *cmd, void *buffer,
				  unsigned int bufflen,
				  unsigned int timeout_ms);

#endif /* _LINUX_NVME_PCI_H */
