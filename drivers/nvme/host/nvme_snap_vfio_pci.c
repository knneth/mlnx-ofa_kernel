// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 *     Author: Max Gurtovoy <mgurtovoy@nvidia.com>
 */

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/interrupt.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>
#include <linux/sched/mm.h>

#include <linux/vfio_pci_core.h>
#include <linux/nvme.h>
#include <linux/nvme-pci.h>

struct mlx5_nvme_vfio_pci_device;

struct mlx5_nvme_pinned_iova_phys {
	struct rb_node node;
	struct vfio_iommu_iova iommu_iova;
};

struct nvme_snap_notifier_block {
	struct notifier_block nb;
	struct mlx5_nvme_vfio_pci_device *mvdev;
};

struct mlx5_nvme_vfio_pci_device {
	struct vfio_pci_core_device vdev;
	bool efficient_cap;

	/* only valid for efficient capable */
	struct nvme_snap_notifier_block *nb;
};

#define SNAP_NVME_ADMIN_VENDOR_IOVA_MGMT 0xC4U
#define SNAP_NVME_IOVA_MGMT_OPM_MAP_RANGE 0x00U
#define SNAP_NVME_IOVA_MGMT_OPM_UNMAP_RANGE 0x01U
#define SNAP_NVME_IOVA_MGMT_OPM_UNMAP_ALL_RANGES 0x02U
#define SNAP_NVME_IOVA_MGMT_DW10_FID_SHIFT 0x0000U
#define SNAP_NVME_IOVA_MGMT_DW10_FID_MASK 0xFFFFU
#define SNAP_NVME_IOVA_MGMT_DW10_OPM_SHIFT 0x0010U
#define SNAP_NVME_IOVA_MGMT_DW10_OPM_MASK 0x000F0000U
#define SNAP_NVME_IOVA_MGMT_DW15_SZU_SHIFT 0x0000U
#define SNAP_NVME_IOVA_MGMT_DW15_SZU_MASK 0x000FU
#define SNAP_NVME_IOVA_MGMT_DW15_SZ_SHIFT 0x0004U
#define SNAP_NVME_IOVA_MGMT_DW15_SZ_MASK 0xFFFFFFF0U

static void init_iova_mgmt_cmd(struct nvme_command *cmd, unsigned int fid,
			       unsigned int opm, unsigned int szu,
			       unsigned int sz, u64 siova, u64 tiova)
{
	u32 dw10, dw11, dw12, dw13, dw14, dw15;

	dw10 = fid << SNAP_NVME_IOVA_MGMT_DW10_FID_SHIFT &
	       SNAP_NVME_IOVA_MGMT_DW10_FID_MASK;
	dw10 |= opm << SNAP_NVME_IOVA_MGMT_DW10_OPM_SHIFT &
		SNAP_NVME_IOVA_MGMT_DW10_OPM_MASK;
	dw11 = (u32)siova;
	dw12 = (u32)(siova >> 32);
	dw13 = (u32)tiova;
	dw14 = (u32)(tiova >> 32);
	dw15 = szu << SNAP_NVME_IOVA_MGMT_DW15_SZU_SHIFT &
	       SNAP_NVME_IOVA_MGMT_DW15_SZU_MASK;
	dw15 |= sz << SNAP_NVME_IOVA_MGMT_DW15_SZ_SHIFT &
		SNAP_NVME_IOVA_MGMT_DW15_SZ_MASK;

	cmd->common.opcode = SNAP_NVME_ADMIN_VENDOR_IOVA_MGMT;
	cmd->common.flags = 0;
	cmd->common.nsid = 0;
	cmd->common.metadata = 0;
	cmd->common.cdw2[0] = 0;
	cmd->common.cdw2[1] = 0;
	cmd->common.dptr.prp1 = 0;
	cmd->common.dptr.prp2 = 0;
	cmd->common.cdw10 = cpu_to_le32(dw10);
	cmd->common.cdw11 = cpu_to_le32(dw11);
	cmd->common.cdw12 = cpu_to_le32(dw12);
	cmd->common.cdw13 = cpu_to_le32(dw13);
	cmd->common.cdw14 = cpu_to_le32(dw14);
	cmd->common.cdw15 = cpu_to_le32(dw15);
}

static int mlx5_nvme_vfio_pci_notifier(struct notifier_block *nb,
				       unsigned long action, void *data)
{
	struct nvme_snap_notifier_block *snap_nb =
		container_of(nb, struct nvme_snap_notifier_block, nb);
	struct mlx5_nvme_vfio_pci_device *mvdev = snap_nb->mvdev;
	struct vfio_iommu_iova *iommu_iova;
	int fid = mvdev->vdev.pdev->is_physfn ?
				0 : (pci_iov_vf_id(mvdev->vdev.pdev) + 1);
	struct pci_dev *pdev;
	struct nvme_command cmd;
	int status;
	unsigned int opm;

	/* Vendor drivers MUST unpin pages in response to an invalidation. */
	if (action != VFIO_IOMMU_NOTIFY_IOVA_UNPIN &&
	    action != VFIO_IOMMU_NOTIFY_IOVA_PIN)
		return NOTIFY_DONE;

	pdev = mvdev->vdev.pdev->physfn;
	if (pdev) {
		iommu_iova = data;
		if (action == VFIO_IOMMU_NOTIFY_IOVA_UNPIN)
			opm = SNAP_NVME_IOVA_MGMT_OPM_UNMAP_RANGE;
		else
			opm = SNAP_NVME_IOVA_MGMT_OPM_MAP_RANGE;

		init_iova_mgmt_cmd(&cmd, fid, opm, 0,
				   iommu_iova->size / 0x1000U, iommu_iova->iova,
				   iommu_iova->phys);
		status = nvme_pdev_admin_passthru_sync(pdev, &cmd, NULL, 0, 0);
		if (!status)
			return NOTIFY_OK;
	}

	return NOTIFY_DONE;
}

static void
nvme_snap_unregister_efficient_notifier(struct mlx5_nvme_vfio_pci_device *mvdev)
{
	struct nvme_snap_notifier_block *nb = mvdev->nb;
	int fid = mvdev->vdev.pdev->is_physfn ?
				0 : (pci_iov_vf_id(mvdev->vdev.pdev) + 1);
	struct pci_dev *pdev;
	struct nvme_command cmd;

	vfio_unregister_notifier(mvdev->vdev.vdev.dev, VFIO_IOMMU_NOTIFY,
				 &nb->nb);
	kfree(nb);
	mvdev->nb = NULL;

	pdev = mvdev->vdev.pdev->physfn;
	if (pdev) {
		init_iova_mgmt_cmd(&cmd, fid,
				   SNAP_NVME_IOVA_MGMT_OPM_UNMAP_ALL_RANGES, 0,
				   0, 0, 0);
		nvme_pdev_admin_passthru_sync(pdev, &cmd, NULL, 0, 0);
	}
}

static int
nvme_snap_register_efficient_notifier(struct mlx5_nvme_vfio_pci_device *mvdev)
{
	struct nvme_snap_notifier_block *nb;
	unsigned long events;
	int ret;

	nb = kzalloc(sizeof(*nb), GFP_KERNEL);
	if (!nb)
		return -ENOMEM;

	mvdev->nb = nb;
	nb->mvdev = mvdev;

	events = VFIO_IOMMU_NOTIFY_IOVA_UNPIN | VFIO_IOMMU_NOTIFY_IOVA_PIN;
	nb->nb.notifier_call = mlx5_nvme_vfio_pci_notifier;
	ret = vfio_register_notifier(mvdev->vdev.vdev.dev, VFIO_IOMMU_NOTIFY,
				     &events, &nb->nb);
	if (ret)
		goto out_free;

	ret = vfio_notify_iova_map(mvdev->vdev.vdev.dev);
	if (ret)
		goto unregister;
	return 0;

unregister:
	vfio_unregister_notifier(mvdev->vdev.vdev.dev, VFIO_IOMMU_NOTIFY,
				 &nb->nb);
out_free:
	kfree(nb);
	mvdev->nb = NULL;
	return ret;
}

static int nvme_snap_vfio_pci_open_device(struct vfio_device *core_vdev)
{
	struct vfio_pci_core_device *vdev =
		container_of(core_vdev, struct vfio_pci_core_device, vdev);
	struct mlx5_nvme_vfio_pci_device *mvdev =
		container_of(vdev, struct mlx5_nvme_vfio_pci_device, vdev);
	int ret;

	ret = vfio_pci_core_enable(vdev);
	if (ret)
		return ret;

	vfio_pci_core_finish_enable(vdev);

	if (!mvdev->efficient_cap)
		goto out;

	ret = nvme_snap_register_efficient_notifier(mvdev);
	if (ret)
		goto out_err;

out:
	return 0;

out_err:
	vfio_pci_core_disable(vdev);
	return ret;
}

static void nvme_snap_vfio_pci_close_device(struct vfio_device *core_vdev)
{
	struct vfio_pci_core_device *vdev =
		container_of(core_vdev, struct vfio_pci_core_device, vdev);
	struct mlx5_nvme_vfio_pci_device *mvdev =
		container_of(vdev, struct mlx5_nvme_vfio_pci_device, vdev);

	if (mvdev->efficient_cap)
		nvme_snap_unregister_efficient_notifier(mvdev);

	vfio_pci_core_close_device(core_vdev);
}

static const struct vfio_device_ops mlx5_nvme_vfio_pci_ops = {
	.name			= "nvme-snap-vfio-pci",
	.open_device		= nvme_snap_vfio_pci_open_device,
	.close_device		= nvme_snap_vfio_pci_close_device,
	.ioctl			= vfio_pci_core_ioctl,
	.read			= vfio_pci_core_read,
	.write			= vfio_pci_core_write,
	.mmap			= vfio_pci_core_mmap,
	.request		= vfio_pci_core_request,
	.match			= vfio_pci_core_match,
};

static void init_identify_ctrl_cmd(struct nvme_command *cmd)
{
	cmd->identify.opcode = nvme_admin_identify;
	cmd->identify.cns = NVME_ID_CNS_CTRL;
}

static int nvme_snap_fill_caps(struct mlx5_nvme_vfio_pci_device *mvdev)
{
	struct nvme_command cmd = {};
	struct pci_dev *pdev;
	struct nvme_id_ctrl *id_ctrl;
	int ret;

	pdev = mvdev->vdev.pdev->physfn;
	if (!pdev)
		return 0;

	id_ctrl = kmalloc(sizeof(struct nvme_id_ctrl), GFP_KERNEL);
	if (!id_ctrl)
		return -ENOMEM;

	init_identify_ctrl_cmd(&cmd);
	ret = nvme_pdev_admin_passthru_sync(pdev, &cmd, id_ctrl,
					    sizeof(struct nvme_id_ctrl), 0);
	if (ret) {
		kfree(id_ctrl);
		return ret;
	}

	if ((le16_to_cpu(id_ctrl->immts) & NVME_IMMTS_UNMAP_RANGED) &&
	    (le16_to_cpu(id_ctrl->immts) & NVME_IMMTS_UNMAP_ALL) &&
	    id_ctrl->imms) {
		mvdev->efficient_cap = true;
		dev_info(&mvdev->vdev.pdev->dev, "Efficient DMA is supported");
	}

	kfree(id_ctrl);

	return 0;
}

static int mlx5_nvme_vfio_pci_probe(struct pci_dev *pdev,
				    const struct pci_device_id *id)
{
	struct mlx5_nvme_vfio_pci_device *mvdev;
	int ret;

	mvdev = kzalloc(sizeof(*mvdev), GFP_KERNEL);
	if (!mvdev)
		return -ENOMEM;

	vfio_pci_core_init_device(&mvdev->vdev, pdev, &mlx5_nvme_vfio_pci_ops);

	if (pdev->is_virtfn) {
		ret = nvme_snap_fill_caps(mvdev);
		if (ret)
			goto out_free;
	}

	ret = vfio_pci_core_register_device(&mvdev->vdev);
	if (ret)
		goto out_free;

	dev_set_drvdata(&pdev->dev, mvdev);

	return 0;

out_free:
	vfio_pci_core_uninit_device(&mvdev->vdev);
	kfree(mvdev);
	return ret;
}

static void mlx5_nvme_vfio_pci_remove(struct pci_dev *pdev)
{
	struct mlx5_nvme_vfio_pci_device *mvdev = dev_get_drvdata(&pdev->dev);

	if (mvdev->efficient_cap)
		WARN_ON(mvdev->nb);

	vfio_pci_core_unregister_device(&mvdev->vdev);
	vfio_pci_core_uninit_device(&mvdev->vdev);
	kfree(mvdev);
}

static const struct pci_device_id mlx5_nvme_vfio_pci_table[] = {
	{ PCI_DRIVER_OVERRIDE_DEVICE_VFIO(PCI_VENDOR_ID_MELLANOX, 0x6001) },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, mlx5_nvme_vfio_pci_table);

static struct pci_driver mlx5_nvme_vfio_pci_driver = {
	.name			= "nvme-snap-vfio-pci",
	.id_table		= mlx5_nvme_vfio_pci_table,
	.probe			= mlx5_nvme_vfio_pci_probe,
	.remove			= mlx5_nvme_vfio_pci_remove,
	.err_handler		= &vfio_pci_core_err_handlers,
};

static void __exit nvme_snap_vfio_pci_cleanup(void)
{
	pci_unregister_driver(&mlx5_nvme_vfio_pci_driver);
}

static int __init nvme_snap_vfio_pci_init(void)
{
	return pci_register_driver(&mlx5_nvme_vfio_pci_driver);
}

module_init(nvme_snap_vfio_pci_init);
module_exit(nvme_snap_vfio_pci_cleanup);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Max Gurtovoy <mgurtovoy@nvidia.com>");
MODULE_AUTHOR("Israel Rukshin <israelr@nvidia.com>");
MODULE_DESCRIPTION(
	"NVMe SNAP VFIO PCI - User Level meta-driver for Mellanox NVMe SNAP device family");
