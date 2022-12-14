/*
 * Copyright (c) 2013-2015, Mellanox Technologies. All rights reserved.
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

#include <rdma/ib_umem.h>
#include <rdma/ib_umem_odp.h>
#include <linux/debugfs.h>

#include "mlx5_ib.h"
#include "odp_exp.h"

struct mlx5_ib_prefetch_work {
	struct mlx5_ib_dev *dev;
	u32		   key;
	u64		   start;
	u64		   length;
	struct work_struct work;
};

int pagefault_single_data_segment(struct mlx5_ib_dev *dev,
				  u32 key, u64 io_virt, size_t bcnt,
				  u32 *bytes_committed,
				  u32 *bytes_mapped);

static void prefetch_work(struct work_struct *work)
{
	struct mlx5_ib_prefetch_work *pwork;
	u32 bytes_committed = 0;

	pwork = container_of(work, struct mlx5_ib_prefetch_work, work);
	pagefault_single_data_segment(pwork->dev, pwork->key, pwork->start,
				      pwork->length, &bytes_committed,
				      NULL);

	if (atomic_dec_and_test(&pwork->dev->num_prefetch))
		complete(&pwork->dev->comp_prefetch);
	kfree(pwork);
}

int mlx5_ib_prefetch_mr(struct ib_mr *ibmr, u64 start, u64 length, u32 flags)
{
	struct mlx5_ib_dev *dev = to_mdev(ibmr->device);
	struct mlx5_ib_prefetch_work *pwork;

	pwork = kmalloc(sizeof(*pwork), GFP_KERNEL);
	if (!pwork)
		return -ENOMEM;

	pwork->dev = dev;
	pwork->key = ibmr->lkey;
	pwork->start = start;
	pwork->length = length;

	atomic_inc(&dev->num_prefetch);

	INIT_WORK(&pwork->work, prefetch_work);
	schedule_work(&pwork->work);

	return 0;
}

int mlx5_ib_exp_odp_init_one(struct mlx5_ib_dev *ibdev)
{
	struct dentry *dbgfs_entry;

	if (ibdev->rep)
		return 0;

	ibdev->odp_stats.odp_debugfs = debugfs_create_dir("odp_stats",
						ibdev->mdev->priv.dbg_root);
	if (!ibdev->odp_stats.odp_debugfs)
		return -ENOMEM;

	dbgfs_entry = debugfs_create_atomic_t("num_odp_mrs", 0400,
					      ibdev->odp_stats.odp_debugfs,
					      &ibdev->odp_stats.num_odp_mrs);
	if (!dbgfs_entry)
		goto out_debugfs;

	dbgfs_entry = debugfs_create_atomic_t("num_odp_mr_pages", 0400,
					      ibdev->odp_stats.odp_debugfs,
					      &ibdev->odp_stats.num_odp_mr_pages);
	if (!dbgfs_entry)
		goto out_debugfs;

	dbgfs_entry = debugfs_create_atomic_t("num_mrs_not_found", 0400,
					      ibdev->odp_stats.odp_debugfs,
					      &ibdev->odp_stats.num_mrs_not_found);
	if (!dbgfs_entry)
		goto out_debugfs;

	dbgfs_entry = debugfs_create_atomic_t("num_failed_resolutions", 0400,
					      ibdev->odp_stats.odp_debugfs,
					      &ibdev->odp_stats.num_failed_resolutions);
	if (!dbgfs_entry)
		goto out_debugfs;

	dbgfs_entry = debugfs_create_atomic_t("num_prefetch", 0400,
					      ibdev->odp_stats.odp_debugfs,
					      &ibdev->num_prefetch);
	if (!dbgfs_entry)
		goto out_debugfs;

	return 0;
out_debugfs:
	debugfs_remove_recursive(ibdev->odp_stats.odp_debugfs);

	return -ENOMEM;
}
