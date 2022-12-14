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

int mlx5_ib_prefetch_mr(struct ib_mr *ibmr, u64 start, u64 length, u32 flags)
{
	struct mlx5_ib_mr  *mr  = to_mmr(ibmr);
	struct mlx5_ib_dev *dev = to_mdev(ibmr->device);
	u64 access_flags;
	int srcu_key;
	unsigned int current_seq;
	int expected_pages, npages, ret = 0;
	int retry;
	u64 idx, addr;
	int need_prefetch = 0;
	u64 end = start + length;

	/*
	 * Lock the SRCU to prevent destroying the MR while this function is
	 * running.
	 */
	srcu_key = srcu_read_lock(&dev->mr_srcu);

	/*
	 * Check that:
	 * - MR is a user space MR
	 * - MR is ODP MR
	 * - MR is not being destroyed (i.e. still in the mr tree)
	 */
	if (!mr->umem || !mr->umem->odp_data ||
	    !mlx5_ib_odp_find_mr_lkey(dev, ibmr->lkey) || !mr->ibmr.pd) {
		ret = -EINVAL;
		goto srcu_unlock;
	}

	start = max_t(u64, ib_umem_start(mr->umem), start);
	end = min_t(u64, ib_umem_end(mr->umem), end);

	if (start > end) {
		ret = -EINVAL;
		goto srcu_unlock;
	}

	access_flags = ((mr->umem->writable &&
			(flags & IB_ACCESS_LOCAL_WRITE)) ?
			(ODP_READ_ALLOWED_BIT | ODP_WRITE_ALLOWED_BIT) :
			ODP_READ_ALLOWED_BIT);

	for (addr = start; addr < end; addr += PAGE_SIZE) {
		idx = (addr - ib_umem_start(mr->umem)) / PAGE_SIZE;
		if ((mr->umem->odp_data->dma_list[idx] & access_flags) !=
		    access_flags) {
			need_prefetch = 1;
			break;
		}
	}

	if (!need_prefetch)
		goto srcu_unlock;

	for (retry = PREFETCH_MR_MAX_RETRIES; retry > 0; retry--) {
		current_seq = ACCESS_ONCE(mr->umem->odp_data->notifiers_seq);
		/*
		 * Ensure the sequence number is valid for some time before we call
		 * gup.
		 */
		smp_rmb();

		npages = ib_umem_odp_map_dma_pages(mr->umem, start, end - start,
						   access_flags, current_seq,
						   IB_ODP_DMA_MAP_FOR_PREFETCH);
		if (npages == -EAGAIN)
			continue;
		if (npages < 0) {
			ret = npages;
			goto srcu_unlock;
		}

		ret = -EAGAIN;
		if (npages > 0) {
			u64 start_idx = (start - (mr->mmkey.iova & PAGE_MASK)) >>
					PAGE_SHIFT;
			mutex_lock(&mr->umem->odp_data->umem_mutex);
			if (!ib_umem_mmu_notifier_retry(mr->umem, current_seq))
				/*
				 * No need to check whether the MTTs
				 * really belong to this MR, since
				 * ib_umem_odp_map_dma_pages already
				 * checks this.
				 */
				ret = mlx5_ib_update_mtt(mr, start_idx, npages,
							 0);
			mutex_unlock(&mr->umem->odp_data->umem_mutex);
			if (ret != -EAGAIN)
				break;
		}
	}
	if (ret) {
		if (ret == -EAGAIN)
			ret = 0;
		goto srcu_unlock;
	}

	expected_pages = (ALIGN(start + length, PAGE_SIZE) -
			 (start & PAGE_MASK)) >> PAGE_SHIFT;
	if (npages != -EAGAIN && npages < expected_pages)
		ret = -EFAULT;

srcu_unlock:
	srcu_read_unlock(&dev->mr_srcu, srcu_key);
	return ret;
}

int mlx5_ib_exp_odp_init_one(struct mlx5_ib_dev *ibdev)
{
	struct dentry *dbgfs_entry;

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

	return 0;
out_debugfs:
	debugfs_remove_recursive(ibdev->odp_stats.odp_debugfs);

	return -ENOMEM;
}
