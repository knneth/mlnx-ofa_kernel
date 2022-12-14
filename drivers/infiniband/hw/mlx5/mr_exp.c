/*
 * Copyright (c) 2016 Mellanox Technologies. All rights reserved.
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

#include <linux/slab.h>
#include "mlx5_ib.h"
#include <rdma/ib_cmem.h>

struct ib_mr *mlx5_ib_exp_alloc_mr(struct ib_pd *pd, struct ib_mr_init_attr *attr)
{

	if (attr->dm)
		return mlx5_ib_get_dm_mr(pd, attr);
	else
		return mlx5_ib_alloc_mr(pd, attr->mr_type, attr->max_num_sg);
}

struct ib_mr *mlx5_ib_exp_reg_user_mr(struct ib_pd *pd,
				      struct ib_mr_init_attr *attr,
				      struct ib_udata *udata,
				      int mr_id)
{
	return mlx5_ib_reg_user_mr(pd, attr,
				   udata,
				   mr_id);
}

struct ib_mr *mlx5_ib_reg_user_mr_wrp(struct ib_pd *pd, u64 start, u64 length,
				      u64 virt_addr, int access_flags,
				      struct ib_udata *udata)
{
	struct ib_mr_init_attr attr = {0};

	attr.start = start;
	attr.length = length;
	attr.hca_va = virt_addr;
	attr.access_flags = access_flags;

	return mlx5_ib_reg_user_mr(pd, &attr, udata, -1);
}

static int get_arg(unsigned long offset)
{
	return offset & ((1 << MLX5_IB_MMAP_CMD_SHIFT) - 1);
}

int get_pg_order(unsigned long offset)
{
	return get_arg(offset);
}

int mlx5_ib_exp_contig_mmap(struct ib_ucontext *ibcontext,
			    struct vm_area_struct *vma,
			    unsigned long  command)
{
	struct mlx5_ib_dev *dev = to_mdev(ibcontext->device);
	struct ib_cmem *ib_cmem;
	unsigned long total_size;
	unsigned long order;
	int err;
	int numa_node;

	if (command == MLX5_IB_EXP_MMAP_GET_CONTIGUOUS_PAGES_CPU_NUMA)
		numa_node = numa_node_id();
	else if (command == MLX5_IB_EXP_MMAP_GET_CONTIGUOUS_PAGES_DEV_NUMA)
		numa_node = dev_to_node(&dev->mdev->pdev->dev);
	else
		numa_node = -1;

	total_size = vma->vm_end - vma->vm_start;
	order = get_pg_order(vma->vm_pgoff);

	ib_cmem = ib_cmem_alloc_contiguous_pages(ibcontext, total_size,
						 order, numa_node);
	if (IS_ERR(ib_cmem))
		return PTR_ERR(ib_cmem);

	err = ib_cmem_map_contiguous_pages_to_vma(ib_cmem, vma);
	if (err) {
		ib_cmem_release_contiguous_pages(ib_cmem);
		return err;
	}

	return 0;
}

struct ib_mr *mlx5_ib_phys_addr(struct ib_pd *pd, u64 length, u64 start_addr,
				int access_flags)
{
#ifdef CONFIG_INFINIBAND_PA_MR
	return mlx5_ib_get_dma_mr_ex(pd, access_flags, start_addr, length);
#else
	pr_debug("Physical Address MR support wasn't compiled in"
		 "the RDMA subsystem. Recompile with Physical"
		 "Address MR\n");
	return ERR_PTR(-EOPNOTSUPP);
#endif /* CONFIG_INFINIBAND_PA_MR */
}

int mlx5_ib_exp_query_mkey(struct ib_mr *mr, u64 mkey_attr_mask,
			   struct ib_mkey_attr *mkey_attr)
{
	struct mlx5_ib_mr *mmr = to_mmr(mr);

	mkey_attr->max_reg_descriptors = mmr->max_descs;

	return 0;
}

struct ib_mr *mlx5_ib_get_memic_mr(struct ib_pd *pd, u64 memic_addr,
				   int acc, u64 length)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	int inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	struct mlx5_core_dev *mdev = dev->mdev;
	struct mlx5_ib_mr *mr;
	void *mkc;
	u32 *in;
	int err;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	in = kzalloc(inlen, GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_free;
	}

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);

	MLX5_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_MEMIC & 0x3);
	MLX5_SET(mkc, mkc, access_mode_4_2,
		 (MLX5_MKC_ACCESS_MODE_MEMIC >> 2) & 0x7);
	MLX5_SET(mkc, mkc, a, !!(acc & IB_ACCESS_REMOTE_ATOMIC));
	MLX5_SET(mkc, mkc, rw, !!(acc & IB_ACCESS_REMOTE_WRITE));
	MLX5_SET(mkc, mkc, rr, !!(acc & IB_ACCESS_REMOTE_READ));
	MLX5_SET(mkc, mkc, lw, !!(acc & IB_ACCESS_LOCAL_WRITE));
	MLX5_SET(mkc, mkc, lr, 1);

	MLX5_SET64(mkc, mkc, len, length);
	MLX5_SET(mkc, mkc, pd, to_mpd(pd)->pdn);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	MLX5_SET64(mkc, mkc, start_addr,
		   memic_addr - pci_resource_start(dev->mdev->pdev, 0));

	err = mlx5_core_create_mkey(mdev, &mr->mmkey, in, inlen);
	if (err)
		goto err_in;

	kfree(in);
	mr->ibmr.lkey = mr->mmkey.key;
	mr->ibmr.rkey = mr->mmkey.key;
	mr->umem = NULL;

	return &mr->ibmr;

err_in:
	kfree(in);

err_free:
	kfree(mr);

	return ERR_PTR(err);
}

struct ib_mr *mlx5_ib_get_dm_mr(struct ib_pd *pd,
			    struct ib_mr_init_attr *attr)
{
	struct ib_mr *mr;

	/* Registration of dm buffer is not allowed with certain
	 * access flags.
	 */
	if (attr->access_flags & ~MLX5_DM_ALLOWED_ACCESS)
		return ERR_PTR(-EINVAL);

	mr = mlx5_ib_get_memic_mr(pd, attr->dm->dev_addr + attr->start,
				  attr->access_flags, attr->length);

	return mr;
}

