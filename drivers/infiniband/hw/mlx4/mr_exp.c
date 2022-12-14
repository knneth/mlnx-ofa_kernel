#include <linux/slab.h>
#include <linux/proc_fs.h>
#include "mlx4_ib.h"

enum {
	MLX4_MAX_MTT_SHIFT		= 31
};

atomic64_t shared_mr_count = ATOMIC_INIT(0);
int mlx4_ib_umem_write_mtt_block(struct mlx4_ib_dev *dev,
						struct mlx4_mtt *mtt,
						u64 mtt_size,
						u64 mtt_shift,
						u64 len,
						u64 cur_start_addr,
						u64 *pages,
						int *start_index,
						int *npages)
{
	int k;
	int err = 0;
	u64 mtt_entries;
	u64 cur_end_addr = cur_start_addr + len;
	u64 cur_end_addr_aligned = 0;

	len += (cur_start_addr & (mtt_size-1ULL));
	cur_end_addr_aligned = round_up(cur_end_addr, mtt_size);
	len += (cur_end_addr_aligned - cur_end_addr);
	if (len & (mtt_size-1ULL)) {
		WARN(1 ,
		"write_block: len %llx is not aligned to mtt_size %llx\n",
			len, mtt_size);
		return -EINVAL;
	}


	mtt_entries = (len >> mtt_shift);

	/* Align the MTT start address to
		the mtt_size.
		Required to handle cases when the MR
		starts in the middle of an MTT record.
		Was not required in old code since
		the physical addresses provided by
		the dma subsystem were page aligned,
		which was also the MTT size.
	*/
	cur_start_addr = round_down(cur_start_addr, mtt_size);
	/* A new block is started ...*/
	for (k = 0; k < mtt_entries; ++k) {
		pages[*npages] = cur_start_addr + (mtt_size * k);
		(*npages)++;
		/*
		 * Be friendly to mlx4_write_mtt() and
		 * pass it chunks of appropriate size.
		 */
		if (*npages == PAGE_SIZE / sizeof(u64)) {
			err = mlx4_write_mtt(dev->dev,
					mtt, *start_index,
					*npages, pages);
			if (err)
				return err;

			(*start_index) += *npages;
			*npages = 0;
		}
	}

	return 0;
}

static inline u64 alignment_of(u64 ptr)
{
	return ilog2(ptr & (~(ptr-1)));
}

static int mlx4_ib_umem_calc_block_mtt(u64 next_block_start,
						u64 current_block_end,
						u64 block_shift)
{
	/* Check whether the alignment of the new block
	     is aligned as well as the previous block.
	     Block address must start with zeros till size of entity_size.
	*/
	if ((next_block_start & ((1ULL << block_shift) - 1ULL)) != 0)
		/* It is not as well aligned as the
		previous block-reduce the mtt size
		accordingly.
		Here we take the last right bit
		which is 1.
		*/
		block_shift = alignment_of(next_block_start);

	/*  Check whether the alignment of the
	     end of previous block - is it aligned
	     as well as the start of the block
	*/
	if (((current_block_end) & ((1ULL << block_shift) - 1ULL)) != 0)
		/* It is not as well aligned as
		the start of the block - reduce the
		mtt size accordingly.
		*/
		block_shift = alignment_of(current_block_end);

	return block_shift;
}

/* Calculate optimal mtt size based on contiguous pages.
* Function will return also the number of pages that are not aligned to the
   calculated mtt_size to be added to total number
    of pages. For that we should check the first chunk length & last chunk
    length and if not aligned to mtt_size we should increment
    the non_aligned_pages number.
    All chunks in the middle already handled as part of mtt shift calculation
    for both their start & end addresses.
*/
int mlx4_ib_umem_calc_optimal_mtt_size(struct ib_umem *umem,
						u64 start_va,
						int *num_of_mtts)
{
	u64 block_shift = MLX4_MAX_MTT_SHIFT;
	u64 current_block_len = 0;
	u64 current_block_start = 0;
	u64 misalignment_bits;
	u64 first_block_start = 0;
	u64 last_block_end = 0;
	u64 total_len = 0;
	u64 last_block_aligned_end = 0;
	u64 min_shift = umem->page_shift;
	struct scatterlist *sg;
	int i;
	u64 next_block_start;
	u64 current_block_end;

	for_each_sg(umem->sg_head.sgl, sg, umem->nmap, i) {
		/* Initialization - save the first chunk start as
		    the current_block_start - block means contiguous pages.
		*/
		if (current_block_len == 0 && current_block_start == 0) {
			first_block_start = current_block_start =
				sg_dma_address(sg);
			/* Find the bits that are different between
			    the physical address and the virtual
			    address for the start of the MR.
			*/
			/* umem_get aligned the start_va to a page
			   boundry. Therefore, we need to align the
			   start va to the same boundry */
			/* misalignment_bits is needed to handle the
			   case of a single memory region. In this
			   case, the rest of the logic will not reduce
			   the block size.  If we use a block size
			   which is bigger than the alignment of the
			   misalignment bits, we might use the virtual
			   page number instead of the physical page
			   number, resulting in access to the wrong
			   data. */
			misalignment_bits =
			(start_va & (~(((u64)(BIT(umem->page_shift)))-1ULL)))
						^ current_block_start;
			block_shift = min(alignment_of(misalignment_bits)
				, block_shift);
		}

		/* Go over the scatter entries and check
		     if they continue the previous scatter entry.
		*/
		next_block_start =
			sg_dma_address(sg);
		current_block_end = current_block_start
			+ current_block_len;
		/* If we have a split (non-contig.) between two block*/
		if (current_block_end != next_block_start) {
			block_shift = mlx4_ib_umem_calc_block_mtt(
					next_block_start,
					current_block_end,
					block_shift);

			/* If we reached the minimum shift for 4k
			     page we stop the loop.
			*/
			if (block_shift <= min_shift)
				goto end;

			/* If not saved yet we are in first block -
			     we save the length of first block to
			     calculate the non_aligned_pages number at
			*    the end.
			*/
			total_len += current_block_len;

			/* Start a new block */
			current_block_start = next_block_start;
			current_block_len =
				sg_dma_len(sg);
			continue;
		}
		/* The scatter entry is another part of
		     the current block, increase the block size
		* An entry in the scatter can be larger than
		4k (page) as of dma mapping
		which merge some blocks together.
		*/
		current_block_len +=
			sg_dma_len(sg);
	}

	/* Account for the last block in the total len */
	total_len += current_block_len;
	/* Add to the first block the misalignment that it suffers from.*/
	total_len += (first_block_start & ((1ULL<<block_shift)-1ULL));
	last_block_end = current_block_start+current_block_len;
	last_block_aligned_end = round_up(last_block_end, 1<<block_shift);
	total_len += (last_block_aligned_end - last_block_end);

	WARN((total_len & ((1ULL<<block_shift)-1ULL)),
		" misaligned total length detected (%llu, %llu)!",
		total_len, block_shift);

	*num_of_mtts = total_len >> block_shift;
end:
	if (block_shift < min_shift) {
		/* If shift is less than the min we set a WARN and
		     return the min shift.
		*/
		WARN(1,
		"mlx4_ib_umem_calc_optimal_mtt_size - unexpected shift %lld\n",
		block_shift);

		block_shift = min_shift;
	}
	return block_shift;

}

struct ib_mr *mlx4_ib_exp_reg_user_mr(struct ib_pd *pd,
				      struct ib_mr_init_attr *attr,
				      struct ib_udata *udata,
				      int mr_id)
{
	return mlx4_ib_reg_user_mr(pd, attr->start, attr->length,
				   attr->hca_va, attr->access_flags,
				   udata,
				   mr_id);
}

struct ib_mr *mlx4_ib_reg_user_mr_wrp(struct ib_pd *pd, u64 start, u64 length,
				      u64 virt_addr, int access_flags,
				      struct ib_udata *udata)
{
	return mlx4_ib_reg_user_mr(pd, start, length, virt_addr,
					access_flags, udata, -1);
}

static ssize_t shared_mr_proc_read(struct file *file, char __user *buffer,
				   size_t len, loff_t *offset)
{
	return -ENOSYS;
}

static ssize_t shared_mr_proc_write(struct file *file, const char __user *buffer,
				    size_t len, loff_t *offset)
{
	return -ENOSYS;
}

static int shared_mr_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct mlx4_shared_mr_info *smr_info =
		(struct mlx4_shared_mr_info *)PDE_DATA(filep->f_path.dentry->d_inode);

	/* Prevent any mapping not on start of area */
	if (vma->vm_pgoff != 0)
		return -EINVAL;

	return ib_umem_map_to_vma(smr_info->umem,
					vma);
}

static const struct file_operations shared_mr_proc_ops = {
	.owner	= THIS_MODULE,
	.read	= shared_mr_proc_read,
	.write	= shared_mr_proc_write,
	.mmap	= shared_mr_mmap
};

static mode_t convert_shared_access(int acc)
{
	return (acc & IB_EXP_ACCESS_SHARED_MR_USER_READ ? S_IRUSR       : 0) |
	       (acc & IB_EXP_ACCESS_SHARED_MR_USER_WRITE  ? S_IWUSR : 0) |
	       (acc & IB_EXP_ACCESS_SHARED_MR_GROUP_READ   ? S_IRGRP  : 0) |
	       (acc & IB_EXP_ACCESS_SHARED_MR_GROUP_WRITE   ? S_IWGRP  : 0) |
	       (acc & IB_EXP_ACCESS_SHARED_MR_OTHER_READ   ? S_IROTH  : 0) |
	       (acc & IB_EXP_ACCESS_SHARED_MR_OTHER_WRITE   ? S_IWOTH  : 0);
}

int prepare_shared_mr(struct mlx4_ib_mr *mr, int access_flags, int mr_id)
{
	struct proc_dir_entry *mr_proc_entry;
	mode_t mode = S_IFREG;
	char name_buff[128];
	kuid_t uid;
	kgid_t gid;

	/* start address and length must be aligned to page size in order
	  * to map a full page and preventing leakage of data.
	  */
	if (ib_umem_offset(mr->umem) || (mr->umem->length & ~PAGE_MASK))
		return -EINVAL;

	mode |= convert_shared_access(access_flags);
	sprintf(name_buff, "%X", mr_id);
	mr->smr_info = kzalloc(sizeof(*mr->smr_info), GFP_KERNEL);
	mr->smr_info->mr_id = mr_id;
	mr->smr_info->umem = mr->umem;

	mr_proc_entry = proc_create_data(name_buff, mode,
					 mlx4_mrs_dir_entry,
					 &shared_mr_proc_ops,
					 mr->smr_info);

	if (!mr_proc_entry) {
		pr_err("prepare_shared_mr failed via proc\n");
		kfree(mr->smr_info);
		return -ENODEV;
	}

	current_uid_gid(&uid, &gid);
	proc_set_user(mr_proc_entry, uid, gid);
	proc_set_size(mr_proc_entry, mr->umem->length);

	/* now creating an extra entry having a uniqe suffix counter */
	mr->smr_info->counter = atomic64_inc_return(&shared_mr_count);
	sprintf(name_buff, "%X.%lld", mr_id, mr->smr_info->counter);
	mr_proc_entry = proc_create_data(name_buff, mode,
					 mlx4_mrs_dir_entry,
					 &shared_mr_proc_ops,
					 mr->smr_info);
	if (!mr_proc_entry) {
		pr_err("prepare_shared_mr failed via proc for %s\n", name_buff);
		free_smr_info(mr);
		return -ENODEV;
	}

	mr->smr_info->counter_used = 1;
	proc_set_user(mr_proc_entry, uid, gid);
	proc_set_size(mr_proc_entry, mr->umem->length);

	return 0;
}

int is_shared_mr(int access_flags)
{
	/* We should check whether IB_EXP_ACCESS_SHARED_MR_USER_READ or
	 * other shared bits were turned on.
	 */
	return !!(access_flags & (IB_EXP_ACCESS_SHARED_MR_USER_READ |
				IB_EXP_ACCESS_SHARED_MR_USER_WRITE |
				IB_EXP_ACCESS_SHARED_MR_GROUP_READ |
				IB_EXP_ACCESS_SHARED_MR_GROUP_WRITE |
				IB_EXP_ACCESS_SHARED_MR_OTHER_READ |
				IB_EXP_ACCESS_SHARED_MR_OTHER_WRITE));
}

void free_smr_info(struct mlx4_ib_mr *mr)
{
	/* When master/parent shared mr is dereged there is
	 * no ability to share this mr any more - its mr_id will be
	 * returned to the kernel as part of ib_uverbs_dereg_mr
	 * and may be allocated again as part of other reg_mr.
	 */
	char name_buff[128];

	sprintf(name_buff, "%X", mr->smr_info->mr_id);
	/* Remove proc entry is checking internally that no operation
	 * was strated on that proc fs file and if in the middle
	 * current process will wait till end of operation.
	 * That's why no sync mechanism is needed when we release
	 * below the shared umem.
	 */
	remove_proc_entry(name_buff, mlx4_mrs_dir_entry);
	if (mr->smr_info->counter_used) {
		sprintf(name_buff, "%X.%lld", mr->smr_info->mr_id,
			mr->smr_info->counter);
		remove_proc_entry(name_buff, mlx4_mrs_dir_entry);
	}

	kfree(mr->smr_info);
	mr->smr_info = NULL;
}

struct ib_mr *mlx4_ib_phys_addr(struct ib_pd *pd, u64 length, u64 virt_addr,
				int access_flags)
{
#ifdef CONFIG_INFINIBAND_PA_MR
	if (virt_addr || length)
		return ERR_PTR(-EINVAL);

	return pd->device->get_dma_mr(pd, access_flags);
#else
	pr_debug("Physical Address MR support wasn't compiled in"
		 "the RDMA subsystem. Recompile with Physical"
		 "Address MR\n");
	return ERR_PTR(-EOPNOTSUPP);
#endif /* CONFIG_INFINIBAND_PA_MR */
}
