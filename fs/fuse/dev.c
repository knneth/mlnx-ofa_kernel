/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "dev_uring_i.h"
#include "fuse_i.h"
#include "fuse_dev_i.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/sched/signal.h>
#include <linux/uio.h>
#include <linux/miscdevice.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/pipe_fs_i.h>
#include <linux/swap.h>
#include <linux/splice.h>
#include <linux/sched.h>

void fuse_set_initialized(struct fuse_conn *fc)
{
	/* Make sure stores before this are seen on another CPU */
	smp_wmb();
	fc->initialized = 1;
	if (fc->init)
		fc->init(fc);

}

void fuse_creds(struct fuse_req *req)
{
	struct fuse_conn *fc = req->fm->fc;

	if (!req->fm->sb || req->fm->sb->s_iflags & SB_I_NOIDMAP) {
		req->in.h.uid = from_kuid(fc->user_ns, current_fsuid());
		req->in.h.gid = from_kgid(fc->user_ns, current_fsgid());
	} else {
		req->in.h.uid = FUSE_INVALID_UIDGID;
		req->in.h.gid = FUSE_INVALID_UIDGID;
	}

	req->in.h.pid = pid_nr_ns(task_pid(current), fc->pid_ns);
}

unsigned int fuse_len_args(unsigned int numargs, struct fuse_arg *args)
{
	unsigned nbytes = 0;
	unsigned i;

	for (i = 0; i < numargs; i++)
		nbytes += args[i].size;

	return nbytes;
}

void fuse_queue_forget(struct fuse_mount *fm, struct fuse_forget_link *forget,
		       u64 nodeid, u64 nlookup)
{
	forget->forget_one.nodeid = nodeid;
	forget->forget_one.nlookup = nlookup;

	if (fm->forget_send) {
		fm->forget_send(fm, forget);
	} else {
		struct fuse_iqueue *fiq = &fm->fc->iq;

		fiq->ops->send_forget(fiq, forget);
	}
}

void fuse_adjust_compat(struct fuse_conn *fc, struct fuse_args *args)
{
	if (fc->minor < 4 && args->opcode == FUSE_STATFS)
		args->out_args[0].size = FUSE_COMPAT_STATFS_SIZE;

	if (fc->minor < 9) {
		switch (args->opcode) {
		case FUSE_LOOKUP:
		case FUSE_CREATE:
		case FUSE_MKNOD:
		case FUSE_MKDIR:
		case FUSE_SYMLINK:
		case FUSE_LINK:
			args->out_args[0].size = FUSE_COMPAT_ENTRY_OUT_SIZE;
			break;
		case FUSE_GETATTR:
		case FUSE_SETATTR:
			args->out_args[0].size = FUSE_COMPAT_ATTR_OUT_SIZE;
			break;
		}
	}
	if (fc->minor < 12) {
		switch (args->opcode) {
		case FUSE_CREATE:
			args->in_args[0].size = sizeof(struct fuse_open_in);
			break;
		case FUSE_MKNOD:
			args->in_args[0].size = FUSE_COMPAT_MKNOD_IN_SIZE;
			break;
		}
	}
}

void fuse_force_creds(struct fuse_req *req)
{
	struct fuse_conn *fc = req->fm->fc;

	if (!req->fm->sb || req->fm->sb->s_iflags & SB_I_NOIDMAP) {
		req->in.h.uid = from_kuid_munged(fc->user_ns, current_fsuid());
		req->in.h.gid = from_kgid_munged(fc->user_ns, current_fsgid());
	} else {
		req->in.h.uid = FUSE_INVALID_UIDGID;
		req->in.h.gid = FUSE_INVALID_UIDGID;
	}

	req->in.h.pid = pid_nr_ns(task_pid(current), fc->pid_ns);
}

void fuse_args_to_req(struct fuse_req *req, struct fuse_args *args)
{
	req->in.h.opcode = args->opcode;
	req->in.h.nodeid = args->nodeid;
	req->args = args;
	if (args->is_ext)
		req->in.h.total_extlen = args->in_args[args->ext_idx].size / 8;
	if (args->end)
		__set_bit(FR_ASYNC, &req->flags);
}

ssize_t __fuse_simple_request(struct mnt_idmap *idmap,
			      struct fuse_mount *fm,
			      struct fuse_args *args)
{
	if (fm->simple_request)
		return fm->simple_request(fm, args);

	return -EINVAL;
}

#ifdef CONFIG_FUSE_IO_URING
static bool fuse_request_queue_background_uring(struct fuse_conn *fc,
					       struct fuse_req *req)
{
	struct fuse_iqueue *fiq = &fc->iq;

	req->in.h.unique = fuse_get_unique(fiq);
	req->in.h.len = sizeof(struct fuse_in_header) +
		fuse_len_args(req->args->in_numargs,
			      (struct fuse_arg *) req->args->in_args);

	return fuse_uring_queue_bq_req(req);
}
#endif

int fuse_simple_background(struct fuse_mount *fm, struct fuse_args *args,
			    gfp_t gfp_flags)
{
	if (fm->simple_background)
		return fm->simple_background(fm, args, gfp_flags);

	return 0;
}

static int fuse_simple_notify_reply(struct fuse_mount *fm,
				    struct fuse_args *args, u64 unique)
{

	if (fm->simple_notify_reply)
		return fm->simple_notify_reply(fm, args, unique);

	return -EINVAL;
}

/*
 * Lock the request.  Up to the next unlock_request() there mustn't be
 * anything that could cause a page-fault.  If the request was already
 * aborted bail out.
 */
static int lock_request(struct fuse_req *req)
{
	int err = 0;
	if (req) {
		spin_lock(&req->waitq.lock);
		if (test_bit(FR_ABORTED, &req->flags))
			err = -ENOENT;
		else
			set_bit(FR_LOCKED, &req->flags);
		spin_unlock(&req->waitq.lock);
	}
	return err;
}

/*
 * Unlock request.  If it was aborted while locked, caller is responsible
 * for unlocking and ending the request.
 */
static int unlock_request(struct fuse_req *req)
{
	int err = 0;
	if (req) {
		spin_lock(&req->waitq.lock);
		if (test_bit(FR_ABORTED, &req->flags))
			err = -ENOENT;
		else
			clear_bit(FR_LOCKED, &req->flags);
		spin_unlock(&req->waitq.lock);
	}
	return err;
}

void fuse_copy_init(struct fuse_copy_state *cs, int write,
		    struct iov_iter *iter)
{
	memset(cs, 0, sizeof(*cs));
	cs->write = write;
	cs->iter = iter;
}

/* Unmap and put previous page of userspace buffer */
static void fuse_copy_finish(struct fuse_copy_state *cs)
{
	if (cs->mapped)
		return;

	if (cs->currbuf) {
		struct pipe_buffer *buf = cs->currbuf;

		if (cs->write)
			buf->len = PAGE_SIZE - cs->len;
		cs->currbuf = NULL;
	} else if (cs->pg) {
		if (cs->write) {
			flush_dcache_page(cs->pg);
			set_page_dirty_lock(cs->pg);
		}
		put_page(cs->pg);
	}
	cs->pg = NULL;
}

/*
 * Get another pagefull of userspace buffer, and map it to kernel
 * address space, and lock request
 */
static int fuse_copy_fill(struct fuse_copy_state *cs)
{
	struct page *page;
	int err;

	err = unlock_request(cs->req);
	if (err)
		return err;

	fuse_copy_finish(cs);
	if (cs->pipebufs) {
		struct pipe_buffer *buf = cs->pipebufs;

		if (!cs->write) {
			err = pipe_buf_confirm(cs->pipe, buf);
			if (err)
				return err;

			BUG_ON(!cs->nr_segs);
			cs->currbuf = buf;
			cs->pg = buf->page;
			cs->offset = buf->offset;
			cs->len = buf->len;
			cs->pipebufs++;
			cs->nr_segs--;
		} else {
			if (cs->nr_segs >= cs->pipe->max_usage)
				return -EIO;

			page = alloc_page(GFP_HIGHUSER);
			if (!page)
				return -ENOMEM;

			buf->page = page;
			buf->offset = 0;
			buf->len = 0;

			cs->currbuf = buf;
			cs->pg = page;
			cs->offset = 0;
			cs->len = PAGE_SIZE;
			cs->pipebufs++;
			cs->nr_segs++;
		}
	} else {
		size_t off;
		err = iov_iter_get_pages2(cs->iter, &page, PAGE_SIZE, 1, &off);
		if (err < 0)
			return err;
		BUG_ON(!err);
		cs->len = err;
		cs->offset = off;
		cs->pg = page;
	}

	return lock_request(cs->req);
}

/* Do as much copy to/from userspace buffer as we can */
static int fuse_copy_do(struct fuse_copy_state *cs, void **val, unsigned *size)
{
	unsigned ncpy = min(*size, cs->len);

	if (val) {
		if (cs->mapped) {
			unsigned len;

			len = copy_from_iter(*val, ncpy, cs->iter);
			if (len != ncpy)
				pr_err("fuse: copy_from_iter() failed\n");
			ncpy = len;
		} else {
			void *pgaddr = kmap_local_page(cs->pg);
			void *buf = pgaddr + cs->offset;

			if (cs->write)
				memcpy(buf, *val, ncpy);
			else
				memcpy(*val, buf, ncpy);

			kunmap_local(pgaddr);
		}
		*val += ncpy;
	}
	*size -= ncpy;
	cs->len -= ncpy;
	cs->offset += ncpy;
	if (cs->is_uring)
		cs->ring.copied_sz += ncpy;

	return ncpy;
}

static int fuse_check_folio(struct folio *folio)
{
	if (folio_mapped(folio) ||
	    folio->mapping != NULL ||
	    (folio->flags & PAGE_FLAGS_CHECK_AT_PREP &
	     ~(1 << PG_locked |
	       1 << PG_referenced |
	       1 << PG_lru |
	       1 << PG_active |
	       1 << PG_workingset |
	       1 << PG_reclaim |
	       1 << PG_waiters |
	       LRU_GEN_MASK | LRU_REFS_MASK))) {
		dump_page(&folio->page, "fuse: trying to steal weird page");
		return 1;
	}
	return 0;
}

/*
 * Attempt to steal a page from the splice() pipe and move it into the
 * pagecache. If successful, the pointer in @pagep will be updated. The
 * folio that was originally in @pagep will lose a reference and the new
 * folio returned in @pagep will carry a reference.
 */
static int fuse_try_move_page(struct fuse_copy_state *cs, struct page **pagep)
{
	int err;
	struct folio *oldfolio = page_folio(*pagep);
	struct folio *newfolio;
	struct pipe_buffer *buf = cs->pipebufs;

	folio_get(oldfolio);
	err = unlock_request(cs->req);
	if (err)
		goto out_put_old;

	fuse_copy_finish(cs);

	err = pipe_buf_confirm(cs->pipe, buf);
	if (err)
		goto out_put_old;

	BUG_ON(!cs->nr_segs);
	cs->currbuf = buf;
	cs->len = buf->len;
	cs->pipebufs++;
	cs->nr_segs--;

	if (cs->len != PAGE_SIZE)
		goto out_fallback;

	if (!pipe_buf_try_steal(cs->pipe, buf))
		goto out_fallback;

	newfolio = page_folio(buf->page);

	folio_clear_uptodate(newfolio);
	folio_clear_mappedtodisk(newfolio);

	if (fuse_check_folio(newfolio) != 0)
		goto out_fallback_unlock;

	/*
	 * This is a new and locked page, it shouldn't be mapped or
	 * have any special flags on it
	 */
	if (WARN_ON(folio_mapped(oldfolio)))
		goto out_fallback_unlock;
	if (WARN_ON(folio_has_private(oldfolio)))
		goto out_fallback_unlock;
	if (WARN_ON(folio_test_dirty(oldfolio) ||
				folio_test_writeback(oldfolio)))
		goto out_fallback_unlock;
	if (WARN_ON(folio_test_mlocked(oldfolio)))
		goto out_fallback_unlock;

	replace_page_cache_folio(oldfolio, newfolio);

	folio_get(newfolio);

	if (!(buf->flags & PIPE_BUF_FLAG_LRU))
		folio_add_lru(newfolio);

	/*
	 * Release while we have extra ref on stolen page.  Otherwise
	 * anon_pipe_buf_release() might think the page can be reused.
	 */
	pipe_buf_release(cs->pipe, buf);

	err = 0;
	spin_lock(&cs->req->waitq.lock);
	if (test_bit(FR_ABORTED, &cs->req->flags))
		err = -ENOENT;
	else
		*pagep = &newfolio->page;
	spin_unlock(&cs->req->waitq.lock);

	if (err) {
		folio_unlock(newfolio);
		folio_put(newfolio);
		goto out_put_old;
	}

	folio_unlock(oldfolio);
	/* Drop ref for ap->pages[] array */
	folio_put(oldfolio);
	cs->len = 0;

	err = 0;
out_put_old:
	/* Drop ref obtained in this function */
	folio_put(oldfolio);
	return err;

out_fallback_unlock:
	folio_unlock(newfolio);
out_fallback:
	cs->pg = buf->page;
	cs->offset = buf->offset;

	err = lock_request(cs->req);
	if (!err)
		err = 1;

	goto out_put_old;
}

static int fuse_ref_page(struct fuse_copy_state *cs, struct page *page,
			 unsigned offset, unsigned count)
{
	struct pipe_buffer *buf;
	int err;

	if (cs->nr_segs >= cs->pipe->max_usage)
		return -EIO;

	get_page(page);
	err = unlock_request(cs->req);
	if (err) {
		put_page(page);
		return err;
	}

	fuse_copy_finish(cs);

	buf = cs->pipebufs;
	buf->page = page;
	buf->offset = offset;
	buf->len = count;

	cs->pipebufs++;
	cs->nr_segs++;
	cs->len = 0;

	return 0;
}

/*
 * Copy a page in the request to/from the userspace buffer.  Must be
 * done atomically
 */
static int fuse_copy_page(struct fuse_copy_state *cs, struct page **pagep,
			  unsigned offset, unsigned count, int zeroing)
{
	int err;
	struct page *page = *pagep;

	if (page && zeroing && count < PAGE_SIZE)
		clear_highpage(page);

	while (count) {
		if (cs->write && cs->pipebufs && page) {
			/*
			 * Can't control lifetime of pipe buffers, so always
			 * copy user pages.
			 */
			if (cs->req->args->user_pages) {
				err = fuse_copy_fill(cs);
				if (err)
					return err;
			} else {
				return fuse_ref_page(cs, page, offset, count);
			}
		} else if (!cs->len) {
			if (cs->move_pages && page &&
			    offset == 0 && count == PAGE_SIZE) {
				err = fuse_try_move_page(cs, pagep);
				if (err <= 0)
					return err;
			} else {
				err = fuse_copy_fill(cs);
				if (err)
					return err;
			}
		}
		if (page) {
			void *mapaddr = kmap_local_page(page);
			void *buf = mapaddr + offset;
			offset += fuse_copy_do(cs, &buf, &count);
			kunmap_local(mapaddr);
		} else
			offset += fuse_copy_do(cs, NULL, &count);
	}
	if (page && !cs->write)
		flush_dcache_page(page);
	return 0;
}

/* Copy a single argument in the request to/from userspace buffer */
static int fuse_copy_one(struct fuse_copy_state *cs, void *val, unsigned size)
{
	while (size) {
		if (!cs->len) {
			int err = fuse_copy_fill(cs);
			if (err)
				return err;
		}
		fuse_copy_do(cs, &val, &size);
	}
	return 0;
}

static int fuse_notify_poll(struct fuse_conn *fc, unsigned int size,
			    struct fuse_copy_state *cs)
{
	struct fuse_notify_poll_wakeup_out outarg;
	int err = -EINVAL;

	if (size != sizeof(outarg))
		goto err;

	err = fuse_copy_one(cs, &outarg, sizeof(outarg));
	if (err)
		goto err;

	fuse_copy_finish(cs);
	return fuse_notify_poll_wakeup(fc, &outarg);

err:
	fuse_copy_finish(cs);
	return err;
}

static int fuse_notify_inval_inode(struct fuse_conn *fc, unsigned int size,
				   struct fuse_copy_state *cs)
{
	struct fuse_notify_inval_inode_out outarg;
	int err = -EINVAL;

	if (size != sizeof(outarg))
		goto err;

	err = fuse_copy_one(cs, &outarg, sizeof(outarg));
	if (err)
		goto err;
	fuse_copy_finish(cs);

	down_read(&fc->killsb);
	err = fuse_reverse_inval_inode(fc, outarg.ino,
				       outarg.off, outarg.len);
	up_read(&fc->killsb);
	return err;

err:
	fuse_copy_finish(cs);
	return err;
}

static int fuse_notify_inval_entry(struct fuse_conn *fc, unsigned int size,
				   struct fuse_copy_state *cs)
{
	struct fuse_notify_inval_entry_out outarg;
	int err = -ENOMEM;
	char *buf;
	struct qstr name;

	buf = kzalloc(FUSE_NAME_MAX + 1, GFP_KERNEL);
	if (!buf)
		goto err;

	err = -EINVAL;
	if (size < sizeof(outarg))
		goto err;

	err = fuse_copy_one(cs, &outarg, sizeof(outarg));
	if (err)
		goto err;

	err = -ENAMETOOLONG;
	if (outarg.namelen > FUSE_NAME_MAX)
		goto err;

	err = -EINVAL;
	if (size != sizeof(outarg) + outarg.namelen + 1)
		goto err;

	name.name = buf;
	name.len = outarg.namelen;
	err = fuse_copy_one(cs, buf, outarg.namelen + 1);
	if (err)
		goto err;
	fuse_copy_finish(cs);
	buf[outarg.namelen] = 0;

	down_read(&fc->killsb);
	err = fuse_reverse_inval_entry(fc, outarg.parent, 0, &name, outarg.flags);
	up_read(&fc->killsb);
	kfree(buf);
	return err;

err:
	kfree(buf);
	fuse_copy_finish(cs);
	return err;
}

static int fuse_notify_delete(struct fuse_conn *fc, unsigned int size,
			      struct fuse_copy_state *cs)
{
	struct fuse_notify_delete_out outarg;
	int err = -ENOMEM;
	char *buf;
	struct qstr name;

	buf = kzalloc(FUSE_NAME_MAX + 1, GFP_KERNEL);
	if (!buf)
		goto err;

	err = -EINVAL;
	if (size < sizeof(outarg))
		goto err;

	err = fuse_copy_one(cs, &outarg, sizeof(outarg));
	if (err)
		goto err;

	err = -ENAMETOOLONG;
	if (outarg.namelen > FUSE_NAME_MAX)
		goto err;

	err = -EINVAL;
	if (size != sizeof(outarg) + outarg.namelen + 1)
		goto err;

	name.name = buf;
	name.len = outarg.namelen;
	err = fuse_copy_one(cs, buf, outarg.namelen + 1);
	if (err)
		goto err;
	fuse_copy_finish(cs);
	buf[outarg.namelen] = 0;

	down_read(&fc->killsb);
	err = fuse_reverse_inval_entry(fc, outarg.parent, outarg.child, &name, 0);
	up_read(&fc->killsb);
	kfree(buf);
	return err;

err:
	kfree(buf);
	fuse_copy_finish(cs);
	return err;
}

static int fuse_notify_store(struct fuse_conn *fc, unsigned int size,
			     struct fuse_copy_state *cs)
{
	struct fuse_notify_store_out outarg;
	struct inode *inode;
	struct address_space *mapping;
	u64 nodeid;
	int err;
	pgoff_t index;
	unsigned int offset;
	unsigned int num;
	loff_t file_size;
	loff_t end;

	err = -EINVAL;
	if (size < sizeof(outarg))
		goto out_finish;

	err = fuse_copy_one(cs, &outarg, sizeof(outarg));
	if (err)
		goto out_finish;

	err = -EINVAL;
	if (size - sizeof(outarg) != outarg.size)
		goto out_finish;

	nodeid = outarg.nodeid;

	down_read(&fc->killsb);

	err = -ENOENT;
	inode = fuse_ilookup(fc, nodeid,  NULL);
	if (!inode)
		goto out_up_killsb;

	mapping = inode->i_mapping;
	index = outarg.offset >> PAGE_SHIFT;
	offset = outarg.offset & ~PAGE_MASK;
	file_size = i_size_read(inode);
	end = outarg.offset + outarg.size;
	if (end > file_size) {
		file_size = end;
		fuse_write_update_attr(inode, file_size, outarg.size);
	}

	num = outarg.size;
	while (num) {
		struct folio *folio;
		struct page *page;
		unsigned int this_num;

		folio = filemap_grab_folio(mapping, index);
		err = PTR_ERR(folio);
		if (IS_ERR(folio))
			goto out_iput;

		page = &folio->page;
		this_num = min_t(unsigned, num, folio_size(folio) - offset);
		err = fuse_copy_page(cs, &page, offset, this_num, 0);
		if (!folio_test_uptodate(folio) && !err && offset == 0 &&
		    (this_num == folio_size(folio) || file_size == end)) {
			folio_zero_segment(folio, this_num, folio_size(folio));
			folio_mark_uptodate(folio);
		}
		folio_unlock(folio);
		folio_put(folio);

		if (err)
			goto out_iput;

		num -= this_num;
		offset = 0;
		index++;
	}

	err = 0;

out_iput:
	iput(inode);
out_up_killsb:
	up_read(&fc->killsb);
out_finish:
	fuse_copy_finish(cs);
	return err;
}

struct fuse_retrieve_args {
	struct fuse_args_pages ap;
	struct fuse_notify_retrieve_in inarg;
};

static void fuse_retrieve_end(struct fuse_mount *fm, struct fuse_args *args,
			      int error)
{
	struct fuse_retrieve_args *ra =
		container_of(args, typeof(*ra), ap.args);

	release_pages(ra->ap.folios, ra->ap.num_folios);
	kfree(ra);
}

static int fuse_retrieve(struct fuse_mount *fm, struct inode *inode,
			 struct fuse_notify_retrieve_out *outarg)
{
	int err;
	struct address_space *mapping = inode->i_mapping;
	pgoff_t index;
	loff_t file_size;
	unsigned int num;
	unsigned int offset;
	size_t total_len = 0;
	unsigned int num_pages, cur_pages = 0;
	struct fuse_conn *fc = fm->fc;
	struct fuse_retrieve_args *ra;
	size_t args_size = sizeof(*ra);
	struct fuse_args_pages *ap;
	struct fuse_args *args;

	offset = outarg->offset & ~PAGE_MASK;
	file_size = i_size_read(inode);

	num = min(outarg->size, fc->max_write);
	if (outarg->offset > file_size)
		num = 0;
	else if (outarg->offset + num > file_size)
		num = file_size - outarg->offset;

	num_pages = (num + offset + PAGE_SIZE - 1) >> PAGE_SHIFT;
	num_pages = min(num_pages, fc->max_pages);

	args_size += num_pages * (sizeof(ap->folios[0]) + sizeof(ap->descs[0]));

	ra = kzalloc(args_size, GFP_KERNEL);
	if (!ra)
		return -ENOMEM;

	ap = &ra->ap;
	ap->folios = (void *) (ra + 1);
	ap->descs = (void *) (ap->folios + num_pages);

	args = &ap->args;
	args->nodeid = outarg->nodeid;
	args->opcode = FUSE_NOTIFY_REPLY;
	args->in_numargs = 3;
	args->in_pages = true;
	args->end = fuse_retrieve_end;

	index = outarg->offset >> PAGE_SHIFT;

	while (num && cur_pages < num_pages) {
		struct folio *folio;
		unsigned int this_num;

		folio = filemap_get_folio(mapping, index);
		if (IS_ERR(folio))
			break;

		this_num = min_t(unsigned, num, PAGE_SIZE - offset);
		ap->folios[ap->num_folios] = folio;
		ap->descs[ap->num_folios].offset = offset;
		ap->descs[ap->num_folios].length = this_num;
		ap->num_folios++;
		cur_pages++;

		offset = 0;
		num -= this_num;
		total_len += this_num;
		index++;
	}
	ra->inarg.offset = outarg->offset;
	ra->inarg.size = total_len;
	fuse_set_zero_arg0(args);
	args->in_args[1].size = sizeof(ra->inarg);
	args->in_args[1].value = &ra->inarg;
	args->in_args[2].size = total_len;

	err = fuse_simple_notify_reply(fm, args, outarg->notify_unique);
	if (err)
		fuse_retrieve_end(fm, args, err);

	return err;
}

static int fuse_notify_retrieve(struct fuse_conn *fc, unsigned int size,
				struct fuse_copy_state *cs)
{
	struct fuse_notify_retrieve_out outarg;
	struct fuse_mount *fm;
	struct inode *inode;
	u64 nodeid;
	int err;

	err = -EINVAL;
	if (size != sizeof(outarg))
		goto copy_finish;

	err = fuse_copy_one(cs, &outarg, sizeof(outarg));
	if (err)
		goto copy_finish;

	fuse_copy_finish(cs);

	down_read(&fc->killsb);
	err = -ENOENT;
	nodeid = outarg.nodeid;

	inode = fuse_ilookup(fc, nodeid, &fm);
	if (inode) {
		err = fuse_retrieve(fm, inode, &outarg);
		iput(inode);
	}
	up_read(&fc->killsb);

	return err;

copy_finish:
	fuse_copy_finish(cs);
	return err;
}

/*
 * Resending all processing queue requests.
 *
 * During a FUSE daemon panics and failover, it is possible for some inflight
 * requests to be lost and never returned. As a result, applications awaiting
 * replies would become stuck forever. To address this, we can use notification
 * to trigger resending of these pending requests to the FUSE daemon, ensuring
 * they are properly processed again.
 *
 * Please note that this strategy is applicable only to idempotent requests or
 * if the FUSE daemon takes careful measures to avoid processing duplicated
 * non-idempotent requests.
 */
static void fuse_resend(struct fuse_conn *fc)
{
	spin_lock(&fc->lock);
	if (!fc->connected) {
		spin_unlock(&fc->lock);
		return;
	}

	if (fc->resend) {
		fc->resend(fc);
		spin_unlock(&fc->lock);
		return;
	}
}

static int fuse_notify_resend(struct fuse_conn *fc)
{
	fuse_resend(fc);
	return 0;
}

int fuse_notify(struct fuse_conn *fc, enum fuse_notify_code code,
		unsigned int size, struct fuse_copy_state *cs)
{
	/* Don't try to move pages (yet) */
	cs->move_pages = 0;

	switch (code) {
	case FUSE_NOTIFY_POLL:
		return fuse_notify_poll(fc, size, cs);

	case FUSE_NOTIFY_INVAL_INODE:
		return fuse_notify_inval_inode(fc, size, cs);

	case FUSE_NOTIFY_INVAL_ENTRY:
		return fuse_notify_inval_entry(fc, size, cs);

	case FUSE_NOTIFY_STORE:
		return fuse_notify_store(fc, size, cs);

	case FUSE_NOTIFY_RETRIEVE:
		return fuse_notify_retrieve(fc, size, cs);

	case FUSE_NOTIFY_DELETE:
		return fuse_notify_delete(fc, size, cs);

	case FUSE_NOTIFY_RESEND:
		return fuse_notify_resend(fc);

	default:
		fuse_copy_finish(cs);
		return -EINVAL;
	}
}
