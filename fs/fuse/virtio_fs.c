// SPDX-License-Identifier: GPL-2.0
/*
 * virtio-fs: Virtio Filesystem
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include <linux/fs.h>
#include <linux/dax.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/group_cpus.h>
#include <linux/pfn_t.h>
#include <linux/memremap.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include "virtio_fs.h"
#include <linux/delay.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/highmem.h>
#include <linux/cleanup.h>
#include <linux/uio.h>
#include "fuse_i.h"
#include "fuse_dev_i.h"

/* Used to help calculate the FUSE connection's max_pages limit for a request's
 * size. Parts of the struct fuse_req are sliced into scattergather lists in
 * addition to the pages used, so this can help account for that overhead.
 */
#define FUSE_HEADER_OVERHEAD    4

/* List of virtio-fs device instances and a lock for the list. Also provides
 * mutual exclusion in device removal and mounting path
 */
static DEFINE_MUTEX(virtio_fs_mutex);
static LIST_HEAD(virtio_fs_instances);

/* The /sys/fs/virtio_fs/ kset */
static struct kset *virtio_fs_kset;

enum {
	VQ_HIPRIO,
	VQ_NOTIFY,
	VQ_REQUEST
};

#define VQ_NAME_LEN	24

struct virtio_fs_vq;

struct virtio_fs_ack_in {
       int32_t error;  /* 0 = success. Negative number for error */
       uint32_t padding;
};

struct virtio_fs_ack_req {
	struct fuse_args args;
	struct virtio_fs_ack_in ack_in;
};

struct virtio_fs_req {
	struct virtio_fs_vq *fsvq;
	struct fuse_req req;
	struct list_head entry;    /* added to virtio_fs_vq reqs lists */
	bool allocated;
	struct completion completion; /* No inflight requests */
	struct virtio_fs_notify_req_extra {
		struct fuse_args args;
		u8 buf[]; /* fs->notify_buf_size */
	} notify[]; /* optional for notify requests */
};

/* Per-virtqueue state */
struct virtio_fs_vq {
	spinlock_t lock;
	struct virtqueue *vq;     /* protected by ->lock */
	struct work_struct done_work;
	unsigned nb_reqs;
	unsigned req_size;
	struct virtio_fs_req *reqs;
	struct list_head free_reqs; /* requests pool */
	struct list_head queued_reqs;
	struct list_head to_send_reqs;
	struct list_head processing;
	struct list_head end_reqs;	/* End these requests */
	struct work_struct dispatch_work;
	struct fuse_dev *fud;
	bool connected:1;
	bool initialized:1;
	bool notify:1;
	bool during_err_handling:1;
	struct completion init_comp;
	long in_flight;
	long in_flight_err_handling;
	u32 reqctr; /* The request counter */
	struct completion in_flight_zero; /* No inflight requests */
	struct kobject *kobj;
	unsigned max_background; /* Maximum number of outstanding fs background requests */
	unsigned active_background; /* Inflight background requests */
	char name[VQ_NAME_LEN];
} ____cacheline_aligned_in_smp;

/* A virtio-fs device instance */
struct virtio_fs {
	struct kobject kobj;
	struct kobject *mqs_kobj;
	struct list_head list;    /* on virtio_fs_instances */
	char *tag;
	struct virtio_fs_vq *vqs;
	unsigned int nvqs;               /* number of virtqueues */
	unsigned int num_request_queues; /* number of request queues */
	bool notify_enabled;
	unsigned int notify_buf_size;
	struct dax_device *dax_dev;

	unsigned int *mq_map; /* index = cpu id, value = request vq id */

	/* DAX memory window where file contents are mapped */
	void *window_kaddr;
	phys_addr_t window_phys_addr;
	size_t window_len;
};

struct fuse_notify_inval_entry_out_arg {
	struct fuse_notify_inval_entry_out out;
	char name[FUSE_NAME_MAX + 1];
};

struct fuse_notify_delete_out_arg {
	struct fuse_notify_delete_out delete;
	char name[FUSE_NAME_MAX + 1];
};

/* Union of all notify types the device can write to the driver */
union virtio_fs_notify_out {
	struct fuse_notify_inval_inode_out inval_inode;
	struct fuse_notify_inval_entry_out_arg inval_entry;
	struct fuse_notify_delete_out_arg delete;
	struct fuse_notify_store_out store;
	struct fuse_notify_retrieve_out retrieve;
};

struct virtio_fs_forget_req {
	struct fuse_in_header ih;
	struct fuse_forget_in arg;
};

struct virtio_fs_forget {
	/* This request can be temporarily queued on virt queue */
	struct list_head list;
	struct virtio_fs_forget_req req;
};

struct virtio_fs_req_work {
	struct fuse_req *req;
	struct virtio_fs_vq *fsvq;
	struct work_struct done_work;
};

static int virtio_fs_enqueue_req(struct virtio_fs_vq *fsvq,
				 struct virtio_fs_req *fs_req, bool in_flight,
				 gfp_t gfp);
static void virtio_fs_notify_send_req(struct virtio_fs *fs);
static void virtio_fs_notify_send_ack(struct virtio_fs *fs, uint64_t unique, int err);
static int __virtio_fs_simple_notify_reply(struct virtio_fs *fs, struct fuse_mount *fm,
					   struct fuse_args *args, u64 unique);

static const struct constant_table dax_param_enums[] = {
	{"always",	FUSE_DAX_ALWAYS },
	{"never",	FUSE_DAX_NEVER },
	{"inode",	FUSE_DAX_INODE_USER },
	{}
};

enum {
	OPT_DAX,
	OPT_DAX_ENUM,
	OPT_GDS,
};

static const struct fs_parameter_spec virtio_fs_parameters[] = {
	fsparam_flag("dax", OPT_DAX),
	fsparam_enum("dax", OPT_DAX_ENUM, dax_param_enums),
	fsparam_flag("gds", OPT_GDS),
	{}
};

static int virtio_fs_parse_param(struct fs_context *fsc,
				 struct fs_parameter *param)
{
	struct fs_parse_result result;
	struct fuse_fs_context *ctx = fsc->fs_private;
	int opt;

	opt = fs_parse(fsc, virtio_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case OPT_DAX:
		ctx->dax_mode = FUSE_DAX_ALWAYS;
		break;
	case OPT_DAX_ENUM:
		ctx->dax_mode = result.uint_32;
		break;
	case OPT_GDS:
		ctx->gds = 1;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static void virtio_fs_free_fsc(struct fs_context *fsc)
{
	struct fuse_fs_context *ctx = fsc->fs_private;

	kfree(ctx);
}

static inline unsigned vq_index_to_fsvq_index(struct virtio_fs *fs, unsigned i)
{
	return i + (!fs->notify_enabled && i > VQ_HIPRIO);
}

static inline struct virtio_fs_vq *vq_to_fsvq(struct virtqueue *vq)
{
	struct virtio_fs *fs = vq->vdev->priv;

	/*
	 * When the notify queue is disabled, fsvq[VQ_NOTIFY].vq is NULL
	 * and fsvq[VQ_REQUEST].vq->index is 1 instead of 2:
	 *
	 *                   vq->index
	 *              notify=1  notify=0
	 *  0 VQ_HIPRIO     0         0
	 *  1 VQ_NOTIFY     1         _
	 *  2 VQ_REQUEST    2         1
	 */
	return &fs->vqs[vq_index_to_fsvq_index(fs, vq->index)];
}

static inline struct virtio_fs_req *fuse_req_to_fs_req(struct fuse_req *req)
{
	return container_of(req, struct virtio_fs_req, req);
}

/* Should be called with fsvq->lock held. */
static inline void inc_in_flight_req(struct virtio_fs_vq *fsvq)
{
	fsvq->in_flight++;
}

/* Should be called with fsvq->lock held. */
static inline void inc_in_flight_err_handling_req(struct virtio_fs_vq *fsvq)
{
	fsvq->in_flight_err_handling++;
}

/* Should be called with fsvq->lock held. */
static inline void dec_in_flight_req(struct virtio_fs_vq *fsvq)
{
	WARN_ON_ONCE(fsvq->in_flight <= 0);
	fsvq->in_flight--;
	if (!fsvq->in_flight)
		complete(&fsvq->in_flight_zero);
}

/* Should be called with fsvq->lock held. */
static inline void dec_in_flight_err_handling_req(struct virtio_fs_vq *fsvq)
{
	WARN_ON_ONCE(fsvq->in_flight_err_handling <= 0);
	fsvq->in_flight_err_handling--;
}

static inline struct virtio_fs_req *fsvq_req_index(struct virtio_fs_vq *fsvq, int i)
{
	return (struct virtio_fs_req *)((u8 *)fsvq->reqs + fsvq->req_size * i);
}

static ssize_t tag_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct virtio_fs *fs = container_of(kobj, struct virtio_fs, kobj);

	return sysfs_emit(buf, "%s\n", fs->tag);
}

static struct kobj_attribute virtio_fs_tag_attr = __ATTR_RO(tag);

static struct attribute *virtio_fs_attrs[] = {
	&virtio_fs_tag_attr.attr,
	NULL
};
ATTRIBUTE_GROUPS(virtio_fs);

static void virtio_fs_ktype_release(struct kobject *kobj)
{
	struct virtio_fs *vfs = container_of(kobj, struct virtio_fs, kobj);

	kfree(vfs->mq_map);
	kfree(vfs->vqs);
	kfree(vfs);
}

static const struct kobj_type virtio_fs_ktype = {
	.release = virtio_fs_ktype_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = virtio_fs_groups,
};

static struct virtio_fs_vq *virtio_fs_kobj_to_vq(struct virtio_fs *fs,
		struct kobject *kobj)
{
	int i;

	for (i = 0; i < fs->nvqs; i++) {
		if (kobj == fs->vqs[i].kobj)
			return &fs->vqs[i];
	}
	return NULL;
}

static ssize_t name_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct virtio_fs *fs = container_of(kobj->parent->parent, struct virtio_fs, kobj);
	struct virtio_fs_vq *fsvq = virtio_fs_kobj_to_vq(fs, kobj);

	if (!fsvq)
		return -EINVAL;
	return sysfs_emit(buf, "%s\n", fsvq->name);
}

static struct kobj_attribute virtio_fs_vq_name_attr = __ATTR_RO(name);

static ssize_t cpu_list_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct virtio_fs *fs = container_of(kobj->parent->parent, struct virtio_fs, kobj);
	struct virtio_fs_vq *fsvq = virtio_fs_kobj_to_vq(fs, kobj);
	unsigned int cpu, qid;
	const size_t size = PAGE_SIZE - 1;
	bool first = true;
	int ret = 0, pos = 0;

	if (!fsvq)
		return -EINVAL;

	qid = vq_index_to_fsvq_index(fs, fsvq->vq->index);
	for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
		if (qid < VQ_REQUEST || (fs->mq_map[cpu] == qid)) {
			if (first)
				ret = snprintf(buf + pos, size - pos, "%u", cpu);
			else
				ret = snprintf(buf + pos, size - pos, ", %u", cpu);

			if (ret >= size - pos)
				break;
			first = false;
			pos += ret;
		}
	}
	ret = snprintf(buf + pos, size + 1 - pos, "\n");
	return pos + ret;
}

static struct kobj_attribute virtio_fs_vq_cpu_list_attr = __ATTR_RO(cpu_list);

static struct attribute *virtio_fs_vq_attrs[] = {
	&virtio_fs_vq_name_attr.attr,
	&virtio_fs_vq_cpu_list_attr.attr,
	NULL
};

static struct attribute_group virtio_fs_vq_attr_group = {
	.attrs = virtio_fs_vq_attrs,
};

/* Make sure virtiofs_mutex is held */
static void virtio_fs_put_locked(struct virtio_fs *fs)
{
	lockdep_assert_held(&virtio_fs_mutex);

	kobject_put(&fs->kobj);
}

static void virtio_fs_put(struct virtio_fs *fs)
{
	mutex_lock(&virtio_fs_mutex);
	virtio_fs_put_locked(fs);
	mutex_unlock(&virtio_fs_mutex);
}

static void virtio_fs_queue_requests_free(struct virtio_fs_vq *fsvq)
{
	struct virtio_fs_req *fs_req;

	spin_lock(&fsvq->lock);
	while (!list_empty(&fsvq->free_reqs)) {
		fs_req = list_first_entry(&fsvq->free_reqs,
					  struct virtio_fs_req, entry);
		list_del_init(&fs_req->entry);
	}
	if (fsvq->notify && fsvq->reqs) {
		int i;

		/*
		 * By design, notify requests are in-flight even at
		 * module unload time so we need to free per-notify
		 * resources here.
		 */
		for (i = 0; i < fsvq->nb_reqs; i++) {
			fs_req = fsvq_req_index(fsvq, i);
			kfree(fs_req->req.argbuf);
			fs_req->req.argbuf = NULL;
		}
	}
	spin_unlock(&fsvq->lock);
	kfree(fsvq->reqs);
	fsvq->reqs = NULL;
}

static void virtio_fs_notify_init(struct fuse_req *req,
				  struct fuse_args *args,
				  void *buf,
				  size_t buf_size)
{

	memset(&req->flags, 0, sizeof(req->flags));
	memset(&req->in, 0, sizeof(req->in));
	memset(&req->out, 0, sizeof(req->out));
	memset(args, 0, sizeof(*args));
	memset(buf, 0, buf_size);
	req->in.h.len = sizeof(*req);
	req->args = args;
	args->out_numargs = 1;
	args->out_args[0].size = buf_size;
	args->out_args[0].value = buf;
}

static inline size_t virtio_fs_max_notify_reqs(struct virtio_fs *fs)
{
	size_t q_size = virtqueue_get_vring_size(fs->vqs[VQ_NOTIFY].vq);
	size_t sg_per_req = 1 + DIV_ROUND_UP(fs->notify_buf_size, PAGE_SIZE);

	return q_size / sg_per_req;
}

static int virtio_fs_queue_requests_alloc(struct virtio_fs *fs, struct virtio_fs_vq *fsvq)
{
	unsigned int queue_size;
	unsigned int req_size;
	int i;

	req_size = sizeof(struct virtio_fs_req);
	queue_size = virtqueue_get_vring_size(fsvq->vq);

	if (fsvq->notify) {
		req_size += sizeof(struct virtio_fs_notify_req_extra) + fs->notify_buf_size;
		queue_size = virtio_fs_max_notify_reqs(fs);
	}

	fsvq->reqs = kcalloc(queue_size, req_size, GFP_KERNEL);
	if (!fsvq->reqs)
		return -ENOMEM;

	fsvq->nb_reqs = queue_size;
	fsvq->req_size = req_size;

	spin_lock(&fsvq->lock);
	/* Initial setting for max_background. This value will be
	 * updated for request queues upon FUSE_INIT. */
	fsvq->max_background = queue_size;
	for (i = 0; i < queue_size; i++) {
		struct virtio_fs_req *fs_req = fsvq_req_index(fsvq, i);

		INIT_LIST_HEAD(&fs_req->entry);
		fs_req->fsvq = fsvq;
		init_completion(&fs_req->completion);
		list_add_tail(&fs_req->entry, &fsvq->free_reqs);

		if (fsvq->notify)
			virtio_fs_notify_init(&fs_req->req,
					      &fs_req->notify[0].args,
					      &fs_req->notify[0].buf,
					      fs->notify_buf_size);

	}
	spin_unlock(&fsvq->lock);

	return 0;
}

static void virtio_fs_drain_queue(struct virtio_fs_vq *fsvq)
{
	if (fsvq->notify) {
		/*
		 * The notification queue will always have in-flight
		 * requests by design. The in_flight_zero condition
		 * will never trigger.
		 */
		return;
	}

	WARN_ON(fsvq->in_flight < 0);

	/* Wait for in flight requests to finish.*/
	spin_lock(&fsvq->lock);
	if (fsvq->in_flight) {
		/* We are holding virtio_fs_mutex. There should not be any
		 * waiters waiting for completion.
		 */
		reinit_completion(&fsvq->in_flight_zero);
		spin_unlock(&fsvq->lock);
		wait_for_completion(&fsvq->in_flight_zero);
	} else {
		spin_unlock(&fsvq->lock);
	}

	flush_work(&fsvq->done_work);
	flush_work(&fsvq->dispatch_work);
}

static void virtio_fs_drain_all_queues_locked(struct virtio_fs *fs)
{
	struct virtio_fs_vq *fsvq;
	int i;

	for (i = 0; i < fs->nvqs; i++) {
		fsvq = &fs->vqs[i];
		if (!fsvq->vq)
			continue;

		virtio_fs_drain_queue(fsvq);
	}
}

static void virtio_fs_drain_all_queues(struct virtio_fs *fs)
{
	/* Provides mutual exclusion between ->remove and ->kill_sb
	 * paths. We don't want both of these draining queue at the
	 * same time. Current completion logic reinits completion
	 * and that means there should not be any other thread
	 * doing reinit or waiting for completion already.
	 */
	mutex_lock(&virtio_fs_mutex);
	virtio_fs_drain_all_queues_locked(fs);
	mutex_unlock(&virtio_fs_mutex);
}

static void virtio_fs_free_all_queues_requests(struct virtio_fs *fs)
{
	struct virtio_fs_vq *fsvq;
	int i;

	for (i = 0; i < fs->nvqs; i++) {
		fsvq = &fs->vqs[i];
		if (!fsvq->vq)
			continue;

		virtio_fs_queue_requests_free(fsvq);
	}
}

static int virtio_fs_alloc_all_queues_requests(struct virtio_fs *fs)
{
	struct virtio_fs_vq *fsvq;
	int i, j, ret;

	for (i = 0; i < fs->nvqs; i++) {
		fsvq = &fs->vqs[i];
		if (!fsvq->vq)
			continue;

		ret = virtio_fs_queue_requests_alloc(fs, fsvq);
		if (ret)
			goto out_stop;
	}
	return 0;

out_stop:
	for (j = 0; j < i; j++) {
		fsvq = &fs->vqs[j];
		if (!fsvq->vq)
			continue;

		virtio_fs_queue_requests_free(fsvq);
	}
	return ret;
}

static void virtio_fs_to_send_reqs(struct virtio_fs_vq *fsvq)
{
	struct virtio_fs_req *fs_req, *next;

	if (list_empty(&fsvq->to_send_reqs))
		return;

	list_for_each_entry_safe(fs_req, next, &fsvq->to_send_reqs, entry) {
		dec_in_flight_err_handling_req(fsvq);
		inc_in_flight_req(fsvq);
		list_move_tail(&fs_req->entry, &fsvq->queued_reqs);
	}
	schedule_work(&fsvq->dispatch_work);
}

static void virtio_fs_start_all_queues(struct virtio_fs *fs)
{
	struct virtio_fs_vq *fsvq;
	int i;

	for (i = 0; i < fs->nvqs; i++) {
		fsvq = &fs->vqs[i];
		if (!fsvq->vq)
			continue;

		spin_lock(&fsvq->lock);
		fsvq->connected = true;
		fsvq->during_err_handling = false;
		virtio_fs_to_send_reqs(fsvq);
		spin_unlock(&fsvq->lock);
	}
}

static void virtio_fs_delete_queues_sysfs(struct virtio_fs *fs)
{
	struct virtio_fs_vq *fsvq;
	int i;

	for (i = 0; i < fs->nvqs; i++) {
		fsvq = &fs->vqs[i];
		if (!fsvq->vq)
			continue;

		kobject_put(fsvq->kobj);
	}
}

static int virtio_fs_add_queues_sysfs(struct virtio_fs *fs)
{
	struct virtio_fs_vq *fsvq;
	char buff[12];
	int i, j, ret;

	for (i = 0; i < fs->nvqs; i++) {
		fsvq = &fs->vqs[i];
		if (!fsvq->vq)
			continue;

		sprintf(buff, "%d", i);
		fsvq->kobj = kobject_create_and_add(buff, fs->mqs_kobj);
		if (!fs->mqs_kobj) {
			ret = -ENOMEM;
			goto out_del;
		}

		ret = sysfs_create_group(fsvq->kobj, &virtio_fs_vq_attr_group);
		if (ret) {
			kobject_put(fsvq->kobj);
			goto out_del;
		}
	}

	return 0;

out_del:
	for (j = 0; j < i; j++) {
		fsvq = &fs->vqs[j];
		kobject_put(fsvq->kobj);
	}
	return ret;
}

/* Add a new instance to the list or return -EEXIST if tag name exists*/
static int virtio_fs_add_instance(struct virtio_device *vdev,
				  struct virtio_fs *fs)
{
	struct virtio_fs *fs2;
	int ret;

	mutex_lock(&virtio_fs_mutex);

	list_for_each_entry(fs2, &virtio_fs_instances, list) {
		if (strcmp(fs->tag, fs2->tag) == 0) {
			mutex_unlock(&virtio_fs_mutex);
			return -EEXIST;
		}
	}

	/* Use the virtio_device's index as a unique identifier, there is no
	 * need to allocate our own identifiers because the virtio_fs instance
	 * is only visible to userspace as long as the underlying virtio_device
	 * exists.
	 */
	fs->kobj.kset = virtio_fs_kset;
	ret = kobject_add(&fs->kobj, NULL, "%d", vdev->index);
	if (ret < 0)
		goto out_unlock;

	fs->mqs_kobj = kobject_create_and_add("mqs", &fs->kobj);
	if (!fs->mqs_kobj) {
		ret = -ENOMEM;
		goto out_del;
	}

	ret = sysfs_create_link(&fs->kobj, &vdev->dev.kobj, "device");
	if (ret < 0)
		goto out_put;

	ret = virtio_fs_add_queues_sysfs(fs);
	if (ret)
		goto out_remove;

	list_add_tail(&fs->list, &virtio_fs_instances);

	mutex_unlock(&virtio_fs_mutex);

	kobject_uevent(&fs->kobj, KOBJ_ADD);

	return 0;

out_remove:
	sysfs_remove_link(&fs->kobj, "device");
out_put:
	kobject_put(fs->mqs_kobj);
out_del:
	kobject_del(&fs->kobj);
out_unlock:
	mutex_unlock(&virtio_fs_mutex);
	return ret;
}

/* Return the virtio_fs with a given tag, or NULL */
static struct virtio_fs *virtio_fs_find_instance(const char *tag)
{
	struct virtio_fs *fs;

	mutex_lock(&virtio_fs_mutex);

	list_for_each_entry(fs, &virtio_fs_instances, list) {
		if (strcmp(fs->tag, tag) == 0) {
			kobject_get(&fs->kobj);
			goto found;
		}
	}

	fs = NULL; /* not found */

found:
	mutex_unlock(&virtio_fs_mutex);

	return fs;
}

static void virtio_fs_free_devs(struct virtio_fs *fs)
{
	unsigned int i;

	for (i = 0; i < fs->nvqs; i++) {
		struct virtio_fs_vq *fsvq = &fs->vqs[i];

		if (!fsvq->vq || !fsvq->fud)
			continue;

		fuse_dev_free(fsvq->fud);
		fsvq->fud = NULL;
	}
}

/* Read filesystem name from virtio config into fs->tag (must kfree()). */
static int virtio_fs_read_tag(struct virtio_device *vdev, struct virtio_fs *fs)
{
	char tag_buf[sizeof_field(struct virtio_fs_config, tag)];
	char *end;
	size_t len;

	virtio_cread_bytes(vdev, offsetof(struct virtio_fs_config, tag),
			   &tag_buf, sizeof(tag_buf));
	end = memchr(tag_buf, '\0', sizeof(tag_buf));
	if (end == tag_buf)
		return -EINVAL; /* empty tag */
	if (!end)
		end = &tag_buf[sizeof(tag_buf)];

	len = end - tag_buf;
	fs->tag = devm_kmalloc(&vdev->dev, len + 1, GFP_KERNEL);
	if (!fs->tag)
		return -ENOMEM;
	memcpy(fs->tag, tag_buf, len);
	fs->tag[len] = '\0';

	/* While the VIRTIO specification allows any character, newlines are
	 * awkward on mount(8) command-lines and cause problems in the sysfs
	 * "tag" attr and uevent TAG= properties. Forbid them.
	 */
	if (strchr(fs->tag, '\n')) {
		dev_dbg(&vdev->dev, "refusing virtiofs tag with newline character\n");
		return -EINVAL;
	}

	dev_info(&vdev->dev, "discovered new tag: %s\n", fs->tag);
	return 0;
}

static void virtio_fs_init_copy_state(struct fuse_copy_state *cs,
				      struct iov_iter *from)
{
	fuse_copy_init(cs, 0, from);
	cs->len = iov_iter_count(from);
	cs->mapped = 1;
}

static size_t virtio_fs_get_notify_outarg_size(enum fuse_notify_code notify_code, void *p)
{
	switch (notify_code) {
	case FUSE_NOTIFY_INVAL_INODE:
		return sizeof(struct fuse_notify_inval_inode_out);
	case FUSE_NOTIFY_INVAL_ENTRY: {
		struct fuse_notify_inval_entry_out *out = p;
		return sizeof(*out) + out->namelen + 1;
	}
	case FUSE_NOTIFY_DELETE: {
		struct fuse_notify_delete_out *out = p;
		return sizeof(*out) + out->namelen + 1;
	}
	case FUSE_NOTIFY_STORE:
		return sizeof(struct fuse_notify_store_out);
	case FUSE_NOTIFY_RETRIEVE:
		return sizeof(struct fuse_notify_retrieve_out);
	default:
		return 0;
	}
}

static void virtio_fs_req_put(struct virtio_fs_req *fs_req)
{
	struct virtio_fs_vq *fsvq = fs_req->fsvq;

	if (refcount_dec_and_test(&fs_req->req.count)) {
		if (unlikely(fs_req->allocated)) {
			kfree(fs_req);
			return;
		}

		spin_lock(&fsvq->lock);
		list_add_tail(&fs_req->entry, &fsvq->free_reqs);
		spin_unlock(&fsvq->lock);
	}
}

static void __virtio_fs_get_request(struct virtio_fs_req *fs_req)
{
	refcount_inc(&fs_req->req.count);
}

static struct virtio_fs_req *virtio_fs_req_get(struct virtio_fs_vq *fsvq,
		struct fuse_mount *fm, gfp_t gfp_flags, bool force)
{
	struct virtio_fs_req *fs_req;

	spin_lock(&fsvq->lock);
	if (!force && !fsvq->initialized) {
		reinit_completion(&fsvq->init_comp);
		spin_unlock(&fsvq->lock);
		wait_for_completion(&fsvq->init_comp);
		spin_lock(&fsvq->lock);
	}
	fs_req = list_first_entry_or_null(&fsvq->free_reqs,
					  struct virtio_fs_req, entry);
	if (likely(fs_req)) {
		refcount_set(&fs_req->req.count, 1);
		list_del_init(&fs_req->entry);
	}
	spin_unlock(&fsvq->lock);

	if (unlikely(!fs_req)) {
		fs_req = kzalloc(sizeof(*fs_req), gfp_flags);
		if (unlikely(!fs_req))
			return NULL;

		INIT_LIST_HEAD(&fs_req->entry);
		fs_req->fsvq = fsvq;
		init_completion(&fs_req->completion);
		refcount_set(&fs_req->req.count, 1);
		fs_req->allocated = true;
	}

	__clear_bit(FR_ISREPLY, &fs_req->req.flags);
	__clear_bit(FR_BACKGROUND, &fs_req->req.flags);
	fs_req->req.fm = fm;

	return fs_req;
}

static void virtio_fs_end_notify(struct virtio_fs_req *fs_req)
{
	enum fuse_notify_code notify_code = fs_req->req.out.h.error;
	struct fuse_args *args = &fs_req->notify[0].args;
	struct fuse_copy_state cs;
	struct fuse_conn *fc;
	struct iov_iter iter;
	struct virtio_fs *fs;
	struct kvec iov[1];
	size_t size;
	int err = 0;

	pr_debug("virtio_fs: received notification %d from device\n", notify_code);

	/*
	 * If we get here without fuse connection,
	 * it means we end a notificaiton request after
	 * disconnect, nothing to do.
	 */
	fc = fs_req->fsvq->fud->fc;
	if (!fc)
		return;

	fs = fc->priv;
	if (WARN_ON(!fs))
		return;

	size = virtio_fs_get_notify_outarg_size(notify_code, args->out_args[0].value);
	iov[0].iov_base = args->out_args[0].value;
	iov[0].iov_len	= size;
	iov_iter_kvec(&iter, ITER_SOURCE, iov, 1, iov[0].iov_len);
	virtio_fs_init_copy_state(&cs, &iter);
	err = fuse_notify(fc, notify_code, size, &cs);
	if (err)
		pr_err("virtio_fs: failed to notify with err=%d\n", err);

	switch (notify_code) {
	case FUSE_NOTIFY_INVAL_INODE:
	case FUSE_NOTIFY_INVAL_ENTRY:
	case FUSE_NOTIFY_DELETE:
	case FUSE_NOTIFY_STORE:
		/* Report notify status with a ACK */
		virtio_fs_notify_send_ack(fs, fs_req->req.out.h.unique, err);
		break;
	case FUSE_NOTIFY_RETRIEVE:
	case FUSE_NOTIFY_RESEND:
	case FUSE_NOTIFY_POLL:
	default:
		break;
	}

	/*
	 * Since all the available notify requests should be sent, we
	 * need to put the request before sending a new one to be able
	 * to reuse it
	 */
	virtio_fs_req_put(fs_req);
	virtio_fs_notify_send_req(fs);
}

static void virtio_fs_request_end(struct virtio_fs_req *fs_req)
{
	struct fuse_req *req = &fs_req->req;
	struct fuse_mount *fm = req->fm;

	if (test_bit(FR_NOTIFY, &req->flags)) {
		/* virtio_fs_end_notify() will put the request */
		virtio_fs_end_notify(fs_req);
		return;
	}

	if (test_bit(FR_ASYNC, &req->flags)) {
		__clear_bit(FR_ASYNC, &req->flags);
		req->args->end(fm, req->args, req->out.h.error);
	}

	if (test_bit(FR_WAITING, &req->flags)) {
		__clear_bit(FR_WAITING, &req->flags);
		/* Wake up waiter sleeping */
		complete(&fs_req->completion);
	} else {
		/* put only non waiting requests */
		virtio_fs_req_put(fs_req);
	}
}

/* Work function for hiprio completion */
static void virtio_fs_hiprio_done_work(struct work_struct *work)
{
	struct virtio_fs_vq *fsvq = container_of(work, struct virtio_fs_vq,
						 done_work);
	struct virtqueue *vq = fsvq->vq;

	/* Free completed FUSE_FORGET requests */
	spin_lock(&fsvq->lock);
	do {
		unsigned int len;
		void *req;

		virtqueue_disable_cb(vq);

		while ((req = virtqueue_get_buf(vq, &len)) != NULL) {
			kfree(req);
			dec_in_flight_req(fsvq);
		}
	} while (!virtqueue_enable_cb(vq));

	if (!list_empty(&fsvq->queued_reqs))
		schedule_work(&fsvq->dispatch_work);

	spin_unlock(&fsvq->lock);
}

static void virtio_fs_request_dispatch_work(struct work_struct *work)
{
	struct virtio_fs_req *fs_req;
	struct virtio_fs_vq *fsvq = container_of(work, struct virtio_fs_vq,
						 dispatch_work);
	int ret;

	pr_debug("virtio-fs: worker %s called.\n", __func__);
	while (1) {
		spin_lock(&fsvq->lock);
		fs_req = list_first_entry_or_null(&fsvq->end_reqs,
						  struct virtio_fs_req, entry);
		if (!fs_req) {
			spin_unlock(&fsvq->lock);
			break;
		}

		list_del_init(&fs_req->entry);
		spin_unlock(&fsvq->lock);
		virtio_fs_request_end(fs_req);
	}

	/* Dispatch pending requests */
	while (1) {
		unsigned int flags;

		spin_lock(&fsvq->lock);
		fs_req = list_first_entry_or_null(&fsvq->queued_reqs,
						  struct virtio_fs_req, entry);
		if (!fs_req) {
			spin_unlock(&fsvq->lock);
			return;
		}
		list_del_init(&fs_req->entry);
		spin_unlock(&fsvq->lock);

		flags = memalloc_nofs_save();
		ret = virtio_fs_enqueue_req(fsvq, fs_req, true, GFP_KERNEL);
		memalloc_nofs_restore(flags);
		if (ret < 0) {
			if (ret == -ENOSPC) {
				spin_lock(&fsvq->lock);
				list_add_tail(&fs_req->entry, &fsvq->queued_reqs);
				spin_unlock(&fsvq->lock);
				return;
			} else if (ret == -EAGAIN) {
				spin_lock(&fsvq->lock);
				list_add_tail(&fs_req->entry, &fsvq->to_send_reqs);
				dec_in_flight_req(fsvq);
				inc_in_flight_err_handling_req(fsvq);
				spin_unlock(&fsvq->lock);
				continue;
			}

			fs_req->req.out.h.error = ret;
			spin_lock(&fsvq->lock);
			dec_in_flight_req(fsvq);
			spin_unlock(&fsvq->lock);
			pr_err("virtio-fs: virtio_fs_enqueue_req() failed %d\n",
			       ret);
			virtio_fs_request_end(fs_req);
		}
	}
}

/*
 * Returns 1 if queue is full and sender should wait a bit before sending
 * next request, 0 otherwise.
 */
static int send_forget_request(struct virtio_fs_vq *fsvq,
			       struct virtio_fs_forget *forget,
			       bool in_flight)
{
	struct scatterlist sg;
	struct virtqueue *vq;
	int ret = 0;
	bool notify;
	struct virtio_fs_forget_req *req = &forget->req;

	spin_lock(&fsvq->lock);
	if (!fsvq->connected) {
		if (in_flight)
			dec_in_flight_req(fsvq);
		kfree(forget);
		goto out;
	}

	sg_init_one(&sg, req, sizeof(*req));
	vq = fsvq->vq;
	dev_dbg(&vq->vdev->dev, "%s\n", __func__);

	ret = virtqueue_add_outbuf(vq, &sg, 1, forget, GFP_ATOMIC);
	if (ret < 0) {
		if (ret == -ENOSPC) {
			pr_debug("virtio-fs: Could not queue FORGET: err=%d. Will try later\n",
				 ret);
			list_add_tail(&forget->list, &fsvq->queued_reqs);
			if (!in_flight)
				inc_in_flight_req(fsvq);
			/* Queue is full */
			ret = 1;
		} else {
			pr_debug("virtio-fs: Could not queue FORGET: err=%d. Dropping it.\n",
				 ret);
			kfree(forget);
			if (in_flight)
				dec_in_flight_req(fsvq);
		}
		goto out;
	}

	if (!in_flight)
		inc_in_flight_req(fsvq);
	notify = virtqueue_kick_prepare(vq);
	spin_unlock(&fsvq->lock);

	if (notify)
		virtqueue_notify(vq);
	return ret;
out:
	spin_unlock(&fsvq->lock);
	return ret;
}

static void virtio_fs_hiprio_dispatch_work(struct work_struct *work)
{
	struct virtio_fs_forget *forget;
	struct virtio_fs_vq *fsvq = container_of(work, struct virtio_fs_vq,
						 dispatch_work);
	pr_debug("virtio-fs: worker %s called.\n", __func__);
	while (1) {
		spin_lock(&fsvq->lock);
		forget = list_first_entry_or_null(&fsvq->queued_reqs,
					struct virtio_fs_forget, list);
		if (!forget) {
			spin_unlock(&fsvq->lock);
			return;
		}

		list_del(&forget->list);
		spin_unlock(&fsvq->lock);
		if (send_forget_request(fsvq, forget, true))
			return;
	}
}

/* Allocate and copy args into req->argbuf */
static int copy_args_to_argbuf(struct fuse_req *req, gfp_t gfp)
{
	struct fuse_args *args = req->args;
	unsigned int offset = 0;
	unsigned int num_in;
	unsigned int num_out;
	unsigned int len;
	unsigned int i;

	num_in = args->in_numargs - args->in_pages;
	num_out = args->out_numargs - args->out_pages;
	len = fuse_len_args(num_in, (struct fuse_arg *) args->in_args) +
	      fuse_len_args(num_out, args->out_args);

	req->argbuf = kmalloc(len, gfp);
	if (!req->argbuf)
		return -ENOMEM;

	for (i = 0; i < num_in; i++) {
		memcpy(req->argbuf + offset,
		       args->in_args[i].value,
		       args->in_args[i].size);
		offset += args->in_args[i].size;
	}

	return 0;
}

/* Copy args out of and free req->argbuf */
static void copy_args_from_argbuf(struct fuse_args *args, struct fuse_req *req)
{
	unsigned int remaining;
	unsigned int offset;
	unsigned int num_in;
	unsigned int num_out;
	unsigned int i;

	remaining = req->out.h.len - sizeof(req->out.h);
	num_in = args->in_numargs - args->in_pages;
	num_out = args->out_numargs - args->out_pages;
	offset = fuse_len_args(num_in, (struct fuse_arg *)args->in_args);

	for (i = 0; i < num_out; i++) {
		unsigned int argsize = args->out_args[i].size;

		if (args->out_argvar &&
		    i == args->out_numargs - 1 &&
		    argsize > remaining) {
			argsize = remaining;
		}

		memcpy(args->out_args[i].value, req->argbuf + offset, argsize);
		offset += argsize;

		if (i != args->out_numargs - 1)
			remaining -= argsize;
	}

	/* Store the actual size of the variable-length arg */
	if (args->out_argvar)
		args->out_args[args->out_numargs - 1].size = remaining;

	kfree(req->argbuf);
	req->argbuf = NULL;
}

/* Work function for request completion */
static void virtio_fs_request_complete(struct fuse_req *req,
				       struct virtio_fs_vq *fsvq)
{
	struct virtio_fs_req *fs_req = fuse_req_to_fs_req(req);
	struct fuse_args *args;
	struct fuse_args_pages *ap;
	unsigned int len, i, thislen;
	struct folio *folio;

	/*
	 * TODO verify that server properly follows FUSE protocol
	 * (oh.uniq, oh.len)
	 */
	args = req->args;
	copy_args_from_argbuf(args, req);

	if (args->out_pages && args->page_zeroing) {
		len = args->out_args[args->out_numargs - 1].size;
		ap = container_of(args, typeof(*ap), args);
		for (i = 0; i < ap->num_folios; i++) {
			thislen = ap->descs[i].length;
			if (len < thislen) {
				WARN_ON(ap->descs[i].offset);
				folio = ap->folios[i];
				folio_zero_segment(folio, len, thislen);
				len = 0;
			} else {
				len -= thislen;
			}
		}
	}

	spin_lock(&fsvq->lock);
	dec_in_flight_req(fsvq);
	if (test_bit(FR_BACKGROUND, &req->flags))
		fsvq->active_background--;
	spin_unlock(&fsvq->lock);
	virtio_fs_request_end(fs_req);
}

static void virtio_fs_complete_req_work(struct work_struct *work)
{
	struct virtio_fs_req_work *w =
		container_of(work, typeof(*w), done_work);

	virtio_fs_request_complete(w->req, w->fsvq);
	kfree(w);
}

static void virtio_fs_requests_done_work(struct work_struct *work)
{
	struct virtio_fs_vq *fsvq = container_of(work, struct virtio_fs_vq,
						 done_work);
	struct virtqueue *vq = fsvq->vq;
	struct virtio_fs_req *fs_req;
	struct virtio_fs_req *next;
	struct fuse_req *req;
	unsigned int len;
	LIST_HEAD(reqs);

	/* Collect completed requests off the virtqueue */
	spin_lock(&fsvq->lock);
	do {
		virtqueue_disable_cb(vq);

		while ((req = virtqueue_get_buf(vq, &len)) != NULL) {
			fs_req = fuse_req_to_fs_req(req);
			list_move_tail(&fs_req->entry, &reqs);
		}
	} while (!virtqueue_enable_cb(vq));
	spin_unlock(&fsvq->lock);

	/* End requests */
	list_for_each_entry_safe(fs_req, next, &reqs, entry) {
		list_del_init(&fs_req->entry);

		/* blocking async request completes in a worker context */
		if (fs_req->req.args->may_block) {
			struct virtio_fs_req_work *w;

			w = kzalloc(sizeof(*w), GFP_NOFS | __GFP_NOFAIL);
			INIT_WORK(&w->done_work, virtio_fs_complete_req_work);
			w->fsvq = fsvq;
			w->req = &fs_req->req;
			schedule_work(&w->done_work);
		} else {
			virtio_fs_request_complete(&fs_req->req, fsvq);
		}
	}

	/* Try to push previously queued requests, as the queue might no longer be full */
	spin_lock(&fsvq->lock);
	if (!list_empty(&fsvq->queued_reqs))
		schedule_work(&fsvq->dispatch_work);
	spin_unlock(&fsvq->lock);
}

static void virtio_fs_map_queues(struct virtio_device *vdev, struct virtio_fs *fs)
{
	const struct cpumask *mask, *masks;
	unsigned int q, cpu;

	/* First attempt to map using existing transport layer affinities
	 * e.g. PCIe MSI-X
	 */
	if (!vdev->config->get_vq_affinity)
		goto fallback;

	for (q = 0; q < fs->num_request_queues; q++) {
		mask = vdev->config->get_vq_affinity(vdev, fs->vqs[VQ_REQUEST + q].vq->index);
		if (!mask)
			goto fallback;

		for_each_cpu(cpu, mask)
			fs->mq_map[cpu] = q + VQ_REQUEST;
	}

	return;
fallback:
	/* Attempt to map evenly in groups over the CPUs */
	masks = group_cpus_evenly(fs->num_request_queues);
	/* If even this fails we default to all CPUs use first request queue */
	if (!masks) {
		for_each_possible_cpu(cpu)
			fs->mq_map[cpu] = VQ_REQUEST;
		return;
	}

	for (q = 0; q < fs->num_request_queues; q++) {
		for_each_cpu(cpu, &masks[q])
			fs->mq_map[cpu] = q + VQ_REQUEST;
	}
	kfree(masks);
}

/* Virtqueue interrupt handler */
static void virtio_fs_vq_done(struct virtqueue *vq)
{
	struct virtio_fs_vq *fsvq = vq_to_fsvq(vq);

	dev_dbg(&vq->vdev->dev, "%s %s\n", __func__, fsvq->name);

	schedule_work(&fsvq->done_work);
}

static void virtio_fs_init_vq(struct virtio_fs_vq *fsvq, char *name,
			      int vq_type)
{
	strscpy(fsvq->name, name, VQ_NAME_LEN);
	spin_lock_init(&fsvq->lock);
	INIT_LIST_HEAD(&fsvq->free_reqs);
	INIT_LIST_HEAD(&fsvq->processing);
	INIT_LIST_HEAD(&fsvq->queued_reqs);
	INIT_LIST_HEAD(&fsvq->to_send_reqs);
	INIT_LIST_HEAD(&fsvq->end_reqs);
	init_completion(&fsvq->in_flight_zero);
	init_completion(&fsvq->init_comp);

	switch (vq_type) {
	case VQ_NOTIFY:
		fsvq->notify = true;
		fallthrough;
	case VQ_REQUEST:
		INIT_WORK(&fsvq->done_work, virtio_fs_requests_done_work);
		INIT_WORK(&fsvq->dispatch_work,
				virtio_fs_request_dispatch_work);
		break;
	case VQ_HIPRIO:
		INIT_WORK(&fsvq->done_work, virtio_fs_hiprio_done_work);
		INIT_WORK(&fsvq->dispatch_work,
				virtio_fs_hiprio_dispatch_work);
		break;
	}
}

/* Free virtqueues (device must already be reset) */
static void virtio_fs_cleanup_vqs(struct virtio_device *vdev)
{
	vdev->config->del_vqs(vdev);
}

/* Initialize virtqueues */
static int virtio_fs_setup_vqs(struct virtio_device *vdev,
			       struct virtio_fs *fs, bool alloc_reqs)
{
	struct virtqueue_info *vqs_info;
	unsigned int info_idx = 0;
	struct virtqueue **vqs;
	unsigned int vq_nvqs;
	unsigned int i;
	int ret = 0;

	vq_nvqs = 1 + fs->notify_enabled + fs->num_request_queues;
	vqs = kmalloc_array(vq_nvqs, sizeof(vqs[VQ_HIPRIO]), GFP_KERNEL);
	vqs_info = kcalloc(vq_nvqs, sizeof(*vqs_info), GFP_KERNEL);
	if (!vqs || !vqs_info) {
		ret = -ENOMEM;
		goto out;
	}

	/* Initialize the hiprio/forget request virtqueue */
	vqs_info[info_idx].callback = virtio_fs_vq_done;
	vqs_info[info_idx].name = fs->vqs[VQ_HIPRIO].name;
	info_idx++;

	if (fs->notify_enabled) {
		/* Initialize the notify request virtqueue */
		vqs_info[info_idx].callback = virtio_fs_vq_done;
		vqs_info[info_idx].name = fs->vqs[VQ_NOTIFY].name;
		info_idx++;
	}

	/* Initialize the requests virtqueues */
	for (i = VQ_REQUEST; i < fs->nvqs; i++) {
		vqs_info[info_idx].callback = virtio_fs_vq_done;
		vqs_info[info_idx].name = fs->vqs[i].name;
		info_idx++;
	}

	/* Leaving irq descriptor NULL will allow for dynamic remapping */
	ret = virtio_find_vqs(vdev, vq_nvqs, vqs, vqs_info, NULL);
	if (ret < 0)
		goto out;

	/* Install vqs but skip notify if not enabled */
	i = info_idx = 0;
	fs->vqs[i++].vq = vqs[info_idx++];
	fs->vqs[i++].vq = fs->notify_enabled ? vqs[info_idx++] : NULL;

	/* Rest are requests queues */
	for (; i < fs->nvqs; i++, info_idx++)
		fs->vqs[i].vq = vqs[info_idx];

	if (alloc_reqs) {
		ret = virtio_fs_alloc_all_queues_requests(fs);
		if (ret)
			goto out_del_vqs;
	}

	kfree(vqs_info);
	kfree(vqs);
	return 0;

out_del_vqs:
	virtio_reset_device(vdev);
	virtio_fs_cleanup_vqs(vdev);
out:
	kfree(vqs_info);
	kfree(vqs);
	return ret;
}

static int virtio_fs_setup_fsvqs(struct virtio_device *vdev,
				 struct virtio_fs *fs)
{
	unsigned int i;
	int ret = 0;

	virtio_cread_le(vdev, struct virtio_fs_config, num_request_queues,
			&fs->num_request_queues);
	if (fs->num_request_queues == 0)
		return -EINVAL;
	pr_debug("virtio-fs: device config num_request_queues=%u\n", fs->num_request_queues);

	fs->notify_buf_size = sizeof(union virtio_fs_notify_out);
	fs->notify_enabled = virtio_has_feature(vdev, VIRTIO_FS_F_NOTIFICATION);
	if (fs->notify_enabled) {
		virtio_cread_le(vdev, struct virtio_fs_config, notify_buf_size,
				&fs->notify_buf_size);
		if (fs->notify_buf_size < sizeof(union virtio_fs_notify_out)) {
			pr_err("virtio-fs: invalid notify buf size %u", fs->notify_buf_size);
			return -EINVAL;
		}
		pr_debug("virtio-fs: device config notify_buf_size=%u\n", fs->notify_buf_size);
	}

	/* Truncate nr of request queues to nr_cpu_id */
	fs->num_request_queues = min_t(unsigned int, fs->num_request_queues,
					nr_cpu_ids);
	fs->nvqs = VQ_REQUEST + fs->num_request_queues;
	fs->vqs = kcalloc(fs->nvqs, sizeof(fs->vqs[VQ_HIPRIO]), GFP_KERNEL);
	if (!fs->vqs)
		return -ENOMEM;

	fs->mq_map = kcalloc_node(nr_cpu_ids, sizeof(*fs->mq_map), GFP_KERNEL,
					dev_to_node(&vdev->dev));
	if (!fs->mq_map) {
		ret = -ENOMEM;
		goto err;
	}

	virtio_fs_init_vq(&fs->vqs[VQ_HIPRIO], "hiprio", VQ_HIPRIO);

	if (fs->notify_enabled)
		virtio_fs_init_vq(&fs->vqs[VQ_NOTIFY], "notify", VQ_NOTIFY);

	for (i = VQ_REQUEST; i < fs->nvqs; i++) {
		char vq_name[VQ_NAME_LEN];

		snprintf(vq_name, VQ_NAME_LEN, "requests.%u", i - VQ_REQUEST);
		virtio_fs_init_vq(&fs->vqs[i], vq_name, VQ_REQUEST);
	}

	ret = virtio_fs_setup_vqs(vdev, fs, true);
	if (ret)
		goto err;

	virtio_fs_start_all_queues(fs);

	return 0;

err:
	kfree(fs->mq_map);
	kfree(fs->vqs);
	fs->mq_map = NULL;
	fs->vqs = NULL;
	return ret;
}

/* Map a window offset to a page frame number.  The window offset will have
 * been produced by .iomap_begin(), which maps a file offset to a window
 * offset.
 */
static long virtio_fs_direct_access(struct dax_device *dax_dev, pgoff_t pgoff,
				    long nr_pages, enum dax_access_mode mode,
				    void **kaddr, pfn_t *pfn)
{
	struct virtio_fs *fs = dax_get_private(dax_dev);
	phys_addr_t offset = PFN_PHYS(pgoff);
	size_t max_nr_pages = fs->window_len / PAGE_SIZE - pgoff;

	if (kaddr)
		*kaddr = fs->window_kaddr + offset;
	if (pfn)
		*pfn = phys_to_pfn_t(fs->window_phys_addr + offset,
					PFN_DEV | PFN_MAP);
	return nr_pages > max_nr_pages ? max_nr_pages : nr_pages;
}

static int virtio_fs_zero_page_range(struct dax_device *dax_dev,
				     pgoff_t pgoff, size_t nr_pages)
{
	long rc;
	void *kaddr;

	rc = dax_direct_access(dax_dev, pgoff, nr_pages, DAX_ACCESS, &kaddr,
			       NULL);
	if (rc < 0)
		return dax_mem2blk_err(rc);

	memset(kaddr, 0, nr_pages << PAGE_SHIFT);
	dax_flush(dax_dev, kaddr, nr_pages << PAGE_SHIFT);
	return 0;
}

static const struct dax_operations virtio_fs_dax_ops = {
	.direct_access = virtio_fs_direct_access,
	.zero_page_range = virtio_fs_zero_page_range,
};

static void virtio_fs_cleanup_dax(void *data)
{
	struct dax_device *dax_dev = data;

	kill_dax(dax_dev);
	put_dax(dax_dev);
}

DEFINE_FREE(cleanup_dax, struct dax_dev *, if (!IS_ERR_OR_NULL(_T)) virtio_fs_cleanup_dax(_T))

static int virtio_fs_setup_dax(struct virtio_device *vdev, struct virtio_fs *fs)
{
	struct dax_device *dax_dev __free(cleanup_dax) = NULL;
	struct virtio_shm_region cache_reg;
	struct dev_pagemap *pgmap;
	bool have_cache;

	if (!IS_ENABLED(CONFIG_FUSE_DAX))
		return 0;

	dax_dev = alloc_dax(fs, &virtio_fs_dax_ops);
	if (IS_ERR(dax_dev)) {
		int rc = PTR_ERR(dax_dev);
		return rc == -EOPNOTSUPP ? 0 : rc;
	}

	/* Get cache region */
	have_cache = virtio_get_shm_region(vdev, &cache_reg,
					   (u8)VIRTIO_FS_SHMCAP_ID_CACHE);
	if (!have_cache) {
		dev_notice(&vdev->dev, "%s: No cache capability\n", __func__);
		return 0;
	}

	if (!devm_request_mem_region(&vdev->dev, cache_reg.addr, cache_reg.len,
				     dev_name(&vdev->dev))) {
		dev_warn(&vdev->dev, "could not reserve region addr=0x%llx len=0x%llx\n",
			 cache_reg.addr, cache_reg.len);
		return -EBUSY;
	}

	dev_notice(&vdev->dev, "Cache len: 0x%llx @ 0x%llx\n", cache_reg.len,
		   cache_reg.addr);

	pgmap = devm_kzalloc(&vdev->dev, sizeof(*pgmap), GFP_KERNEL);
	if (!pgmap)
		return -ENOMEM;

	pgmap->type = MEMORY_DEVICE_FS_DAX;

	/* Ideally we would directly use the PCI BAR resource but
	 * devm_memremap_pages() wants its own copy in pgmap.  So
	 * initialize a struct resource from scratch (only the start
	 * and end fields will be used).
	 */
	pgmap->range = (struct range) {
		.start = (phys_addr_t) cache_reg.addr,
		.end = (phys_addr_t) cache_reg.addr + cache_reg.len - 1,
	};
	pgmap->nr_range = 1;

	fs->window_kaddr = devm_memremap_pages(&vdev->dev, pgmap);
	if (IS_ERR(fs->window_kaddr))
		return PTR_ERR(fs->window_kaddr);

	fs->window_phys_addr = (phys_addr_t) cache_reg.addr;
	fs->window_len = (phys_addr_t) cache_reg.len;

	dev_dbg(&vdev->dev, "%s: window kaddr 0x%px phys_addr 0x%llx len 0x%llx\n",
		__func__, fs->window_kaddr, cache_reg.addr, cache_reg.len);

	fs->dax_dev = no_free_ptr(dax_dev);
	return devm_add_action_or_reset(&vdev->dev, virtio_fs_cleanup_dax,
					fs->dax_dev);
}

static int virtio_fs_probe(struct virtio_device *vdev)
{
	struct virtio_fs *fs;
	int ret;

	fs = kzalloc(sizeof(*fs), GFP_KERNEL);
	if (!fs)
		return -ENOMEM;
	kobject_init(&fs->kobj, &virtio_fs_ktype);
	vdev->priv = fs;

	ret = virtio_fs_read_tag(vdev, fs);
	if (ret < 0)
		goto out;

	ret = virtio_fs_setup_fsvqs(vdev, fs);
	if (ret < 0)
		goto out;

	virtio_fs_map_queues(vdev, fs);

	ret = virtio_fs_setup_dax(vdev, fs);
	if (ret < 0)
		goto out_vqs;

	/* Bring the device online in case the filesystem is mounted and
	 * requests need to be sent before we return.
	 */
	virtio_device_ready(vdev);

	ret = virtio_fs_add_instance(vdev, fs);
	if (ret < 0)
		goto out_vqs;

	return 0;

out_vqs:
	virtio_reset_device(vdev);
	virtio_fs_cleanup_vqs(vdev);

out:
	vdev->priv = NULL;
	kobject_put(&fs->kobj);
	return ret;
}

static void virtio_fs_stop_all_queues(struct virtio_fs *fs, bool err_handling)
{
	struct virtio_fs_vq *fsvq;
	int i;

	for (i = 0; i < fs->nvqs; i++) {
		fsvq = &fs->vqs[i];
		if (!fsvq->vq)
			continue;

		spin_lock(&fsvq->lock);
		fsvq->connected = false;
		fsvq->during_err_handling = err_handling;
		spin_unlock(&fsvq->lock);
	}
}

static void virtio_fs_remove(struct virtio_device *vdev)
{
	struct virtio_fs *fs = vdev->priv;

	mutex_lock(&virtio_fs_mutex);
	/* This device is going away. No one should get new reference */
	list_del_init(&fs->list);
	virtio_fs_delete_queues_sysfs(fs);
	sysfs_remove_link(&fs->kobj, "device");
	kobject_put(fs->mqs_kobj);
	kobject_del(&fs->kobj);
	virtio_fs_stop_all_queues(fs, false);
	virtio_fs_drain_all_queues_locked(fs);
	virtio_reset_device(vdev);

	/*
	 * Cleanup VQs before requests to force unmapping DMAed
	 * buffers of in-flight notify requests.
	 */
	virtio_fs_cleanup_vqs(vdev);
	virtio_fs_free_all_queues_requests(fs);

	vdev->priv = NULL;
	/* Put device reference on virtio_fs object */
	virtio_fs_put_locked(fs);
	mutex_unlock(&virtio_fs_mutex);
}

#ifdef CONFIG_PM_SLEEP
static int virtio_fs_freeze(struct virtio_device *vdev)
{
	/* TODO need to save state here */
	pr_warn("virtio-fs: suspend/resume not yet supported\n");
	return -EOPNOTSUPP;
}

static int virtio_fs_restore(struct virtio_device *vdev)
{
	 /* TODO need to restore state here */
	return 0;
}
#endif /* CONFIG_PM_SLEEP */

static int virtio_fs_reset_prepare(struct virtio_device *vdev)
{
	struct virtio_fs *fs = vdev->priv;

	mutex_lock(&virtio_fs_mutex);

	/* Ensure no requests in virtqueues before deleting vqs. */
	virtio_fs_stop_all_queues(fs, true);
	virtio_fs_drain_all_queues_locked(fs);

	/* Ensure we don't receive any more interrupts */
	virtio_reset_device(vdev);

	virtio_fs_cleanup_vqs(vdev);

	mutex_unlock(&virtio_fs_mutex);

	return 0;
}

static int virtio_fs_reset_done(struct virtio_device *vdev)
{
	struct virtio_fs *fs = vdev->priv;
	int ret;

	mutex_lock(&virtio_fs_mutex);
	ret = virtio_fs_setup_vqs(vdev, fs, false);
	if (ret) {
		mutex_unlock(&virtio_fs_mutex);
		return ret;
	}

	virtio_fs_start_all_queues(fs);
	virtio_device_ready(vdev);
	mutex_unlock(&virtio_fs_mutex);

	return 0;
}

static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_FS, VIRTIO_DEV_ANY_ID },
	{},
};

static const unsigned int feature_table[] = {
	VIRTIO_FS_F_NOTIFICATION,
};

static struct virtio_driver virtio_fs_driver = {
	.driver.name		= KBUILD_MODNAME,
	.id_table		= id_table,
	.feature_table		= feature_table,
	.feature_table_size	= ARRAY_SIZE(feature_table),
	.probe			= virtio_fs_probe,
	.remove			= virtio_fs_remove,
#ifdef CONFIG_PM_SLEEP
	.freeze			= virtio_fs_freeze,
	.restore		= virtio_fs_restore,
#endif
	.reset_prepare		= virtio_fs_reset_prepare,
	.reset_done		= virtio_fs_reset_done,
};

#define FUSE_REQ_ID_STEP (1ULL << 1)

/*
 * The unique_id is constructed as such:
 * | 32 bits | 32 bits |
 *    qid       reqctr
 */
static u64 virtio_fs_get_unique(struct virtio_fs_vq *fsvq)
{
	u64 unique_id;

	spin_lock(&fsvq->lock);
	fsvq->reqctr += FUSE_REQ_ID_STEP;
	unique_id = ((u64)(fsvq->vq->index) << 32 | fsvq->reqctr);
	spin_unlock(&fsvq->lock);

	return unique_id;

}

static void virtio_fs_send_forget(struct fuse_mount *fm, struct fuse_forget_link *link)
{
	struct virtio_fs_forget *forget;
	struct virtio_fs_forget_req *req;
	struct virtio_fs *fs = fm->fc->priv;
	struct virtio_fs_vq *fsvq = &fs->vqs[VQ_HIPRIO];
	u64 unique = virtio_fs_get_unique(fsvq);

	/* Allocate a buffer for the request */
	forget = kmalloc(sizeof(*forget), GFP_NOFS | __GFP_NOFAIL);
	req = &forget->req;

	req->ih = (struct fuse_in_header){
		.opcode = FUSE_FORGET,
		.nodeid = link->forget_one.nodeid,
		.unique = unique,
		.len = sizeof(*req),
	};
	req->arg = (struct fuse_forget_in){
		.nlookup = link->forget_one.nlookup,
	};

	send_forget_request(fsvq, forget, false);
	kfree(link);
}

/* Count number of scatter-gather elements required */
static unsigned int sg_count_fuse_folios(struct fuse_folio_desc *folio_descs,
					 unsigned int num_folios,
					 unsigned int total_len)
{
	unsigned int i;
	unsigned int this_len;

	for (i = 0; i < num_folios && total_len; i++) {
		this_len =  min(folio_descs[i].length, total_len);
		total_len -= this_len;
	}

	return i;
}

/* Return the number of scatter-gather list elements required */
static unsigned int sg_count_fuse_req(struct fuse_req *req)
{
	struct fuse_args *args = req->args;
	struct fuse_args_pages *ap = container_of(args, typeof(*ap), args);
	unsigned int size, total_sgs = 0 /* fuse_in_header */;

	if (!test_bit(FR_NOTIFY, &req->flags))
		total_sgs += 1;

	if (args->in_numargs - args->in_pages)
		total_sgs += 1;

	if (args->in_pages) {
		size = args->in_args[args->in_numargs - 1].size;
		total_sgs += sg_count_fuse_folios(ap->descs, ap->num_folios,
						  size);
	}

	if (!test_bit(FR_ISREPLY, &req->flags))
		return total_sgs;

	total_sgs += 1 /* fuse_out_header */;

	if (args->out_numargs - args->out_pages)
		total_sgs += 1;

	if (args->out_pages) {
		size = args->out_args[args->out_numargs - 1].size;
		total_sgs += sg_count_fuse_folios(ap->descs, ap->num_folios,
						  size);
	}

	return total_sgs;
}

/* Add folios to scatter-gather list and return number of elements used */
static unsigned int sg_init_fuse_folios(struct scatterlist *sg,
					struct folio **folios,
					struct fuse_folio_desc *folio_descs,
					unsigned int num_folios,
				        unsigned int total_len)
{
	unsigned int i;
	unsigned int this_len;

	for (i = 0; i < num_folios && total_len; i++) {
		sg_init_table(&sg[i], 1);
		this_len =  min(folio_descs[i].length, total_len);
		sg_set_folio(&sg[i], folios[i], this_len, folio_descs[i].offset);
		total_len -= this_len;
	}

	return i;
}

/* Add args to scatter-gather list and return number of elements used */
static unsigned int sg_init_fuse_args(struct scatterlist *sg,
				      struct fuse_req *req,
				      struct fuse_arg *args,
				      unsigned int numargs,
				      bool argpages,
				      void *argbuf,
				      unsigned int *len_used)
{
	struct fuse_args_pages *ap = container_of(req->args, typeof(*ap), args);
	unsigned int total_sgs = 0;
	unsigned int len;

	len = fuse_len_args(numargs - argpages, args);
	if (len)
		sg_init_one(&sg[total_sgs++], argbuf, len);

	if (argpages)
		total_sgs += sg_init_fuse_folios(&sg[total_sgs],
						 ap->folios, ap->descs,
						 ap->num_folios,
						 args[numargs - 1].size);

	if (len_used)
		*len_used = len;

	return total_sgs;
}

/* Add a request to a virtqueue and kick the device */
static int virtio_fs_enqueue_req(struct virtio_fs_vq *fsvq,
				 struct virtio_fs_req *fs_req, bool in_flight,
				 gfp_t gfp)
{
	/* requests need at least 4 elements */
	struct scatterlist *stack_sgs[6];
	struct scatterlist stack_sg[ARRAY_SIZE(stack_sgs)];
	struct scatterlist **sgs = stack_sgs;
	struct scatterlist *sg = stack_sg;
	struct fuse_req *req = &fs_req->req;
	struct virtqueue *vq;
	struct fuse_args *args = req->args;
	unsigned int argbuf_used = 0;
	unsigned int out_sgs = 0;
	unsigned int in_sgs = 0;
	unsigned int total_sgs;
	unsigned int i;
	bool notify_req;
	bool notify;
	int ret;

	notify_req = test_bit(FR_NOTIFY, &req->flags);

	/* Does the sglist fit on the stack? */
	total_sgs = sg_count_fuse_req(req);
	if (total_sgs > ARRAY_SIZE(stack_sgs)) {
		sgs = kmalloc_array(total_sgs, sizeof(sgs[0]), gfp);
		sg = kmalloc_array(total_sgs, sizeof(sg[0]), gfp);
		if (!sgs || !sg) {
			ret = -ENOMEM;
			goto out;
		}
	}

	/* Use a bounce buffer since stack args cannot be mapped */
	ret = copy_args_to_argbuf(req, gfp);
	if (ret < 0)
		goto out;

	if (!notify_req) {
		/* Request elements */
		sg_init_one(&sg[out_sgs++], &req->in.h, sizeof(req->in.h));
		out_sgs += sg_init_fuse_args(&sg[out_sgs], req,
					     (struct fuse_arg *)args->in_args,
					     args->in_numargs, args->in_pages,
					     req->argbuf, &argbuf_used);
	}

	/* Reply elements */
	if (test_bit(FR_ISREPLY, &req->flags)) {
		sg_init_one(&sg[out_sgs + in_sgs++],
			    &req->out.h, sizeof(req->out.h));
		in_sgs += sg_init_fuse_args(&sg[out_sgs + in_sgs], req,
					    args->out_args, args->out_numargs,
					    args->out_pages,
					    req->argbuf + argbuf_used, NULL);
	}

	WARN_ON(out_sgs + in_sgs != total_sgs);

	for (i = 0; i < total_sgs; i++)
		sgs[i] = &sg[i];

	spin_lock(&fsvq->lock);

	if (!fsvq->connected) {
		if (fsvq->during_err_handling)
			ret = -EAGAIN;
		else
			ret = -ENOTCONN;
		spin_unlock(&fsvq->lock);
		goto out;
	}

	if (test_bit(FR_BACKGROUND, &req->flags) &&
	    fsvq->active_background == fsvq->max_background) {
		spin_unlock(&fsvq->lock);
		ret = -ENOSPC;
		goto out;
	}

	vq = fsvq->vq;
	ret = virtqueue_add_sgs(vq, sgs, out_sgs, in_sgs, req, GFP_ATOMIC);
	if (ret < 0) {
		spin_unlock(&fsvq->lock);
		goto out;
	}

	if (!notify_req) {
		/* Request successfully sent. */
		list_add_tail(&fs_req->entry, &fsvq->processing);
		if (test_bit(FR_BACKGROUND, &req->flags))
			fsvq->active_background++;
	}

	if (!in_flight)
		inc_in_flight_req(fsvq);
	notify = virtqueue_kick_prepare(vq);

	spin_unlock(&fsvq->lock);

	if (notify)
		virtqueue_notify(vq);

out:
	if (ret < 0 && req->argbuf) {
		kfree(req->argbuf);
		req->argbuf = NULL;
	}
	if (sgs != stack_sgs) {
		kfree(sgs);
		kfree(sg);
	}

	return ret;
}

static void virtio_fs_req_send_async(struct virtio_fs_req *fs_req)
{
	struct fuse_req *req = &fs_req->req;
	struct virtio_fs_vq *fsvq = fs_req->fsvq;
	int ret;

	req->in.h.len = sizeof(struct fuse_in_header) +
		fuse_len_args(req->args->in_numargs,
			      (struct fuse_arg *) req->args->in_args);

	if (req->in.h.opcode != FUSE_NOTIFY_REPLY)
		req->in.h.unique = virtio_fs_get_unique(fsvq);

	pr_debug("%s: opcode %u unique %#llx nodeid %#llx in.len %u out.len %u queue_id %u\n",
		 __func__, req->in.h.opcode, req->in.h.unique,
		 req->in.h.nodeid, req->in.h.len,
		 fuse_len_args(req->args->out_numargs, req->args->out_args),
		 fsvq->vq->index);

	ret = virtio_fs_enqueue_req(fsvq, fs_req, false, GFP_ATOMIC);
	if (ret < 0) {
		if (ret == -ENOSPC) {
			/*
			 * Virtqueue full. Retry submission from worker
			 * context.
			 */
			spin_lock(&fsvq->lock);
			list_add_tail(&fs_req->entry, &fsvq->queued_reqs);
			inc_in_flight_req(fsvq);
			spin_unlock(&fsvq->lock);
			return;
		} else if (ret == -EAGAIN) {
			spin_lock(&fsvq->lock);
			list_add_tail(&fs_req->entry, &fsvq->to_send_reqs);
			inc_in_flight_err_handling_req(fsvq);
			spin_unlock(&fsvq->lock);
			return;
		}
		req->out.h.error = ret;
		pr_err("virtio-fs: virtio_fs_enqueue_req() failed %d\n", ret);

		/* Can't end request in submission context. Use a worker */
		spin_lock(&fsvq->lock);
		list_add_tail(&fs_req->entry, &fsvq->end_reqs);
		schedule_work(&fsvq->dispatch_work);
		spin_unlock(&fsvq->lock);
		return;
	}
}

static void virtio_fs_req_send_sync(struct virtio_fs_req *fs_req)
{
	reinit_completion(&fs_req->completion);
	__set_bit(FR_WAITING, &fs_req->req.flags);
	virtio_fs_req_send_async(fs_req);
	wait_for_completion(&fs_req->completion);
}

static inline void virtio_fs_ctx_set_defaults(struct fuse_fs_context *ctx)
{
	ctx->rootmode = S_IFDIR;
	ctx->default_permissions = 1;
	ctx->allow_other = 1;
	ctx->max_read = UINT_MAX;
	ctx->blksize = 512;
	ctx->destroy = true;
	ctx->no_control = true;
	ctx->no_force_umount = true;
}

static void virtio_fs_notify_send_ack_end(struct fuse_mount *fm, struct fuse_args *args,
					  int error)
{
	struct virtio_fs_ack_req *ack_req = container_of(args, typeof(*ack_req), args);

	kfree(ack_req);
}

static void virtio_fs_notify_send_ack(struct virtio_fs *fs, uint64_t unique,
				      int err)
{
	struct virtio_fs_ack_req *ack_req;
	int rc;

	pr_debug("virtio-fs: sending ACK unique %#llx with status=%d\n", unique, err);

	ack_req = kzalloc(sizeof(*ack_req), GFP_KERNEL);
	if (!ack_req)
		return;

	ack_req->ack_in.error = -err;
	ack_req->args.opcode = FUSE_NOTIFY_REPLY;
	ack_req->args.nocreds = true;
	ack_req->args.in_numargs = 1;
	ack_req->args.in_args[0].size = sizeof(ack_req->ack_in);
	ack_req->args.in_args[0].value = &ack_req->ack_in;
	ack_req->args.end = virtio_fs_notify_send_ack_end;
	rc = __virtio_fs_simple_notify_reply(fs, NULL, &ack_req->args, unique);
	if (rc)
		kfree(ack_req);
}

static void virtio_fs_notify_send_req(struct virtio_fs *fs)
{
	/*
	 * Notify reqs are not coming from the fuse layer. Instead, we
	 * use virtiofs-generated requests allocated at vq setup time.
	 *
	 * The fuse daemon is free to reply when they need to notify
	 * us of something.
	 */
	struct virtio_fs_req *fs_req;

	fs_req = virtio_fs_req_get(&fs->vqs[VQ_NOTIFY], NULL, GFP_KERNEL, true);
	if (!fs_req) {
		pr_err("virtio-fs: cannot get notify request\n");
		return;
	}
	if (fs_req->allocated) {
		/*
		 * Should never happen - allocated request will have
		 * the wrong size, we cannot use them
		 */
		pr_err("virtio-fs: allocated notify request not supported\n");
		virtio_fs_req_put(fs_req);
		return;
	}

	/* reset before reuse */
	virtio_fs_notify_init(&fs_req->req,
			      &fs_req->notify[0].args,
			      &fs_req->notify[0].buf,
			      fs->notify_buf_size);

	set_bit(FR_ISREPLY, &fs_req->req.flags);
	set_bit(FR_ASYNC, &fs_req->req.flags);
	set_bit(FR_NOTIFY, &fs_req->req.flags);
	fs_req->notify[0].args.may_block = 1;
	virtio_fs_req_send_async(fs_req);
}

static void virtio_fs_send_all_notify_reqs(struct virtio_fs *fs)
{
	struct virtio_fs_vq *fsvq = &fs->vqs[VQ_NOTIFY];
	int i;

	/* notify requests are sent during the first mount only */
	if (fsvq->in_flight > 0)
		return;

	for (i = 0; i < fsvq->nb_reqs; i++)
		virtio_fs_notify_send_req(fs);
}

static int virtio_fs_fill_super(struct super_block *sb, struct fs_context *fsc)
{
	struct fuse_mount *fm = get_fuse_mount_super(sb);
	struct fuse_conn *fc = fm->fc;
	struct virtio_fs *fs = fc->priv;
	struct fuse_fs_context *ctx = fsc->fs_private;
	unsigned int i;
	int err;

	virtio_fs_ctx_set_defaults(ctx);
	mutex_lock(&virtio_fs_mutex);

	/* After holding mutex, make sure virtiofs device is still there.
	 * Though we are holding a reference to it, drive ->remove might
	 * still have cleaned up virtual queues. In that case bail out.
	 */
	err = -EINVAL;
	if (list_empty(&fs->list)) {
		pr_info("virtio-fs: tag <%s> not found\n", fs->tag);
		goto err;
	}

	err = -ENOMEM;
	/* Allocate fuse_dev for hiprio and notification queues */
	for (i = 0; i < fs->nvqs; i++) {
		struct virtio_fs_vq *fsvq = &fs->vqs[i];

		if (!fsvq->vq)
			continue;

		fsvq->fud = fuse_dev_alloc();
		if (!fsvq->fud)
			goto err_free_fuse_devs;
	}
	/* virtiofs allocates and installs its own fuse devices */
	ctx->fudptr = NULL;
	if (ctx->dax_mode != FUSE_DAX_NEVER) {
		if (ctx->dax_mode == FUSE_DAX_ALWAYS && !fs->dax_dev) {
			err = -EINVAL;
			pr_err("virtio-fs: dax can't be enabled as filesystem"
			       " device does not support it.\n");
			goto err_free_fuse_devs;
		}
		ctx->dax_dev = fs->dax_dev;
	}
	fc->gds = ctx->gds;
	err = fuse_fill_super_common(sb, ctx);
	if (err < 0)
		goto err_free_fuse_devs;

	for (i = 0; i < fs->nvqs; i++) {
		struct virtio_fs_vq *fsvq = &fs->vqs[i];

		if (!fsvq->vq)
			continue;

		fuse_dev_install(fsvq->fud, fc);
	}

	/* Previous unmount will stop all queues. Start these again */
	virtio_fs_start_all_queues(fs);
	fuse_send_init(fm);
	if (fs->notify_enabled)
		virtio_fs_send_all_notify_reqs(fs);
	mutex_unlock(&virtio_fs_mutex);
	return 0;

err_free_fuse_devs:
	virtio_fs_free_devs(fs);
err:
	mutex_unlock(&virtio_fs_mutex);
	return err;
}

static void virtio_fs_conn_destroy(struct fuse_mount *fm)
{
	struct fuse_conn *fc = fm->fc;
	struct virtio_fs *vfs = fc->priv;
	struct virtio_fs_vq *fsvq = &vfs->vqs[VQ_HIPRIO];

	/* Stop dax worker. Soon evict_inodes() will be called which
	 * will free all memory ranges belonging to all inodes.
	 */
	if (IS_ENABLED(CONFIG_FUSE_DAX))
		fuse_dax_cancel_work(fc);

	/* Stop forget queue. Soon destroy will be sent */
	spin_lock(&fsvq->lock);
	fsvq->connected = false;
	spin_unlock(&fsvq->lock);
	virtio_fs_drain_all_queues(vfs);

	/* fuse_conn_destroy() must have sent destroy. Stop all queues
	 * and drain one more time and free fuse devices. Freeing fuse
	 * devices will drop their reference on fuse_conn and that in
	 * turn will drop its reference on virtio_fs object.
	 */
	virtio_fs_stop_all_queues(vfs, false);
	virtio_fs_drain_all_queues(vfs);
	virtio_fs_free_devs(vfs);
}

static void virtio_kill_sb(struct super_block *sb)
{
	struct fuse_mount *fm = get_fuse_mount_super(sb);
	bool last;

	/* If mount failed, we can still be called without any fc */
	if (sb->s_root) {
		last = fuse_mount_remove(fm);
		if (last)
			virtio_fs_conn_destroy(fm);
	}
	kill_anon_super(sb);
	fuse_mount_destroy(fm);
}

static int virtio_fs_test_super(struct super_block *sb,
				struct fs_context *fsc)
{
	struct fuse_mount *fsc_fm = fsc->s_fs_info;
	struct fuse_mount *sb_fm = get_fuse_mount_super(sb);

	return fsc_fm->fc->priv == sb_fm->fc->priv;
}

static int virtio_fs_simple_background(struct fuse_mount *fm,
		struct fuse_args *args, gfp_t gfp_flags)
{
	struct fuse_conn *fc = fm->fc;
	struct virtio_fs *fs = fc->priv;
	struct virtio_fs_req *fs_req;
	unsigned int queue_id;
	struct virtio_fs_vq *fsvq;
	struct fuse_req *req;

	queue_id = fs->mq_map[raw_smp_processor_id()];
	fsvq = &fs->vqs[queue_id];

	fs_req = virtio_fs_req_get(fsvq, fm, gfp_flags, args->force);
	if (!fs_req)
		return -ENOMEM;

	req = &fs_req->req;
	if (args->force) {
		WARN_ON(!args->nocreds);
	} else {
		WARN_ON(args->nocreds);
		fuse_creds(req);
		if (unlikely(req->in.h.uid == ((uid_t)-1) ||
			     req->in.h.gid == ((gid_t)-1))) {
			virtio_fs_req_put(fs_req);
			return -EOVERFLOW;
		}
	}

	fuse_args_to_req(req, args);

	__set_bit(FR_ISREPLY, &req->flags);
	__set_bit(FR_BACKGROUND, &req->flags);
	virtio_fs_req_send_async(fs_req);

	return 0;
}

static ssize_t virtio_fs_simple_request(struct fuse_mount *fm,
		struct fuse_args *args)
{
	struct fuse_conn *fc = fm->fc;
	struct virtio_fs *fs = fc->priv;
	struct virtio_fs_req *fs_req;
	unsigned int queue_id;
	struct virtio_fs_vq *fsvq;
	struct fuse_req *req;
	gfp_t gfp_flags;
	ssize_t ret;

	queue_id = fs->mq_map[raw_smp_processor_id()];
	fsvq = &fs->vqs[queue_id];

	gfp_flags = GFP_KERNEL;
	if (args->force)
		gfp_flags |= __GFP_NOFAIL;

	fs_req = virtio_fs_req_get(fsvq, fm, gfp_flags, args->force);
	if (!fs_req)
		return -ENOMEM;

	req = &fs_req->req;
	if (args->force) {
		if (!args->nocreds)
			fuse_force_creds(req);
	} else {
		WARN_ON(args->nocreds);
		fuse_creds(req);
		if (unlikely(req->in.h.uid == ((uid_t)-1) ||
			     req->in.h.gid == ((gid_t)-1))) {
			virtio_fs_req_put(fs_req);
			return -EOVERFLOW;
		}
	}

	/* Needs to be done after req_get() so that fc->minor is valid */
	fuse_adjust_compat(fc, args);
	fuse_args_to_req(req, args);

	if (!args->noreply)
		__set_bit(FR_ISREPLY, &req->flags);
	virtio_fs_req_send_sync(fs_req);
	ret = req->out.h.error;
	if (!ret && args->out_argvar) {
		BUG_ON(args->out_numargs == 0);
		ret = args->out_args[args->out_numargs - 1].size;
	}
	virtio_fs_req_put(fs_req);

	return ret;
}

static int __virtio_fs_simple_notify_reply(struct virtio_fs *fs, struct fuse_mount *fm,
					   struct fuse_args *args, u64 unique)
{
	struct virtio_fs_req *fs_req;
	unsigned int queue_id;
	struct virtio_fs_vq *fsvq;
	struct fuse_req *req;

	queue_id = fs->mq_map[raw_smp_processor_id()];
	fsvq = &fs->vqs[queue_id];

	fs_req = virtio_fs_req_get(fsvq, fm, GFP_KERNEL, args->force);
	if (!fs_req)
		return -ENOMEM;

	req = &fs_req->req;
	if (!args->nocreds) {
		fuse_creds(req);
		if (unlikely(req->in.h.uid == ((uid_t)-1) ||
			     req->in.h.gid == ((gid_t)-1))) {
			virtio_fs_req_put(fs_req);
			return -EOVERFLOW;
		}
	}

	req->in.h.unique = unique;

	fuse_args_to_req(req, args);

	virtio_fs_req_send_async(fs_req);

	return 0;
}

static int virtio_fs_simple_notify_reply(struct fuse_mount *fm,
					 struct fuse_args *args, u64 unique)
{
	return __virtio_fs_simple_notify_reply(fm->fc->priv, fm, args, unique);
}

static void virtio_fs_conn_resend(struct fuse_conn *fc)
{
	struct virtio_fs *fs = fc->priv;
	struct virtio_fs_vq *fsvq;
	struct virtio_fs_req *fs_req, *next;
	int i;

	for (i = 0; i < fs->nvqs; i++) {
		fsvq = &fs->vqs[i];

		spin_lock(&fsvq->lock);
		list_for_each_entry_safe(fs_req, next, &fsvq->processing, entry) {
			__virtio_fs_get_request(fs_req);
			/* mark the request as resend request */
			fs_req->req.in.h.unique |= FUSE_UNIQUE_RESEND;
			list_move_tail(&fs_req->entry, &fsvq->queued_reqs);
		}

		if (!list_empty(&fsvq->queued_reqs))
			schedule_work(&fsvq->dispatch_work);
		spin_unlock(&fsvq->lock);
	}
}

static void virtio_fs_conn_abort(struct fuse_conn *fc)
{
	/* virtio_fs_conn_destroy will drain, flush and stop all VQs */
}

static void virtio_fs_conn_wait_aborted(struct fuse_conn *fc)
{
	/* virtio_fs_conn_destroy will drain, flush and stop all VQs */
}

static void virtio_fs_conn_put_priv(void *priv)
{
	struct virtio_fs *fs = priv;

	virtio_fs_put(fs);
}

static void virtio_fs_conn_init(struct fuse_conn *fc)
{
	struct virtio_fs *fs = fc->priv;
	struct virtio_fs_vq *fsvq;
	unsigned int max_background = fc->max_background;
	unsigned int base_max_background, leftovers;
	int i;

	/* Set max_background to 1 if number of request queues is bigger
	 * than max_background of the filesystem */
	if (max_background < (fs->nvqs - VQ_REQUEST)) {
		for (i = VQ_REQUEST; i < fs->nvqs; i++) {
			fsvq = &fs->vqs[i];
			spin_lock(&fsvq->lock);
			fsvq->max_background = 1;
			spin_unlock(&fsvq->lock);
		}
	} else {
		base_max_background = max_background / (fs->nvqs - VQ_REQUEST);
		leftovers = max_background % (fs->nvqs - VQ_REQUEST);

		/* Split the max_background between all the request queues and make
		 * sure max_background is not zero for each queue. */
		for (i = VQ_REQUEST; i < fs->nvqs; i++) {
			fsvq = &fs->vqs[i];
			spin_lock(&fsvq->lock);
			fsvq->max_background = base_max_background;
			if (leftovers > 0) {
				fsvq->max_background += 1;
				leftovers--;
			}
			spin_unlock(&fsvq->lock);
		}
	}

	for (i = 0; i < fs->nvqs; i++) {
		fsvq = &fs->vqs[i];
		if (!fsvq->vq)
			continue;

		spin_lock(&fsvq->lock);
		fsvq->initialized = true;
		spin_unlock(&fsvq->lock);
		complete(&fsvq->init_comp);
	}
}

static int virtio_fs_get_tree(struct fs_context *fsc)
{
	struct virtio_fs *fs;
	struct super_block *sb;
	struct fuse_conn *fc = NULL;
	struct fuse_mount *fm;
	unsigned int virtqueue_size;
	int err = -EIO;

	/* This gets a reference on virtio_fs object. This ptr gets installed
	 * in fc->priv. Once fuse_conn is going away, it calls fc->release()
	 * to drop the reference to this object.
	 */
	fs = virtio_fs_find_instance(fsc->source);
	if (!fs) {
		pr_info("virtio-fs: tag <%s> not found\n", fsc->source);
		return -EINVAL;
	}

	virtqueue_size = virtqueue_get_vring_size(fs->vqs[VQ_REQUEST].vq);
	if (WARN_ON(virtqueue_size <= FUSE_HEADER_OVERHEAD))
		goto out_err;

	err = -ENOMEM;
	fc = kzalloc(sizeof(struct fuse_conn), GFP_KERNEL);
	if (!fc)
		goto out_err;

	fm = kzalloc(sizeof(struct fuse_mount), GFP_KERNEL);
	if (!fm)
		goto out_err;

	fm->simple_request = virtio_fs_simple_request;
	fm->simple_background = virtio_fs_simple_background;
	fm->simple_notify_reply = virtio_fs_simple_notify_reply;
	fm->forget_send	= virtio_fs_send_forget;

	fuse_conn_init(fc, fm, fsc->user_ns, NULL, NULL);
	fc->priv = fs;
	fc->conn_put_priv = virtio_fs_conn_put_priv;
	fc->release = fuse_free_conn;
	fc->abort = virtio_fs_conn_abort;
	fc->wait_aborted = virtio_fs_conn_wait_aborted;
	fc->resend = virtio_fs_conn_resend;
	fc->init = virtio_fs_conn_init;

	fc->delete_stale = true;
	fc->auto_submounts = true;
	fc->sync_fs = true;
	fc->use_pages_for_kvec_io = true;

	/* Tell FUSE to split requests that exceed the virtqueue's size */
	fc->max_pages_limit = min_t(unsigned int, fc->max_pages_limit,
				    virtqueue_size - FUSE_HEADER_OVERHEAD);

	fsc->s_fs_info = fm;
	sb = sget_fc(fsc, virtio_fs_test_super, set_anon_super_fc);
	if (fsc->s_fs_info)
		fuse_mount_destroy(fm);
	if (IS_ERR(sb))
		return PTR_ERR(sb);

	if (!sb->s_root) {
		err = virtio_fs_fill_super(sb, fsc);
		if (err) {
			deactivate_locked_super(sb);
			return err;
		}

		sb->s_flags |= SB_ACTIVE;
	}

	WARN_ON(fsc->root);
	fsc->root = dget(sb->s_root);
	return 0;

out_err:
	kfree(fc);
	virtio_fs_put(fs);
	return err;
}

static const struct fs_context_operations virtio_fs_context_ops = {
	.free		= virtio_fs_free_fsc,
	.parse_param	= virtio_fs_parse_param,
	.get_tree	= virtio_fs_get_tree,
};

static int virtio_fs_init_fs_context(struct fs_context *fsc)
{
	struct fuse_fs_context *ctx;

	if (fsc->purpose == FS_CONTEXT_FOR_SUBMOUNT)
		return fuse_init_fs_context_submount(fsc);

	ctx = kzalloc(sizeof(struct fuse_fs_context), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	fsc->fs_private = ctx;
	fsc->ops = &virtio_fs_context_ops;
	return 0;
}

static struct file_system_type virtio_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "virtiofs",
	.init_fs_context = virtio_fs_init_fs_context,
	.kill_sb	= virtio_kill_sb,
	.fs_flags	= FS_ALLOW_IDMAP,
};

static int virtio_fs_uevent(const struct kobject *kobj, struct kobj_uevent_env *env)
{
	const struct virtio_fs *fs = container_of(kobj, struct virtio_fs, kobj);

	add_uevent_var(env, "TAG=%s", fs->tag);
	return 0;
}

static const struct kset_uevent_ops virtio_fs_uevent_ops = {
	.uevent = virtio_fs_uevent,
};

static int __init virtio_fs_sysfs_init(void)
{
	virtio_fs_kset = kset_create_and_add("virtiofs", &virtio_fs_uevent_ops,
					     fs_kobj);
	if (!virtio_fs_kset)
		return -ENOMEM;
	return 0;
}

static void virtio_fs_sysfs_exit(void)
{
	kset_unregister(virtio_fs_kset);
	virtio_fs_kset = NULL;
}

static int __init virtio_fs_init(void)
{
	int ret;

	pr_info("virtio-fs: Loading NVIDIA-virtiofs +mq +lockless +nvq +flr +gds\n");

	fuse_inode_cachep = kmem_cache_create("nvidiavfs_inode",
                                      sizeof(struct fuse_inode), 0,
                                      SLAB_HWCACHE_ALIGN|SLAB_ACCOUNT|SLAB_RECLAIM_ACCOUNT,
                                      fuse_inode_init_once);

	if (!fuse_inode_cachep)
		return -ENOMEM;

	ret = virtio_fs_sysfs_init();
	if (ret < 0)
		goto cache_cleanup;

	ret = register_virtio_driver(&virtio_fs_driver);
	if (ret < 0)
		goto sysfs_exit;

	ret = register_filesystem(&virtio_fs_type);
	if (ret < 0)
		goto unregister_virtio_driver;

	sanitize_global_limit(&max_user_bgreq);
	sanitize_global_limit(&max_user_congthresh);

	return 0;

unregister_virtio_driver:
	unregister_virtio_driver(&virtio_fs_driver);
sysfs_exit:
	virtio_fs_sysfs_exit();
cache_cleanup:
	kmem_cache_destroy(fuse_inode_cachep);

	return ret;
}
module_init(virtio_fs_init);

static void __exit virtio_fs_exit(void)
{
	unregister_filesystem(&virtio_fs_type);
	unregister_virtio_driver(&virtio_fs_driver);
	virtio_fs_sysfs_exit();
	kmem_cache_destroy(fuse_inode_cachep);
}
module_exit(virtio_fs_exit);

MODULE_AUTHOR("Stefan Hajnoczi <stefanha@redhat.com>");
MODULE_DESCRIPTION("Virtio Filesystem");
MODULE_LICENSE("GPL");
MODULE_ALIAS_FS(KBUILD_MODNAME);
MODULE_DEVICE_TABLE(virtio, id_table);
