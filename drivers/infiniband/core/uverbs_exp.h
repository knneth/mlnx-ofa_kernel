#ifndef UVERBS_EXP_H
#define UVERBS_EXP_H

#include <linux/kref.h>
#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/cdev.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_user_verbs_exp.h>

struct ib_udct_object {
	struct ib_uevent_object	uevent;
};

typedef int (*uverbs_ex_cmd)(struct ib_uverbs_file *file,
			     struct ib_device *ib_dev,
			     struct ib_udata *ucore,
			     struct ib_udata *uhw);

#define IB_UVERBS_DECLARE_EXP_CMD(name)				\
	int ib_uverbs_exp_##name(struct ib_uverbs_file *file,	\
				struct ib_device *ib_dev,	\
				 struct ib_udata *ucore,	\
				 struct ib_udata *uhw)

IB_UVERBS_DECLARE_EXP_CMD(create_qp);
IB_UVERBS_DECLARE_EXP_CMD(modify_cq);
IB_UVERBS_DECLARE_EXP_CMD(query_device);
IB_UVERBS_DECLARE_EXP_CMD(create_cq);
IB_UVERBS_DECLARE_EXP_CMD(modify_qp);
IB_UVERBS_DECLARE_EXP_CMD(reg_mr);
IB_UVERBS_DECLARE_EXP_CMD(create_dct);
IB_UVERBS_DECLARE_EXP_CMD(destroy_dct);
IB_UVERBS_DECLARE_EXP_CMD(query_dct);
IB_UVERBS_DECLARE_EXP_CMD(arm_dct);
IB_UVERBS_DECLARE_EXP_CMD(create_mr);
IB_UVERBS_DECLARE_EXP_CMD(prefetch_mr);
IB_UVERBS_DECLARE_EXP_CMD(create_flow);
IB_UVERBS_DECLARE_EXP_CMD(query_mkey);
IB_UVERBS_DECLARE_EXP_CMD(create_wq);
IB_UVERBS_DECLARE_EXP_CMD(modify_wq);
IB_UVERBS_DECLARE_EXP_CMD(destroy_wq);
IB_UVERBS_DECLARE_EXP_CMD(create_rwq_ind_table);
IB_UVERBS_DECLARE_EXP_CMD(destroy_rwq_ind_table);

unsigned long ib_uverbs_exp_get_unmapped_area(struct file *filp,
					      unsigned long addr,
					      unsigned long len, unsigned long pgoff,
					      unsigned long flags);
long ib_uverbs_exp_ioctl(struct file *filp,
			 unsigned int cmd, unsigned long arg);

void ib_uverbs_async_handler(struct ib_uverbs_file *file,
			     __u64 element, __u64 event,
			     struct list_head *obj_list,
			     u32 *counter);
void ib_uverbs_dct_event_handler(struct ib_event *event, void *context_ptr);

void ib_uverbs_exp_cleanup_dct_ucontext(struct ib_uverbs_file *file,
					struct ib_ucontext *context);

int ib_uverbs_create_flow_common(struct ib_uverbs_file *file,
				 struct ib_device *ib_dev,
				 struct ib_udata *ucore,
				 struct ib_udata *uhw,
				 bool is_exp);
#endif
