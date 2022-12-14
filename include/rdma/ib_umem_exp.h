#ifndef IB_UMEM_EXP_H
#define IB_UMEM_EXP_H

#include <linux/list.h>
#include <linux/scatterlist.h>
#include <linux/workqueue.h>

struct ib_umem;
int ib_umem_map_to_vma(struct ib_umem *umem,
				struct vm_area_struct *vma);
#endif
