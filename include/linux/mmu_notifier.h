#ifndef _COMPAT_LINUX_MMU_NOTIFIER_H
#define _COMPAT_LINUX_MMU_NOTIFIER_H

#include "../../compat/config.h"

#include_next <linux/mmu_notifier.h>

#ifndef HAVE_MMU_NOTIFIER_CALL_SRCU
#define mmu_notifier_call_srcu LINUX_BACKPORT(mmu_notifier_call_srcu)
extern void mmu_notifier_call_srcu(struct rcu_head *rcu, void (*func)(struct rcu_head *rcu));
#endif

#ifndef HAVE_MMU_NOTIFIER_SYNCHRONIZE
#define mmu_notifier_synchronize LINUX_BACKPORT(mmu_notifier_synchronize)
extern void mmu_notifier_synchronize(void);
#endif

#endif /* _COMPAT_LINUX_MMU_NOTIFIER_H */
