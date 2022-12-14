#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
#ifdef CONFIG_MMU_NOTIFIER
#ifndef HAVE_MMU_NOTIFIER_CALL_SRCU
#include <linux/mmu_notifier.h>
DEFINE_STATIC_SRCU(srcu);
void mmu_notifier_call_srcu(struct rcu_head *rcu,
			    void (*func)(struct rcu_head *rcu))
{
	call_srcu(&srcu, rcu, func);
}
EXPORT_SYMBOL_GPL(mmu_notifier_call_srcu);
#ifndef HAVE_MMU_NOTIFIER_SYNCHRONIZE
void mmu_notifier_synchronize(void)
{
        synchronize_srcu(&srcu);
}
EXPORT_SYMBOL_GPL(mmu_notifier_synchronize);
#endif
#endif
#endif
#endif
