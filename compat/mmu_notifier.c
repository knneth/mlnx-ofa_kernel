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
#endif

#ifndef HAVE_MMU_NOTIFIER_UNREGISTER_NO_RELEASE
#include <linux/mmu_notifier.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#ifndef HAVE_MMU_NOTIFIER_HAS_LOCK
#ifdef HAVE_MM_STRUCT_HAS_NOTIFIER_SUBSCRIPTION
struct mmu_notifier_subscriptions {
#else
struct mmu_notifier_mm {
#endif	
	/* all mmu notifiers registered in this mm are queued in this list */
	struct hlist_head list;
	bool has_itree;
	/* to serialize the list modifications and hlist_unhashed */
	spinlock_t lock;
	unsigned long invalidate_seq;
	unsigned long active_invalidate_ranges;
	struct rb_root_cached itree;
	wait_queue_head_t wq;
	struct hlist_head deferred_list;
};
#endif

void mmu_notifier_unregister_no_release(struct mmu_notifier *mn,
					struct mm_struct *mm)
{
#ifdef HAVE_MM_STRUCT_HAS_NOTIFIER_SUBSCRIPTION
	spin_lock(&mm->notifier_subscriptions->lock);
#else
	spin_lock(&mm->mmu_notifier_mm->lock);
#endif	
	/*
	 * Can not use list_del_rcu() since __mmu_notifier_release
	 * can delete it before we hold the lock.
	 */
	hlist_del_init_rcu(&mn->hlist);
#ifdef HAVE_MM_STRUCT_HAS_NOTIFIER_SUBSCRIPTION
	spin_unlock(&mm->notifier_subscriptions->lock);
#else
	spin_unlock(&mm->mmu_notifier_mm->lock);
#endif	

	BUG_ON(atomic_read(&mm->mm_count) <= 0);
	mmdrop(mm);
}
EXPORT_SYMBOL_GPL(mmu_notifier_unregister_no_release);
#endif
#endif
#endif
