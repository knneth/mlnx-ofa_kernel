#ifndef _COMPAT_LINUX_SCHED_MM_H
#define _COMPAT_LINUX_SCHED_MM_H

#include "../../../compat/config.h"

#ifdef HAVE_SCHED_MM_H
#include_next <linux/sched/mm.h>
#endif

#include_next <linux/sched.h>

#ifndef HAVE_MMGET_NOT_ZERO
#ifndef HAVE_SCHED_MMGET_NOT_ZERO
static inline bool mmget_not_zero(struct mm_struct *mm)
{
	return atomic_inc_not_zero(&mm->mm_users);
}
#endif
#endif

#ifndef HAVE_MMGRAB
static inline void mmgrab(struct mm_struct *mm)
{
	atomic_inc(&mm->mm_count);
}
#endif

#ifndef HAVE_MMGET
static inline void mmget(struct mm_struct *mm)
{
	atomic_inc(&mm->mm_users);
}

#endif

#endif /* _COMPAT_LINUX_SCHED_MM_H */
