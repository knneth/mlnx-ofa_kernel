#ifndef _COMPAT_LINUX_CPU_RMAP_H
#define _COMPAT_LINUX_CPU_RMAP_H

#include "../../compat/config.h"

#include_next <linux/cpu_rmap.h>


#ifndef HAVE_IRQ_CPU_RMAP_REMOVE
static inline int irq_cpu_rmap_remove(struct cpu_rmap *rmap, int irq)
{
	return irq_set_affinity_notifier(irq, NULL);
}
#endif

#endif /* _COMPAT_LINUX_CPU_RMAP_H */
