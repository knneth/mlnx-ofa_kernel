#ifndef _COMPAT_LINUX_INTERRUPT_H
#define _COMPAT_LINUX_INTERRUPT_H

#include_next<linux/interrupt.h>

/* Include the autogenerated header file */
#include "../../compat/config.h"

#ifndef HAVE_IRQ_AFFINITY_DESC
/**
 * struct irq_affinity_desc - Interrupt affinity descriptor
 * @mask:	cpumask to hold the affinity assignment
 * @is_managed: 1 if the interrupt is managed internally
 */
struct irq_affinity_desc {
	struct cpumask	mask;
	unsigned int	is_managed : 1;
};
#endif

#endif /* _COMPAT_LINUX_INTERRUPT_H */