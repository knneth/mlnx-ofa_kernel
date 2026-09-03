#ifndef _COMPAT_LINUX_IRQ_H
#define _COMPAT_LINUX_IRQ_H 1

#include "../../compat/config.h"

#include_next <linux/irq.h>

#ifndef HAVE_IRQ_GET_EFFECTIVE_AFFINITY_MASK
static inline
const struct cpumask *irq_get_effective_affinity_mask(unsigned int irq)
{
	struct irq_data *d = irq_get_irq_data(irq);

	return d ? irq_data_get_effective_affinity_mask(d) : NULL;
}
#endif

#endif	/* _COMPAT_LINUX_IRQ_H */
