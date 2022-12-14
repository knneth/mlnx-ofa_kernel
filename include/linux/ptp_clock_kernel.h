#ifndef LINUX_PTP_CLOCK_KERNEL_H
#define LINUX_PTP_CLOCK_KERNEL_H 1

#include "../../compat/config.h"

#if defined (CONFIG_PTP_1588_CLOCK) || defined(CONFIG_PTP_1588_CLOCK_MODULE)
#include_next <linux/ptp_clock_kernel.h>
#endif

#endif	/* LINUX_PTP_CLOCK_KERNEL_H */
