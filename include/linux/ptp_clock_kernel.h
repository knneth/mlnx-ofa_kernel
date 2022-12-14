#ifndef _COMPAT_LINUX_PTP_CLOCK_KERNEL_H
#define _COMPAT_LINUX_PTP_CLOCK_KERNEL_H

#include "../../compat/config.h"

#if defined (CONFIG_PTP_1588_CLOCK) || defined(CONFIG_PTP_1588_CLOCK_MODULE)
#include_next <linux/ptp_clock_kernel.h>
#endif

#endif /* _COMPAT_LINUX_PTP_CLOCK_KERNEL_H */
