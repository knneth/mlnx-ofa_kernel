#ifndef LINUX_PTP_CLOCK_KERNEL_H
#define LINUX_PTP_CLOCK_KERNEL_H 1

#include "../../compat/config.h"

#include_next <linux/ptp_clock_kernel.h>

#ifndef HAVE_PTP_CLOCK_REGISTER_2_PARAMS
#define ptp_clock_register(a, b) (ptp_clock_register(a))
#endif
#endif	/* LINUX_PTP_CLOCK_KERNEL_H */
