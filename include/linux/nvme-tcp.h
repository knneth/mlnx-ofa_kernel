#ifndef _COMPAT_LINUX_NVME_TCP_H
#define _COMPAT_LINUX_NVME_TCP_H

#include "../../compat/config.h"

#include_next <linux/nvme-tcp.h>

#ifndef HAVE_NVME_TCP_MIN_C2HTERM_PLEN
#define NVME_TCP_MIN_C2HTERM_PLEN      24
#define NVME_TCP_MAX_C2HTERM_PLEN      152
#endif

#endif /* _COMPAT_LINUX_NVME_TCP_H */
