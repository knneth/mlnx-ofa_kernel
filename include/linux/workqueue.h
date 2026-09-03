#ifndef _COMPAT_LINUX_WORKQUEUE_H
#define _COMPAT_LINUX_WORKQUEUE_H

#include "../../compat/config.h"

#include_next <linux/workqueue.h>

#ifndef HAVE_WQ_PERCPU
#define WQ_PERCPU 0
#endif

#ifndef HAVE_SYSTEM_PERCPU_WQ
#define system_percpu_wq system_wq
#endif

#ifndef HAVE_SYSTEM_DFL_WQ
#define system_dfl_wq system_wq
#endif

#endif /* _COMPAT_LINUX_WORKQUEUE_H */
