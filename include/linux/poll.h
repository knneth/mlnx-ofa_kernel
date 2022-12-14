#ifndef _COMPAT_LINUX_POLL_H
#define _COMPAT_LINUX_POLL_H

#include "../../compat/config.h"

#include_next <linux/poll.h>

#ifndef EPOLLIN
#define EPOLLIN		POLLIN
#define EPOLLOUT	POLLOUT
#define EPOLLWRNORM	POLLWRNORM
#define EPOLLRDNORM	POLLRDNORM
#endif

#endif /* _COMPAT_LINUX_POLL_H */
