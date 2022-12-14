#ifndef _COMPAT_UAPI_LINUX_EVENTPOLL_H
#define _COMPAT_UAPI_LINUX_EVENTPOLL_H

#include "../../../compat/config.h"

#include_next <uapi/linux/eventpoll.h>

#ifndef EPOLLIN
#include <linux/poll.h>
#define EPOLLIN		POLLIN
#define EPOLLOUT	POLLOUT
#define EPOLLERR        POLLERR
#define EPOLLWRNORM	POLLWRNORM
#define EPOLLRDNORM	POLLRDNORM
#define EPOLLRDHUP	POLLRDHUP
#endif

#endif /* _COMPAT_UAPI_LINUX_EVENTPOLL_H */
