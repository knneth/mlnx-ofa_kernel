#ifndef _COMPAT_LINUX_EVENTPOLL_H
#define _COMPAT_LINUX_EVENTPOLL_H

#include "../../compat/config.h"

#include_next <linux/eventpoll.h>

#ifndef EPOLLRDHUP
#define EPOLLRDHUP      (__force __poll_t)0x00002000
#endif

#endif /* _COMPAT_LINUX_EVENTPOLL_H */
