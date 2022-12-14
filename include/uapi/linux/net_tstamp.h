#ifndef _COMPAT_UAPI_LINUX_NET_TSTAMP_H
#define _COMPAT_UAPI_LINUX_NET_TSTAMP_H

#include "../../../compat/config.h"

#include_next <uapi/linux/net_tstamp.h>

#ifndef HAVE_HWTSTAMP_FILTER_NTP_ALL
#define HWTSTAMP_FILTER_NTP_ALL	15
#endif

#endif /* _COMPAT_UAPI_LINUX_NET_TSTAMP_H */
