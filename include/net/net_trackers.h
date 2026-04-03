/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _COMPAT_NET_NET_TRACKERS_H
#define _COMPAT_NET_NET_TRACKERS_H

#include "../../compat/config.h"

#if defined(HAVE_LINUX_REF_TRACKER_H) && defined(HAVE_NET_NET_TRACKERS_H)
#include_next <net/net_trackers.h>
#else

#ifndef HAVE_NETDEVICE_TRACKER
#ifdef CONFIG_NET_DEV_REFCNT_TRACKER
typedef struct ref_tracker *netdevice_tracker;
#else
typedef struct {} netdevice_tracker;
#endif

#ifdef CONFIG_NET_NS_REFCNT_TRACKER
typedef struct ref_tracker *netns_tracker;
#else
typedef struct {} netns_tracker;
#endif
#endif /* HAVE_NETDEVICE_TRACKER */
#endif /* HAVE_LINUX_REF_TRACKER_H */

#endif /* _COMPAT_NET_NET_TRACKERS_H */
