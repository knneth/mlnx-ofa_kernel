#ifndef _COMPAT_LINUX_BPF_H
#define _COMPAT_LINUX_BPF_H

#include "../../compat/config.h"

#include_next <linux/bpf.h>

#if defined(HAVE_XDP_CONVERT_TO_XDP_FRAME) && \
    defined(HAVE_XDP_REDIRECT)
#define HAVE_XDP
#else
#undef HAVE_XDP
#endif

#if defined(HAVE_XDP_CONVERT_TO_XDP_FRAME) && \
    defined(HAVE_XDP_REDIRECT)
#define HAVE_XDP_EXTENDED
#else
#undef HAVE_XDP_EXTENDED
#endif


/*Note - if you use HAVE_XDP_ENABLE define you should include <linux/bpf.h> in file you use this define*/
#if defined(HAVE_XDP) || defined(HAVE_XDP_EXTENDED)
#define HAVE_XDP_ENABLE
#else
#undef HAVE_XDP_ENABLE
#endif

#ifdef HAVE_XDP_SUPPORT
#endif/* HAVE_XDP_SUPPORT */

#ifndef XDP_PACKET_HEADROOM
#define XDP_PACKET_HEADROOM 256
#endif

#endif /* _COMPAT_LINUX_BPF_H */
