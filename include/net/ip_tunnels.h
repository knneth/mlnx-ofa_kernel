#ifndef _COMPAT_NET_IP_TUNNELS_H
#define _COMPAT_NET_IP_TUNNELS_H

#include "../../compat/config.h"

#include_next <net/ip_tunnels.h>

#ifndef HAVE_IP_TUNNEL_INFO_OPTS_SET_4_PARAMS
#define ip_tunnel_info_opts_set(a,b,c,d) ip_tunnel_info_opts_set(a,b,c)
#endif

#endif /* _COMPAT_NET_IP_TUNNELS_H */
