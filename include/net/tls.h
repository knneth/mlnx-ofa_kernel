#ifndef _COMPAT_NET_TLS_H
#define _COMPAT_NET_TLS_H 1

#include "../../compat/config.h"

#include_next <net/tls.h>

#if defined(HAVE_KTLS_STRUCTS) && !defined(HAVE_TLS_DRIVER_CTX)

static inline void *__tls_driver_ctx(struct tls_context *tls_ctx,
				     enum tls_offload_ctx_dir direction)
{
	if (direction == TLS_OFFLOAD_CTX_DIR_TX)
		return tls_offload_ctx_tx(tls_ctx)->driver_state;
	else
		return tls_offload_ctx_rx(tls_ctx)->driver_state;
}

static inline void *
tls_driver_ctx(const struct sock *sk, enum tls_offload_ctx_dir direction)
{
	return __tls_driver_ctx(tls_get_ctx(sk), direction);
}

#endif

#endif	/* _COMPAT_NET_TLS_H */
