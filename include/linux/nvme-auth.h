#ifndef _COMPAT_LINUX_NVME_AUTH_H
#define _COMPAT_LINUX_NVME_AUTH_H

#include "../../compat/config.h"

#include_next <linux/nvme-auth.h>

#if defined(CONFIG_NVME_TCP_TLS) && defined(HAVE_NVME_AUTH_TRANSFORM_KEY_DHCHAP)
#ifndef HAVE_NVME_AUTH_GENERATE_PSK
int nvme_auth_generate_psk(u8 hmac_id, u8 *skey, size_t skey_len,
                           u8 *c1, u8 *c2, size_t hash_len,
                           u8 **ret_psk, size_t *ret_len);
#endif
#ifndef HAVE_NVME_AUTH_GENERATE_DIGEST
int nvme_auth_generate_digest(u8 hmac_id, u8 *psk, size_t psk_len,
			      char *subsysnqn, char *hostnqn, u8 **ret_digest);
#endif
#ifndef HAVE_NVME_AUTH_DERIVE_TLS_PSK
static inline int nvme_auth_derive_tls_psk(int hmac_id, u8 *psk, size_t psk_len,
					   u8 *psk_digest, u8 **ret_psk)
{
	return 0;
}
#endif

#endif

#endif /* _COMPAT_LINUX_NVME_AUTH_H */
