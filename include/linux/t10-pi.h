#ifndef _COMPAT_LINUX_T10_PI_H
#define _COMPAT_LINUX_T10_PI_H 1

#include "../../compat/config.h"


#include_next <linux/t10-pi.h>

/*
 * A T10 PI-capable target device can be formatted with different
 * protection schemes.	Currently 0 through 3 are defined:
 *
 * Type 0 is regular (unprotected) I/O
 *
 * Type 1 defines the contents of the guard and reference tags
 *
 * Type 2 defines the contents of the guard and reference tags and
 * uses 32-byte commands to seed the latter
 *
 * Type 3 defines the contents of the guard tag only
 */

#ifndef HAVE_T10_PI_PREPARE
#if defined(CONFIG_BLK_DEV_INTEGRITY) && !defined(HAVE_EXT_PI_REF_TAG)
static inline void t10_pi_prepare(struct request *rq, u8 protection_type)
{
	const int tuple_sz = sizeof(struct t10_pi_tuple);
	u32 ref_tag = t10_pi_ref_tag(rq);
	struct bio *bio;

	if (protection_type == T10_PI_TYPE3_PROTECTION)
		return;

	__rq_for_each_bio(bio, rq) {
		struct bio_integrity_payload *bip = bio_integrity(bio);
		u32 virt = bip_get_seed(bip) & 0xffffffff;
		struct bio_vec iv;
		struct bvec_iter iter;

		/* Already remapped? */
		if (bip->bip_flags & BIP_MAPPED_INTEGRITY)
			break;

		bip_for_each_vec(iv, bip, iter) {
			void *p, *pmap;
			unsigned int j;

			pmap = kmap_atomic(iv.bv_page);
			p = pmap + iv.bv_offset;
			for (j = 0; j < iv.bv_len; j += tuple_sz) {
				struct t10_pi_tuple *pi = p;

				if (be32_to_cpu(pi->ref_tag) == virt)
					pi->ref_tag = cpu_to_be32(ref_tag);
				virt++;
				ref_tag++;
				p += tuple_sz;
			}

			kunmap_atomic(pmap);
		}

		bip->bip_flags |= BIP_MAPPED_INTEGRITY;
	}
}

static inline void t10_pi_complete(struct request *rq, u8 protection_type,
				   unsigned int intervals)
{
	const int tuple_sz = sizeof(struct t10_pi_tuple);
	u32 ref_tag = t10_pi_ref_tag(rq);
	struct bio *bio;

	if (protection_type == T10_PI_TYPE3_PROTECTION)
		return;

	__rq_for_each_bio(bio, rq) {
		struct bio_integrity_payload *bip = bio_integrity(bio);
		u32 virt = bip_get_seed(bip) & 0xffffffff;
		struct bio_vec iv;
		struct bvec_iter iter;

		bip_for_each_vec(iv, bip, iter) {
			void *p, *pmap;
			unsigned int j;

			pmap = kmap_atomic(iv.bv_page);
			p = pmap + iv.bv_offset;
			for (j = 0; j < iv.bv_len && intervals; j += tuple_sz) {
				struct t10_pi_tuple *pi = p;

				if (be32_to_cpu(pi->ref_tag) == ref_tag)
					pi->ref_tag = cpu_to_be32(virt);
				virt++;
				ref_tag++;
				intervals--;
				p += tuple_sz;
			}

			kunmap_atomic(pmap);
		}
	}
}
#else
static inline void t10_pi_complete(struct request *rq, u8 protection_type,
				   unsigned int intervals)
{
}
static inline void t10_pi_prepare(struct request *rq, u8 protection_type)
{
}
#endif
#endif /* HAVE_T10_PI_PREPARE */

#endif /* _COMPAT_LINUX_T10_PI_H */
