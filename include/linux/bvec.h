/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _COMPAT_LINUX_BVEC_H
#define _COMPAT_LINUX_BVEC_H

#include "../../compat/config.h"

#include_next <linux/bvec.h>

#ifndef HAVE_MP_BVEC_ITER_BVEC
#define mp_bvec_iter_bvec(bvec, iter)	bvec_iter_bvec((bvec), (iter))
#endif

#ifndef HAVE_BVEC_ITER_ADVANCE_SINGLE
/* Older kernels (<5.11): provide bvec_iter_advance_single as a static inline.
 * Copied verbatim from upstream 6b6667aa4d1e "block: optimise for_each_bvec()
 * advance". Uses only standard bio_vec / bvec_iter fields that have been in
 * <linux/bvec.h> since well before 5.4.
 */
static inline void bvec_iter_advance_single(const struct bio_vec *bv,
					    struct bvec_iter *iter,
					    unsigned int bytes)
{
	unsigned int done = iter->bi_bvec_done + bytes;

	if (done == bv[iter->bi_idx].bv_len) {
		done = 0;
		iter->bi_idx++;
	}
	iter->bi_bvec_done = done;
	iter->bi_size -= bytes;
}
#endif /* !HAVE_BVEC_ITER_ADVANCE_SINGLE */

#endif /* _COMPAT_LINUX_BVEC_H */
