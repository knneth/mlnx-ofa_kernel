#ifndef _MLNX_LINUX_REFCOUNT_H
#define _MLNX_LINUX_REFCOUNT_H

#include "../../compat/config.h"

#ifdef HAVE_REFCOUNT
#include_next <linux/refcount.h>
#else /* HAVE_REFCOUNT */

/* simply map back to atomic interface */

#include <linux/atomic.h>

#define refcount_t		atomic_t
#define refcount_set		atomic_set
#define refcount_inc		atomic_inc
#define refcount_dec		atomic_dec
#define refcount_read		atomic_read
#define refcount_inc_not_zero	atomic_inc_not_zero
#define refcount_dec_and_test	atomic_dec_and_test

#endif /* HAVE_REFCOUNT */


#endif /* _MLNX_LINUX_REFCOUNT_H */
