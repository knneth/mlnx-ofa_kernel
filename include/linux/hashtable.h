#ifndef COMPAT_LINUX_HASHTABLE_H
#define COMPAT_LINUX_HASHTABLE_H

#include "../../compat/config.h"

#ifdef HAVE_LINUX_HASHTABLE_H
#include_next <linux/hashtable.h>
#endif

#ifndef DECLARE_HASHTABLE
#include <linux/types.h>
#define DECLARE_HASHTABLE(name, bits)                                   	\
	struct hlist_head name[1 << (bits)]
#endif

#ifndef hash_init
#include <linux/types.h>
#include <linux/list.h>
#define HASH_SIZE(name) (ARRAY_SIZE(name))
static inline void __hash_init(struct hlist_head *ht, unsigned int sz)
{
	unsigned int i;

	for (i = 0; i < sz; i++)
		INIT_HLIST_HEAD(&ht[i]);
}

/**
 * hash_init - initialize a hash table
 * @hashtable: hashtable to be initialized
 *
 * Calculates the size of the hashtable from the given parameter, otherwise
 * same as hash_init_size.
 *
 * This has to be a macro since HASH_BITS() will not work on pointers since
 * it calculates the size during preprocessing.
 */
#define hash_init(hashtable) __hash_init(hashtable, HASH_SIZE(hashtable))
#endif /* hash_init */

#endif /* COMPAT_LINUX_HASHTABLE_H */
