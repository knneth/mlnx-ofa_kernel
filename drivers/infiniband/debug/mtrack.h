#ifndef __mtrack_h_
#define __mtrack_h_

#include "memtrack.h"

#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/io.h>           /* For ioremap_nocache, ioremap, iounmap */
#include <linux/random.h>
# include <linux/io-mapping.h>	/* For ioremap_nocache, ioremap, iounmap */
#include <linux/mm.h>           /* For all page handling */
#include <linux/workqueue.h>    /* For all work-queue handling */
#include <linux/scatterlist.h>  /* For using scatterlists */
#include <linux/skbuff.h>       /* For skbufs handling */
#include <asm/uaccess.h>	/* For copy from/to user */
#include <linux/export.h>
#include <linux/module.h>
#include <linux/pci.h>		/* for pci_vpd_alloc */

#define MEMTRACK_ERROR_INJECTION_MESSAGE(module, file, line, call_func, func) ({ \
	printk(KERN_ERR "%s::%s::%s failure injected at %s:%d\n", module->name, call_func, func, file, line);\
	dump_stack();								\
})

#ifdef ZERO_OR_NULL_PTR
#define IS_VALID_ADDR(addr) (!ZERO_OR_NULL_PTR(addr))
#else
#define IS_VALID_ADDR(addr) (addr)
#endif

#ifdef CONFIG_ARM64
#ifndef CONFIG_GENERIC_IOREMAP
#undef ioremap
static inline void *ioremap(phys_addr_t phys_addr, size_t size)
{
	return __ioremap(phys_addr, size, __pgprot(PROT_DEVICE_nGnRE));
}
#endif /* CONFIG_GENERIC_IOREMAP */

#undef ioremap_nocache
static inline void *ioremap_nocache(phys_addr_t phys_addr, size_t size)
{
#ifndef CONFIG_GENERIC_IOREMAP
	return __ioremap(phys_addr, size, __pgprot(PROT_DEVICE_nGnRE));
#else
	return ioremap_prot(phys_addr, size, PROT_DEVICE_nGnRE);
#endif
}

#undef ioremap_wc
static inline void *ioremap_wc(phys_addr_t phys_addr, size_t size)
{
#ifndef CONFIG_GENERIC_IOREMAP
	return __ioremap(phys_addr, size, __pgprot(PROT_NORMAL_NC));
#else
	return ioremap_prot(phys_addr, size, PROT_NORMAL_NC);
#endif
}

/* ARCH_HAS_IOREMAP_WC was defined for arm64 until 2014-07-24 */
#ifndef ARCH_HAS_IOREMAP_WC
#define ARCH_HAS_IOREMAP_WC 1
#endif

#ifdef iounmap
#undef iounmap
static inline void iounmap(void *addr)
{
	__iounmap(addr);
}
#endif /* iounmap  */
#endif /* CONFIG_ARM64 */

static inline void *mlx5_mtrack_kzalloc(size_t size, gfp_t flags)
{
	return kzalloc(size, flags);
}

static inline void *mlx5_mtrack_kzalloc_node(size_t size, gfp_t flags, int node)
{
	return kzalloc_node(size, flags, node);
}

static inline void *mlx5_mtrack_kvzalloc(size_t size, gfp_t flags)
{
	return kvzalloc(size, flags);
}

static inline void *mlx5_mtrack_kvmalloc_array(size_t n, size_t size, gfp_t flags)
{
	return kvmalloc_array(n, size, flags);
}

static inline void *mlx5_mtrack_kvcalloc(size_t n, size_t size, gfp_t flags)
{
	return kvcalloc(n, size, flags);
}

static inline void *mlx5_mtrack_kcalloc_node(size_t n, size_t size, gfp_t flags, int node)
{
		return kcalloc_node(n, size, flags, node);
}

static inline void *mlx5_mtrack_kcalloc(size_t n, size_t size, gfp_t flags)
{
	return kcalloc(n, size, flags);
}

static inline void *mlx5_mtrack_kmalloc(size_t size, gfp_t flags)
{
	return kmalloc(size, flags);
}

#ifdef HAVE_PCI_VPD_ALLOC
static inline void *mlx5_mtrack_pci_vpd_alloc(struct pci_dev *pci_dev, unsigned int *size_ptr)
{
	return pci_vpd_alloc(pci_dev, size_ptr);
}
#endif

static inline void *mlx5_mtrack_kmalloc_node(size_t size, gfp_t flags, int node)
{
	return kmalloc_node(size, flags, node);
}

static inline void *mlx5_mtrack_krealloc(const void *objp, size_t new_size, gfp_t flags)
{
	return krealloc(objp, new_size, flags);
}

static inline void *mlx5_mtrack_kvmalloc(size_t size, gfp_t flags)
{
	return kvmalloc(size, flags);
}

static inline void *mlx5_mtrack_kvmalloc_node(size_t size, gfp_t flags, int node)
{
	return kvmalloc_node(size, flags, node);
}

static inline void *mlx5_mtrack_kvzalloc_node(size_t size, gfp_t flags, int node)
{
	return kvzalloc_node(size, flags, node);
}

static inline void *mlx5_mtrack_kmalloc_array(size_t n, size_t size, gfp_t flags)
{
	return kmalloc_array(n, size, flags);
}

static inline void *mlx5_mtrack_kmemdup(const void *src, size_t len, gfp_t gfp)
{
	return kmemdup(src, len, gfp);
}

static inline void *mlx5_mtrack_kmemdup_nul(const char *src, size_t len, gfp_t gfp)
{
	return kmemdup_nul(src, len, gfp);
}

static inline void *mlx5_mtrack_kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	return kmem_cache_alloc(cachep, flags);
}

static inline void *mlx5_mtrack_vmalloc(unsigned long size)
{
	return vmalloc(size);
}

static inline void *mlx5_mtrack_vmalloc_node(unsigned long size, int node)
{
	return vmalloc_node(size, node);
}

static inline struct page *mlx5_mtrack_alloc_pages_node(int nid, gfp_t gfp_mask, unsigned int order)
{
	return alloc_pages_node(nid, gfp_mask, order);
}

static inline struct page *mlx5_mtrack_dev_alloc_pages(unsigned int order)
{
	return dev_alloc_pages(order);
}

static inline struct page *mlx5_mtrack_alloc_pages(gfp_t gfp, unsigned int order)
{
	return alloc_pages(gfp, order);
}

static inline unsigned long mlx5_mtrack___get_free_pages(gfp_t gfp_mask, unsigned int order)
{
	return __get_free_pages(gfp_mask, order);
}

static inline unsigned long mlx5_mtrack_get_zeroed_page(gfp_t gfp_mask)
{
	return get_zeroed_page(gfp_mask);
}

#undef kzalloc
#define kzalloc(size, flags) ({							\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kzalloc", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kzalloc");\
	else									\
		__memtrack_addr = mlx5_mtrack_kzalloc(size, flags);		\
	if (IS_VALID_ADDR(__memtrack_addr) && !is_non_trackable_alloc_func(__func__)) {	\
		memtrack_alloc(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), size, 0UL, 0, __FILE__, __LINE__, flags); \
	}									\
	__memtrack_addr;							\
})

#undef kzalloc_node
#define kzalloc_node(size, flags, node) ({					\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kzalloc_node", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kzalloc_node"); \
	else									\
		__memtrack_addr = mlx5_mtrack_kzalloc_node(size, flags, node);	\
	if (IS_VALID_ADDR(__memtrack_addr) && (size) > 0 &&			\
	    !is_non_trackable_alloc_func(__func__)) {				\
		memtrack_alloc(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), size, 0UL, 0, __FILE__, __LINE__, flags); \
	}									\
	__memtrack_addr;							\
})

#undef kvzalloc
#define kvzalloc(size, flags) ({						\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kvzalloc", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kvzalloc"); \
	else									\
		__memtrack_addr = mlx5_mtrack_kvzalloc(size, flags);		\
	if (IS_VALID_ADDR(__memtrack_addr) && !is_non_trackable_alloc_func(__func__)) {	\
		memtrack_alloc(MEMTRACK_KVMALLOC, 0UL, (unsigned long)(__memtrack_addr), size, 0UL, 0, __FILE__, __LINE__, flags); \
	}									\
	__memtrack_addr;							\
})

#undef kvmalloc_array
#define kvmalloc_array(n, size, flags) ({					\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kvmalloc_array", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kvmalloc_array"); \
	else									\
		__memtrack_addr = mlx5_mtrack_kvmalloc_array(n, size, flags);	\
	if (IS_VALID_ADDR(__memtrack_addr) && \
	    !is_non_trackable_alloc_func(__func__) && (n) * (size) > 0) {	\
		memtrack_alloc(MEMTRACK_KVMALLOC, 0UL, (unsigned long)(__memtrack_addr), (n)*size, 0UL, 0, __FILE__, __LINE__, flags); \
	}									\
	__memtrack_addr;							\
})

#undef kvcalloc
#define kvcalloc(n, size, flags) ({						\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kvcalloc", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kvcalloc"); \
	else									\
		__memtrack_addr = mlx5_mtrack_kvcalloc(n, size, flags);		\
	if (IS_VALID_ADDR(__memtrack_addr) &&					\
	    !is_non_trackable_alloc_func(__func__)) {				\
		memtrack_alloc(MEMTRACK_KVMALLOC, 0UL, (unsigned long)(__memtrack_addr),(n)*(size), 0UL, 0, __FILE__, __LINE__, flags); \
	}									\
	__memtrack_addr;							\
})

#undef kcalloc_node
#define kcalloc_node(n, size, flags, node) ({					\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kcalloc_node", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kcalloc_node"); \
	else									\
		__memtrack_addr = mlx5_mtrack_kcalloc_node(n, size, flags, node);	\
	if (IS_VALID_ADDR(__memtrack_addr) && (size) > 0 &&			\
	    !is_non_trackable_alloc_func(__func__)) {				\
		memtrack_alloc(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr),(n) * (size), 0UL, 0, __FILE__, __LINE__, flags); \
	}									\
	__memtrack_addr;							\
})

#undef kcalloc
#define kcalloc(n, size, flags) ({ \
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kcalloc", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kcalloc");\
	else									\
		__memtrack_addr = mlx5_mtrack_kcalloc(n, size, flags);			\
	if (IS_VALID_ADDR(__memtrack_addr) && (n) * (size) > 0 &&		\
	    !is_non_trackable_alloc_func(__func__)) {				\
		memtrack_alloc(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), (n)*(size), 0UL, 0, __FILE__, __LINE__, flags); \
	}									\
	__memtrack_addr;							\
})

#undef kmalloc
#define kmalloc(sz, flgs) ({							\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kmalloc", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kmalloc");\
	else									\
		__memtrack_addr = mlx5_mtrack_kmalloc(sz, flgs);		\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), sz, 0UL, 0, __FILE__, __LINE__, flgs); \
		if (memtrack_randomize_mem())					\
			memset(__memtrack_addr, 0x5A, sz);			\
	}									\
	__memtrack_addr;							\
})

#ifdef HAVE_PCI_VPD_ALLOC
#undef pci_vpd_alloc
#define pci_vpd_alloc(pci_dev, size_ptr) ({					\
	void *__memtrack_addr = NULL;						\
	unsigned int __memtrack_size;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "pci_vpd_alloc", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "pci_vpd_alloc"); \
	else {								\
		__memtrack_addr = mlx5_mtrack_pci_vpd_alloc(pci_dev, &__memtrack_size);		\
		if (size_ptr != NULL) 						\
			*size_ptr = __memtrack_size;				\
	} 									\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), __memtrack_size, 0UL, 0, __FILE__, __LINE__, GFP_KERNEL); \
	}									\
	__memtrack_addr;							\
})
#endif

#undef kmalloc_node
#define kmalloc_node(sz, flgs, node) ({						\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kmalloc_node", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kmalloc_node"); \
	else									\
		__memtrack_addr = mlx5_mtrack_kmalloc_node(sz, flgs, node);			\
	if (__memtrack_addr) {							\
		memtrack_alloc(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), sz, 0UL, 0, __FILE__, __LINE__, flgs); \
		if (memtrack_randomize_mem() && ((flgs) == GFP_KERNEL))		\
			memset(__memtrack_addr, 0x5A, sz);			\
	}									\
	__memtrack_addr;							\
})

#undef krealloc
#define krealloc(p, new_size, flags) ({	\
	void *__memtrack_addr = NULL;	\
	void *__old_addr = (void *)p;   \
					\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "krealloc", __func__, __LINE__))		\
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "krealloc");\
	else {												\
		if (IS_VALID_ADDR(__old_addr) &&			                                        \
			!is_non_trackable_alloc_func(__func__)) {				\
			memtrack_free(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__old_addr), 0UL, 0, __FILE__, __LINE__); \
		}												\
		__memtrack_addr = mlx5_mtrack_krealloc(p, new_size, flags);				\
	}												\
	if (IS_VALID_ADDR(__memtrack_addr) && !is_non_trackable_alloc_func(__func__)) {			\
		memtrack_alloc(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), new_size, 0UL, 0, __FILE__, __LINE__, flags);\
	}												\
	__memtrack_addr;										\
})

#undef kvmalloc
#define kvmalloc(sz, flgs) ({						\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kvmalloc", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kvmalloc"); \
	else									\
		__memtrack_addr = mlx5_mtrack_kvmalloc(sz, flgs);			\
	if (IS_VALID_ADDR(__memtrack_addr) && !is_non_trackable_alloc_func(__func__)) {\
		memtrack_alloc(MEMTRACK_KVMALLOC, 0UL, (unsigned long)(__memtrack_addr), sz, 0UL, 0, __FILE__, __LINE__, flgs); \
		if (memtrack_randomize_mem() && ((flgs) == GFP_KERNEL))		\
			memset(__memtrack_addr, 0x5A, sz);			\
	}									\
	__memtrack_addr;							\
})

#undef kvmalloc_node
#define kvmalloc_node(sz, flgs, node) ({						\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kvmalloc_node", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kvmalloc_node"); \
	else									\
		__memtrack_addr = mlx5_mtrack_kvmalloc_node(sz, flgs, node);	\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_KVMALLOC, 0UL, (unsigned long)(__memtrack_addr), sz, 0UL, 0, __FILE__, __LINE__, flgs); \
		if (memtrack_randomize_mem() && ((flgs) == GFP_KERNEL))		\
			memset(__memtrack_addr, 0x5A, sz);			\
	}									\
	__memtrack_addr;							\
})

#undef kvzalloc_node
#define kvzalloc_node(sz, flgs, node) ({						\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kvzalloc_node", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kvzalloc_node"); \
	else									\
		__memtrack_addr = mlx5_mtrack_kvzalloc_node(sz, flgs, node);	\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_KVMALLOC, 0UL, (unsigned long)(__memtrack_addr), sz, 0UL, 0, __FILE__, __LINE__, flgs); \
	}									\
	__memtrack_addr;							\
})

#undef kmalloc_array
#define kmalloc_array(n, size, flags) ({ \
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kmalloc_array", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kmalloc_array"); \
	else									\
		__memtrack_addr = mlx5_mtrack_kmalloc_array(n, size, flags);	\
	if (IS_VALID_ADDR(__memtrack_addr) && (n) * (size) > 0) {		\
		memtrack_alloc(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), (n)*(size), 0UL, 0, __FILE__, __LINE__, flags); \
	}									\
	__memtrack_addr;							\
})

#undef kmemdup
#define kmemdup(src, sz, flgs) ({						\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kmemdup", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kmemdup");\
	else									\
		__memtrack_addr = mlx5_mtrack_kmemdup(src, sz, flgs);		\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), sz, 0UL, 0, __FILE__, __LINE__, flgs); \
	}									\
	__memtrack_addr;							\
})

#undef kmemdup_nul
#define kmemdup_nul(src, sz, flgs) ({						\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kmemdup_nul", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kmemdup_nul");\
	else									\
		__memtrack_addr = mlx5_mtrack_kmemdup_nul(src, sz, flgs);	\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), sz, 0UL, 0, __FILE__, __LINE__, flgs); \
	}									\
	__memtrack_addr;							\
})

#ifndef kstrdup
#define kstrdup(src, flgs) ({						\
	void *__memtrack_addr = NULL;						\
	size_t sz = strlen(src) + 1;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kstrdup", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kstrdup");\
	else									\
		__memtrack_addr = kstrdup(src, flgs);			\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), sz, 0UL, 0, __FILE__, __LINE__, flgs); \
	}									\
	__memtrack_addr;							\
})
#endif

#define kfree(addr) ({								\
	void *__memtrack_addr = (void *)addr;					\
										\
	if (IS_VALID_ADDR(__memtrack_addr) &&					\
	    !is_non_trackable_free_func(__func__)) {				\
		memtrack_free(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), 0UL, 0, __FILE__, __LINE__); \
	}									\
	kfree(__memtrack_addr);							\
})

#ifdef kfree_rcu
	#undef kfree_rcu
#endif
#if !defined(__kvfree_rcu) && !defined(__kfree_rcu)
/*
 * Removed __kvfree_rcu macro upstream v5.12
 * commit 5ea5d1ed572c ("rcu: Eliminate the __kvfree_rcu() macro")
 */

#ifdef HAVE_KFREE_RCU_MIGHTSLEEP
/* 
 * Due to v6.3 changes
 * commit 04a522b7da3dbc083f8ae0aa1a6184b959a8f81c
 * rcu: Refactor kvfree_call_rcu() and high-level helpers
 */
#define __kvfree_rcu(ptr, rhf) \
do {									\
	typeof (ptr) ___p = (ptr);					\
									\
	if (___p) {									\
		BUILD_BUG_ON(!__is_kvfree_rcu_offset(offsetof(typeof(*(ptr)), rhf)));	\
		kvfree_call_rcu(&((___p)->rhf), (void *) (___p));			\
	}										\
} while (0)
#else /* ifdef kfree_rcu_mightsleep */
#define __kvfree_rcu(head, offset) \
       do { \
              BUILD_BUG_ON(!__is_kvfree_rcu_offset(offset)); \
              kvfree_call_rcu(head, (rcu_callback_t)(unsigned long)(offset)); \
       } while (0)
#endif /* ifdef kfree_rcu_mightsleep */
#endif /* !defined(__kvfree_rcu) && !defined(kfree_rcu) */

#ifdef __kvfree_rcu

#ifdef HAVE_KFREE_RCU_MIGHTSLEEP
#define kfree_rcu_2(ptr, rhf) ({						\
	void *__memtrack_addr = (void *)ptr;					\
										\
	if (IS_VALID_ADDR(__memtrack_addr) &&					\
	    !is_non_trackable_free_func(__func__)) {				\
		memtrack_free(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), 0UL, 0, __FILE__, __LINE__); \
	}									\
	__kvfree_rcu(ptr, rhf);					\
})

#define __kvfree_rcu_1(ptr)                                   	\
do {                                                            \
        typeof(ptr) ___p = (ptr);                               \
                                                                \
        if (___p)                                               \
		kvfree_call_rcu(NULL, (void *) (___p));         \
} while (0)
#else /* ifdef kfree_rcu_mightsleep */
#define kfree_rcu_2(addr, rcu_head) ({								\
	void *__memtrack_addr = (void *)addr;					\
										\
	if (IS_VALID_ADDR(__memtrack_addr) &&					\
	    !is_non_trackable_free_func(__func__)) {				\
		memtrack_free(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), 0UL, 0, __FILE__, __LINE__); \
	}									\
	__kvfree_rcu(&((addr)->rcu_head), offsetof(typeof(*(addr)), rcu_head));					\
})

#define __kvfree_rcu_1(ptr)                                   	\
do {                                                            \
        typeof(ptr) ___p = (ptr);                               \
                                                                \
        if (___p)                                               \
                kvfree_call_rcu(NULL, (rcu_callback_t) (___p)); \
} while (0)
#endif /* ifdef kfree_rcu_mightsleep */

#else

#define kfree_rcu_2(addr, rcu_head) ({								\
	void *__memtrack_addr = (void *)addr;					\
										\
	if (IS_VALID_ADDR(__memtrack_addr) &&					\
	    !is_non_trackable_free_func(__func__)) {				\
		memtrack_free(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), 0UL, 0, __FILE__, __LINE__); \
	}									\
	__kfree_rcu(&((addr)->rcu_head), offsetof(typeof(*(addr)), rcu_head));					\
})

#define __kvfree_rcu_1(ptr)                                   	\
do {                                                            \
        typeof(ptr) ___p = (ptr);                               \
                                                                \
        if (___p)                                               \
                kfree_call_rcu(NULL, (rcu_callback_t) (___p)); \
} while (0)

#endif /* __kvfree_rcu */

/* commit 1835f475e351 ("rcu: Introduce single argument kvfree_rcu() interface") */
/* commit 7e3f926bf4538 ("rcu/kvfree: Eliminate k[v]free_rcu() single argument macro */
#undef kvfree_rcu_arg_1
#undef kvfree_rcu_arg_2
#undef kvfree_rcu

#define kvfree_rcu_arg_1(ptr) ({ 						\
	void *__memtrack_addr = (void *)ptr;					\
										\
	if (IS_VALID_ADDR(__memtrack_addr) &&					\
	    !is_non_trackable_free_func(__func__)) {				\
		memtrack_free(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), 0UL, 0, __FILE__, __LINE__); \
	}									\
	__kvfree_rcu_1(ptr);					\
})

#define kfree_rcu(ptr, rhf) kvfree_rcu_arg_2(ptr, rhf)
#define kvfree_rcu(ptr, rhf) kvfree_rcu_arg_2(ptr, rhf)

#define kvfree_rcu_arg_2(ptr, rhf) kfree_rcu_2(ptr, rhf)


#undef vmalloc
#define vmalloc(size) ({							\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "vmalloc", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "vmalloc");\
	else									\
		__memtrack_addr = mlx5_mtrack_vmalloc(size);				\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_VMALLOC, 0UL, (unsigned long)(__memtrack_addr), size, 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
		if (memtrack_randomize_mem())					\
			memset(__memtrack_addr, 0x5A, size);			\
	}									\
	__memtrack_addr;							\
})

#ifndef vzalloc
#define vzalloc(size) ({							\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "vzalloc", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "vzalloc");\
	else									\
		__memtrack_addr = vzalloc(size);				\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_VMALLOC, 0UL, (unsigned long)(__memtrack_addr), size, 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
	}									\
	__memtrack_addr;							\
})
#endif

#ifndef vzalloc_node
#define vzalloc_node(size, node) ({						\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "vzalloc_node", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "vzalloc_node"); \
	else									\
		__memtrack_addr = vzalloc_node(size, node);			\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_VMALLOC, 0UL, (unsigned long)(__memtrack_addr), size, 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
	}									\
	__memtrack_addr;							\
})
#endif

#ifndef __vmalloc
#ifdef HAVE_VMALLOC_3_PARAM
#define __vmalloc(size, mask, prot) ({						\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "__vmalloc", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "__vmalloc"); \
	else									\
		__memtrack_addr = __vmalloc(size, mask, prot);			\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_VMALLOC, 0UL, (unsigned long)(__memtrack_addr), size, 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
		if (memtrack_randomize_mem())					\
			memset(__memtrack_addr, 0x5A, size);			\
	}									\
	__memtrack_addr;							\
})
#else
#define __vmalloc(size, mask) ({						\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "__vmalloc", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "__vmalloc"); \
	else									\
		__memtrack_addr = __vmalloc(size, mask);			\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_VMALLOC, 0UL, (unsigned long)(__memtrack_addr), size, 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
		if (memtrack_randomize_mem())					\
			memset(__memtrack_addr, 0x5A, size);			\
	}									\
	__memtrack_addr;							\
})
#endif
#endif

#undef vmalloc_node
#define vmalloc_node(size, node) ({						\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "vmalloc_node", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "vmalloc_node"); \
	else									\
		__memtrack_addr = mlx5_mtrack_vmalloc_node(size, node);		\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_VMALLOC, 0UL, (unsigned long)(__memtrack_addr), size, 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
		if (memtrack_randomize_mem())					\
			memset(__memtrack_addr, 0x5A, size);			\
	}									\
	__memtrack_addr;							\
})

#define vfree(addr) ({ \
	void *__memtrack_addr = (void *)addr;					\
	if (IS_VALID_ADDR(__memtrack_addr) && !is_non_trackable_free_func(__func__)) {	\
		memtrack_free(MEMTRACK_VMALLOC, 0UL, (unsigned long)(__memtrack_addr), 0UL, 0, __FILE__, __LINE__); \
	}									\
	vfree(__memtrack_addr);							\
})

#ifndef kvfree
#define kvfree(addr) ({								\
	void *__memtrack_addr = (void *)addr;					\
	if (IS_VALID_ADDR(__memtrack_addr) && !is_non_trackable_free_func(__func__)) {	\
		if (is_vmalloc_addr(__memtrack_addr)) {				\
			memtrack_free(MEMTRACK_VMALLOC, 0UL, (unsigned long)(__memtrack_addr), 0UL, 0, __FILE__, __LINE__); \
		} else {							\
			memtrack_free(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), 0UL, 0, __FILE__, __LINE__); \
		}								\
	}									\
	kvfree(__memtrack_addr);						\
})
#endif

#ifndef memdup_user
#define memdup_user(user_addr, size) ({						\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "memdup_user", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "memdup_user"); \
	else									\
		__memtrack_addr = memdup_user(user_addr, size);			\
										\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), size, 0UL, 0, __FILE__, __LINE__, GFP_KERNEL); \
	}									\
	__memtrack_addr;							\
})
#endif

#ifndef memdup_user_nul
#define memdup_user_nul(user_addr, size) ({						\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "memdup_user_nul", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "memdup_user_nul"); \
	else									\
		__memtrack_addr = memdup_user_nul(user_addr, size);			\
										\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), size, 0UL, 0, __FILE__, __LINE__, GFP_KERNEL); \
	}									\
	__memtrack_addr;							\
})
#endif

#undef kmem_cache_alloc
#define kmem_cache_alloc(cache, flags) ({					\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kmem_cache_alloc", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kmem_cache_alloc"); \
	else									\
		__memtrack_addr = mlx5_mtrack_kmem_cache_alloc(cache, flags);	\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_KMEM_OBJ, 0UL, (unsigned long)(__memtrack_addr), 1, 0UL, 0, __FILE__, __LINE__, flags); \
	}									\
	__memtrack_addr;							\
})

#undef kmem_cache_zalloc
#define kmem_cache_zalloc(cache, flags) ({					\
	void *__memtrack_addr = NULL;						\
										\
	__memtrack_addr = kmem_cache_alloc(cache, flags | __GFP_ZERO);		\
	__memtrack_addr;							\
})

#define kmem_cache_free(cache, addr) ({						\
	void *__memtrack_addr = (void *)addr;					\
										\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_free(MEMTRACK_KMEM_OBJ, 0UL, (unsigned long)(__memtrack_addr), 0UL, 0, __FILE__, __LINE__); \
	}									\
	kmem_cache_free(cache, __memtrack_addr);				\
})

#ifndef kasprintf
#define kasprintf(gfp, fmt, ...) ({						\
	void *__memtrack_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "kasprintf", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "kasprintf"); \
	else									\
		__memtrack_addr = kasprintf(gfp, fmt, __VA_ARGS__);		\
	if (IS_VALID_ADDR(__memtrack_addr) && !is_non_trackable_alloc_func(__func__) && strncmp((char *)__memtrack_addr, "infiniband", 10)) {	\
		memtrack_alloc(MEMTRACK_KMALLOC, 0UL, (unsigned long)(__memtrack_addr), strlen((char *)__memtrack_addr), 0UL, 0, __FILE__, __LINE__, gfp); \
	}									\
	__memtrack_addr;							\
})
#endif

/* All IO-MAP handling */
#ifdef ioremap
	#undef ioremap
#endif
#define ioremap(phys_addr, size) ({						\
	void __iomem *__memtrack_addr = NULL;					\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "ioremap", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "ioremap");\
	else									\
		__memtrack_addr = ioremap(phys_addr, size);			\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_IOREMAP, 0UL, (unsigned long)(__memtrack_addr), size, 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
	}									\
	__memtrack_addr;							\
})

#ifdef ioremap_wc
        #define kernel_has_ioremap_wc 1
	#undef ioremap_wc
#endif

#if defined(ARCH_HAS_IOREMAP_WC) || defined(kernel_has_ioremap_wc)
#define ioremap_wc(phys_addr, size) ({						\
	void __iomem *__memtrack_addr = NULL;					\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "ioremap_wc", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "ioremap_wc");\
	else									\
		__memtrack_addr = ioremap_wc(phys_addr, size);			\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_IOREMAP, 0UL, (unsigned long)(__memtrack_addr), size, 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
	}									\
	__memtrack_addr;							\
})
#else
#define ioremap_wc(phys_addr, size) ({						\
	void __iomem *__memtrack_addr = NULL;					\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "ioremap_wc", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "ioremap_wc");\
	else									\
		__memtrack_addr = ioremap_nocache(phys_addr, size);			\
	__memtrack_addr;							\
})
#endif

#define io_mapping_create_wc(base, size) ({					\
	void __iomem *__memtrack_addr = NULL;					\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "io_mapping_create_wc", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "io_mapping_create_wc"); \
	else									\
		__memtrack_addr = io_mapping_create_wc(base, size);		\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_IOREMAP, 0UL, (unsigned long)(__memtrack_addr), size, 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
	}									\
	__memtrack_addr;							\
})

#define io_mapping_free(addr) ({						\
	void *__memtrack_addr = (void *)addr;					\
										\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_free(MEMTRACK_IOREMAP, 0UL, (unsigned long)(__memtrack_addr), 0UL, 0, __FILE__, __LINE__); \
	}									\
	io_mapping_free(__memtrack_addr);					\
})

#ifdef ioremap_nocache
	#undef ioremap_nocache
#endif
#ifdef CONFIG_PPC
#define ioremap_nocache(phys_addr, size) ({					\
	void __iomem *__memtrack_addr = NULL;					\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "ioremap_nocache", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "ioremap_nocache"); \
	else									\
		__memtrack_addr = ioremap(phys_addr, size);			\
	__memtrack_addr;							\
})
#else
#define ioremap_nocache(phys_addr, size) ({ \
	void __iomem *__memtrack_addr = NULL;					\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "ioremap_nocache", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "ioremap_nocache"); \
	else									\
		__memtrack_addr = ioremap_nocache(phys_addr, size);		\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_alloc(MEMTRACK_IOREMAP, 0UL, (unsigned long)(__memtrack_addr), size, 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
	}									\
	__memtrack_addr;							\
})
#endif	/* PPC */

#ifdef iounmap
	#undef iounmap
#endif
#define iounmap(addr) ({							\
	void *__memtrack_addr = (void *)addr;					\
										\
	if (IS_VALID_ADDR(__memtrack_addr)) {					\
		memtrack_free(MEMTRACK_IOREMAP, 0UL, (unsigned long)(__memtrack_addr), 0UL, 0, __FILE__, __LINE__); \
	}									\
	iounmap(__memtrack_addr);						\
})


/* All Page handlers */
/* TODO: Catch netif_rx for page dereference */
#undef alloc_pages_node
#define alloc_pages_node(nid, gfp_mask, order) ({				\
	struct page *page_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "alloc_pages_node", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "alloc_pages_node"); \
	else									\
	page_addr = (struct page *)mlx5_mtrack_alloc_pages_node(nid, gfp_mask, order);	\
	if (page_addr && !is_non_trackable_alloc_func(__func__)) {		\
		memtrack_alloc(MEMTRACK_PAGE_ALLOC, 0UL, (unsigned long)(page_addr), (unsigned long)(order), 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
	}									\
	page_addr;								\
})

#undef dev_alloc_pages
#define dev_alloc_pages(order) ({                              \
	struct page *page_addr = NULL;                                          \
                                                                        \
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "dev_alloc_pages", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "dev_alloc_pages"); \
	else                                                                    \
	page_addr = (struct page *)mlx5_mtrack_dev_alloc_pages(order);     	\
	if (page_addr && !is_non_trackable_alloc_func(__func__)) {              \
		memtrack_alloc(MEMTRACK_PAGE_ALLOC, 0UL, (unsigned long)(page_addr), (unsigned long)(order), 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
	}                                                                       \
	page_addr;                                                              \
})

#ifdef HAVE_SPLIT_PAGE_EXPORTED
#define split_page(pg, order) ({					\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "split_page", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "split_page"); \
	else {								\
		int i;							\
		split_page(pg, order);					\
		for (i = 1; i < (1 << order); i++) {			\
			struct page *page_addr = &pg[i];		\
			if (page_addr && !is_non_trackable_alloc_func(__func__)) {	\
				memtrack_alloc(MEMTRACK_PAGE_ALLOC, 0UL, (unsigned long)(page_addr), (unsigned long)(order), 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
			}						\
		}							\
	}								\
})
#endif

#undef alloc_pages
#ifdef CONFIG_NUMA
#define alloc_pages(gfp_mask, order) ({						\
	struct page *page_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "alloc_pages", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "alloc_pages"); \
	else									\
		page_addr = (struct page *)mlx5_mtrack_alloc_pages(gfp_mask, order);	\
	if (page_addr && !is_non_trackable_alloc_func(__func__)) {		\
		memtrack_alloc(MEMTRACK_PAGE_ALLOC, 0UL, (unsigned long)(page_addr), (unsigned long)(order), 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
	}									\
	page_addr;								\
})
#else
#define alloc_pages(gfp_mask, order) ({						\
	struct page *page_addr;							\
										\
	page_addr = (struct page *)mlx5_mtrack_alloc_pages_node(numa_node_id(), gfp_mask, order); \
	page_addr;								\
})
#endif

#undef __get_free_pages
#define __get_free_pages(gfp_mask, order) ({					\
	struct page *page_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "__get_free_pages", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "__get_free_pages"); \
	else									\
		page_addr = (struct page *)mlx5_mtrack___get_free_pages(gfp_mask, order);	\
	if (page_addr && !is_non_trackable_alloc_func(__func__)) {		\
		memtrack_alloc(MEMTRACK_PAGE_ALLOC, 0UL, (unsigned long)(page_addr), (unsigned long)(order), 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
	}									\
	(unsigned long)page_addr;						\
})

#undef get_zeroed_page
#define get_zeroed_page(gfp_mask) ({						\
	struct page *page_addr = NULL;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "get_zeroed_page", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "get_zeroed_page"); \
	else									\
		page_addr = (struct page *)mlx5_mtrack_get_zeroed_page(gfp_mask);	\
	if (page_addr && !is_non_trackable_alloc_func(__func__)) {		\
		memtrack_alloc(MEMTRACK_PAGE_ALLOC, 0UL, (unsigned long)(page_addr), 0, 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
	}									\
	(unsigned long)page_addr;						\
})

#define __free_pages(addr, order) ({						\
	void *__memtrack_addr = (void *)addr;					\
										\
	if (__memtrack_addr && !is_non_trackable_alloc_func(__func__)) {	\
		if (!memtrack_check_size(MEMTRACK_PAGE_ALLOC, (unsigned long)(__memtrack_addr), (unsigned long)(order), __FILE__, __LINE__)) \
			memtrack_free(MEMTRACK_PAGE_ALLOC, 0UL, (unsigned long)(__memtrack_addr), 0UL, 0, __FILE__, __LINE__); \
	}									\
	__free_pages(addr, order);						\
})


#define free_pages(addr, order) ({						\
	void *__memtrack_addr = (void *)addr;					\
										\
	if (__memtrack_addr && !is_non_trackable_alloc_func(__func__)) {	\
		if (!memtrack_check_size(MEMTRACK_PAGE_ALLOC, (unsigned long)(__memtrack_addr), (unsigned long)(order), __FILE__, __LINE__)) \
			memtrack_free(MEMTRACK_PAGE_ALLOC, 0UL, (unsigned long)(__memtrack_addr), 0UL, 0, __FILE__, __LINE__); \
	}									\
	free_pages(addr, order);						\
})


#define get_page(addr) ({							\
	void *__memtrack_addr = (void *)addr;					\
										\
	if (__memtrack_addr && !is_non_trackable_alloc_func(__func__)) {	\
		if (memtrack_is_new_addr(MEMTRACK_PAGE_ALLOC, (unsigned long)(__memtrack_addr), 0, __FILE__, __LINE__)) { \
			memtrack_alloc(MEMTRACK_PAGE_ALLOC, 0UL, (unsigned long)(__memtrack_addr), 0, 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
		}								\
	}									\
	get_page(addr);								\
})

#define get_user_pages_fast(start, nr_pages, write, pages) ({			\
	int __memtrack_rc = -1;							\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "get_user_pages_fast", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "get_user_pages_fast"); \
	else									\
		__memtrack_rc = get_user_pages_fast(start, nr_pages, write, pages); \
	if (__memtrack_rc > 0 && !is_non_trackable_alloc_func(__func__)) {	\
		int __memtrack_i;						\
										\
		for (__memtrack_i = 0; __memtrack_i < __memtrack_rc; __memtrack_i++) \
			memtrack_alloc(MEMTRACK_PAGE_ALLOC, 0UL, (unsigned long)(pages[__memtrack_i]), 0, 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
	}									\
	__memtrack_rc;								\
})

#define put_page(addr) ({							\
	void *__memtrack_addr = (void *)addr;					\
										\
	if (__memtrack_addr && !is_non_trackable_alloc_func(__func__)) {	\
		/* Check whether this is not part of umem put page & not */\
		/* a new addr and the ref-count is 1 then we'll free this addr */\
		/* Don't change the order these conditions */			\
		if (!is_umem_put_page(__func__) && \
		    !memtrack_is_new_addr(MEMTRACK_PAGE_ALLOC, (unsigned long)(__memtrack_addr), 1, __FILE__, __LINE__) && \
		    (memtrack_get_page_ref_count((unsigned long)(__memtrack_addr)) == 1)) { \
			memtrack_free(MEMTRACK_PAGE_ALLOC, 0UL, (unsigned long)(__memtrack_addr), 0UL, 0, __FILE__, __LINE__); \
		}								\
	}									\
	put_page(addr);								\
})


/* Work-Queue handlers */
#ifdef create_workqueue
	#undef create_workqueue
#endif
#ifdef create_rt_workqueue
	#undef create_rt_workqueue
#endif
#ifdef create_freezeable_workqueue
	#undef create_freezeable_workqueue
#endif
#ifdef create_singlethread_workqueue
	#undef create_singlethread_workqueue
#endif

#if defined(alloc_ordered_workqueue)
	#undef alloc_ordered_workqueue
#endif

#ifdef alloc_workqueue
/* In kernels < 5.1, alloc_workqueue was a macro */
#undef alloc_workqueue
#ifdef CONFIG_LOCKDEP
#define alloc_workqueue(name, flags, max_active, args...)			\
({										\
	static struct lock_class_key __key;					\
	const char *__lock_name;						\
	struct workqueue_struct *wq_addr = NULL;				\
										\
	if (__builtin_constant_p(name))						\
		__lock_name = (name);						\
	else									\
		__lock_name = #name;						\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "alloc_workqueue", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "alloc_workqueue"); \
	else									\
		wq_addr = __alloc_workqueue_key((name), (flags), (max_active),	\
						&__key, __lock_name, ##args);	\
	if (wq_addr) {								\
		memtrack_alloc(MEMTRACK_WORK_QUEUE, 0UL, (unsigned long)(wq_addr), 0, 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
	}									\
	wq_addr;								\
})
#else
#define alloc_workqueue(name, flags, max_active, args...) ({			\
	struct workqueue_struct *wq_addr = NULL;				\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "alloc_workqueue", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "alloc_workqueue"); \
	else									\
		wq_addr = __alloc_workqueue_key((name), (flags), (max_active),	\
						NULL, NULL, ##args);		\
	if (wq_addr) {								\
		memtrack_alloc(MEMTRACK_WORK_QUEUE, 0UL, (unsigned long)(wq_addr), 0, 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
	}									\
	wq_addr;								\
})
#endif
#else
/* In kernels >= 5.1, alloc_workqueue is a function */
#define alloc_workqueue(name, flags, max_active, args...) ({			\
	struct workqueue_struct *wq_addr = NULL;				\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "alloc_workqueue", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "alloc_workqueue"); \
	else									\
		wq_addr = alloc_workqueue(name, flags, max_active, ##args);	\
	if (wq_addr) {								\
		memtrack_alloc(MEMTRACK_WORK_QUEUE, 0UL, (unsigned long)(wq_addr), 0, 0UL, 0, __FILE__, __LINE__, GFP_ATOMIC); \
	}									\
	wq_addr;								\
})
#endif

#define WQ_RESCUER 1 << 7 /* internal: workqueue has rescuer */

#define create_workqueue(name)							\
	alloc_workqueue((name), WQ_RESCUER, 1);

#define create_freezeable_workqueue(name)					\
	alloc_workqueue((name), WQ_FREEZEABLE | WQ_UNBOUND | WQ_RESCUER, 1);

#define create_singlethread_workqueue(name)					\
	alloc_workqueue((name), WQ_UNBOUND | WQ_RESCUER, 1);

#define alloc_ordered_workqueue(name, flags, args...)				\
	alloc_workqueue((name), WQ_UNBOUND | __WQ_ORDERED | (flags), 1, ##args)

#define destroy_workqueue(wq_addr) ({						\
	void *__memtrack_addr = (void *)wq_addr;				\
										\
	if (__memtrack_addr) {							\
		memtrack_free(MEMTRACK_WORK_QUEUE, 0UL, (unsigned long)(__memtrack_addr), 0UL, 0, __FILE__, __LINE__); \
	}									\
	destroy_workqueue(wq_addr);						\
})

/* ONLY error injection to functions that we don't monitor */
#define alloc_skb(size, prio) ({ \
	struct sk_buff *__memtrack_skb = NULL;					\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "alloc_skb", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "alloc_skb"); \
	else									\
		 __memtrack_skb = alloc_skb(size, prio);			\
	__memtrack_skb;								\
})

#define dev_alloc_skb(size) ({							\
	struct sk_buff *__memtrack_skb = NULL;					\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "dev_alloc_skb", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "dev_alloc_skb"); \
	else									\
		__memtrack_skb = dev_alloc_skb(size);				\
	__memtrack_skb;								\
})

#define alloc_skb_fclone(size, prio) ({						\
	struct sk_buff *__memtrack_skb = NULL;					\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "alloc_skb_fclone", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "alloc_skb_fclone"); \
	else									\
		__memtrack_skb = alloc_skb_fclone(size, prio);			\
	__memtrack_skb;								\
})

#define copy_from_user(to, from, n) ({						\
	int ret = n;								\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "copy_from_user", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "copy_from_user"); \
	else									\
		ret = copy_from_user(to, from, n);				\
	ret;									\
})

#define copy_to_user(to, from, n) ({						\
	int ret = n;								\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "copy_to_user", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "copy_to_user"); \
	else									\
		ret = copy_to_user(to, from, n);				\
	ret;									\
})

#define sysfs_create_file(kobj, attr) ({						\
	int ret = -ENOSYS;							\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "sysfs_create_file", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "sysfs_create_file"); \
	else									\
		ret = sysfs_create_file(kobj, attr);				\
	ret;									\
})

#define sysfs_create_link(kobj, target, name) ({				\
	int ret = -ENOSYS;							\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "sysfs_create_link", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "sysfs_create_link"); \
	else									\
		ret = sysfs_create_link(kobj, target, name);			\
	ret;									\
})

#define sysfs_create_group(kobj, grp) ({					\
	int ret = -ENOSYS;							\
										\
	if (memtrack_inject_error(THIS_MODULE, __FILE__, "sysfs_create_group", __func__, __LINE__)) \
		MEMTRACK_ERROR_INJECTION_MESSAGE(THIS_MODULE, __FILE__, __LINE__, __func__, "sysfs_create_group"); \
	else									\
		ret = sysfs_create_group(kobj, grp);				\
	ret;									\
})

#endif /* __mtrack_h_ */

