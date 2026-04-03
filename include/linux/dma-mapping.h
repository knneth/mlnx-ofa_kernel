#ifndef _COMPAT_LINUX_DMA_MAPPING_H
#define _COMPAT_LINUX_DMA_MAPPING_H

#include "../../compat/config.h"

#include_next <linux/dma-mapping.h>

#ifndef HAVE_DMA_IOVA_STATE
struct dma_iova_state {
	dma_addr_t addr;
	u64 __size;
};

static inline bool dma_use_iova(struct dma_iova_state *state)
{
	return false;
}
static inline bool dma_iova_try_alloc(struct device *dev,
		struct dma_iova_state *state, phys_addr_t phys, size_t size)
{
	return false;
}
static inline void dma_iova_free(struct device *dev,
		struct dma_iova_state *state)
{
}
static inline void dma_iova_destroy(struct device *dev,
		struct dma_iova_state *state, size_t mapped_len,
		enum dma_data_direction dir, unsigned long attrs)
{
}
static inline int dma_iova_sync(struct device *dev,
		struct dma_iova_state *state, size_t offset, size_t size)
{
	return -EOPNOTSUPP;
}
static inline int dma_iova_link(struct device *dev,
		struct dma_iova_state *state, phys_addr_t phys, size_t offset,
		size_t size, enum dma_data_direction dir, unsigned long attrs)
{
	return -EOPNOTSUPP;
}
static inline void dma_iova_unlink(struct device *dev,
		struct dma_iova_state *state, size_t offset, size_t size,
		enum dma_data_direction dir, unsigned long attrs)
{
}

#endif

#endif /* _COMPAT_LINUX_DMA_MAPPING_H */
