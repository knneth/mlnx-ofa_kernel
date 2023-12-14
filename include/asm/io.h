#ifndef _COMPAT_ASM_IO_H
#define _COMPAT_ASM_IO_H

#include "../../compat/config.h"

#include_next <asm/io.h>

#ifdef CONFIG_ARM64
#ifndef memcpy_toio_64
static inline void __memcpy_toio_64(volatile void __iomem *to, const void *from)
{
	const u64 *from64 = from;

	/*
	 * 	 * Newer ARM core have sensitive write combining buffers, it is
	 * 	 	 * important that the stores be contiguous blocks of store instructions.
	 * 	 	 	 * Normal memcpy does not work reliably.
	 * 	 	 	 	 */
	asm volatile("stp %x0, %x1, [%8, #16 * 0]\n"
			"stp %x2, %x3, [%8, #16 * 1]\n"
			"stp %x4, %x5, [%8, #16 * 2]\n"
			"stp %x6, %x7, [%8, #16 * 3]\n"
			:
			: "rZ"(from64[0]), "rZ"(from64[1]), "rZ"(from64[2]),
			"rZ"(from64[3]), "rZ"(from64[4]), "rZ"(from64[5]),
			"rZ"(from64[6]), "rZ"(from64[7]), "r"(to));
}
#define memcpy_toio_64(to, from) __memcpy_toio_64(to, from)
#endif /* memcpy_toio_64 */
#else /* CONFIG_ARM64 */
#ifndef memcpy_toio_64
#define memcpy_toio_64 memcpy_toio_64
/*
 * memcpy_toio_64	Copy 64 bytes of data into I/O memory
 * @dst:		The (I/O memory) destination for the copy
 * @src:		The (RAM) source for the data
 * @count:		The number of bytes to copy
 *
 * dst and src must be aligned to 8 bytes. This operation copies exactly 64
 * bytes. It is intended to be used for write combining IO memory. The
 * architecture should provide an implementation that has a high chance of
 * generating a single combined transaction.
 */
static inline void memcpy_toio_64(volatile void __iomem *addr,
		const void *buffer)
{
	unsigned int i = 0;

#if BITS_PER_LONG == 64
	for (; i != 8; i++)
		__raw_writeq(((const u64 *)buffer)[i],
				((u64 __iomem *)addr) + i);
#else
	for (; i != 16; i++)
		__raw_writel(((const u32 *)buffer)[i],
				((u32 __iomem *)addr) + i);
#endif
}
#endif
#endif /* CONFIG_ARM64 */

#endif /* _COMPAT_ASM_IO_H */
