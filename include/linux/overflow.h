#ifndef _COMPAT_LINUX_OVERFLOW_H
#define _COMPAT_LINUX_OVERFLOW_H

#include "../../compat/config.h"

#include_next <linux/overflow.h>

#ifndef HAVE_SIZE_MUL_SUB_ADD
/**
 * size_add() - Calculate size_t addition with saturation at SIZE_MAX
 * @addend1: first addend
 * @addend2: second addend
 *
 * Returns: calculate @addend1 + @addend2, both promoted to size_t,
 * with any overflow causing the return value to be SIZE_MAX. The
 * lvalue must be size_t to avoid implicit type conversion.
 */
static inline size_t __must_check size_add(size_t addend1, size_t addend2)
{
	size_t bytes;

	if (check_add_overflow(addend1, addend2, &bytes))
		return SIZE_MAX;

	return bytes;
}
/**
 * size_mul() - Calculate size_t multiplication with saturation at SIZE_MAX
 * @factor1: first factor
 * @factor2: second factor
 *
 * Returns: calculate @factor1 * @factor2, both promoted to size_t,
 * with any overflow causing the return value to be SIZE_MAX. The
 * lvalue must be size_t to avoid implicit type conversion.
 */
static inline size_t __must_check size_mul(size_t factor1, size_t factor2)
{
	size_t bytes;

	if (check_mul_overflow(factor1, factor2, &bytes))
		return SIZE_MAX;

	return bytes;
}
/**
 * size_sub() - Calculate size_t subtraction with saturation at SIZE_MAX
 * @minuend: value to subtract from
 * @subtrahend: value to subtract from @minuend
 *
 * Returns: calculate @minuend - @subtrahend, both promoted to size_t,
 * with any overflow causing the return value to be SIZE_MAX. For
 * composition with the size_add() and size_mul() helpers, neither
 * argument may be SIZE_MAX (or the result with be forced to SIZE_MAX).
 * The lvalue must be size_t to avoid implicit type conversion.
 */
static inline size_t __must_check size_sub(size_t minuend, size_t subtrahend)
{
	size_t bytes;

	if (minuend == SIZE_MAX || subtrahend == SIZE_MAX ||
			check_sub_overflow(minuend, subtrahend, &bytes))
		return SIZE_MAX;

	return bytes;
}
#endif /* HAVE_SIZE_MUL_SUB_ADD */

#ifndef struct_size
/**
 * array_size() - Calculate size of 2-dimensional array.
 *
 * @a: dimension one
 * @b: dimension two
 *
 * Calculates size of 2-dimensional array: @a * @b.
 *
 * Returns: number of bytes needed to represent the array or SIZE_MAX on
 * overflow.
 */
static inline __must_check size_t array_size(size_t a, size_t b)
{
	size_t bytes;

	if (check_mul_overflow(a, b, &bytes))
		return SIZE_MAX;

	return bytes;
}

/**
 * array3_size() - Calculate size of 3-dimensional array.
 *
 * @a: dimension one
 * @b: dimension two
 * @c: dimension three
 *
 * Calculates size of 3-dimensional array: @a * @b * @c.
 *
 * Returns: number of bytes needed to represent the array or SIZE_MAX on
 * overflow.
 */
static inline __must_check size_t array3_size(size_t a, size_t b, size_t c)
{
	size_t bytes;

	if (check_mul_overflow(a, b, &bytes))
		return SIZE_MAX;
	if (check_mul_overflow(bytes, c, &bytes))
		return SIZE_MAX;

	return bytes;
}

static inline __must_check size_t __ab_c_size(size_t n, size_t size, size_t c)
{
	size_t bytes;

	if (check_mul_overflow(n, size, &bytes))
		return SIZE_MAX;
	if (check_add_overflow(bytes, c, &bytes))
		return SIZE_MAX;

	return bytes;
}

/**
 * struct_size() - Calculate size of structure with trailing array.
 * @p: Pointer to the structure.
 * @member: Name of the array member.
 * @n: Number of elements in the array.
 *
 * Calculates size of memory needed for structure @p followed by an
 * array of @n @member elements.
 *
 * Return: number of bytes needed or SIZE_MAX on overflow.
 */
#define struct_size(p, member, n)					\
	__ab_c_size(n,							\
		    sizeof(*(p)->member) + __must_be_array((p)->member),\
		    sizeof(*(p)))
#endif /* struct_size */

#ifndef check_shl_overflow
#define check_shl_overflow(a, s, d) ({					\
	typeof(a) _a = a;						\
	typeof(s) _s = s;						\
	typeof(d) _d = d;						\
	u64 _a_full = _a;						\
	unsigned int _to_shift =					\
		_s >= 0 && _s < 8 * sizeof(*d) ? _s : 0;		\
	*_d = (_a_full << _to_shift);					\
	(_to_shift != _s || *_d < 0 || _a < 0 ||			\
		(*_d >> _to_shift) != _a);				\
})
#endif /* check_shl_overflow */

#endif /* _COMPAT_LINUX_OVERFLOW_H */
