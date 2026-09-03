#ifndef _COMPAT_LINUX_OVERFLOW_H
#define _COMPAT_LINUX_OVERFLOW_H

#include "../../compat/config.h"

#include_next <linux/overflow.h>

#ifndef HAVE_OVERFLOWS_TYPE

#ifndef HAVE__OVERFLOWS_TYPE_CONSTEXPR
#define __overflows_type_constexpr(x, T) (			\
	is_unsigned_type(typeof(x)) ?				\
		(x) > type_max(T) :				\
	is_unsigned_type(typeof(T)) ?				\
		(x) < 0 || (x) > type_max(T) :			\
	(x) < type_min(T) || (x) > type_max(T))
#endif

#define __overflows_type(x, T)		({	\
	typeof(T) v = 0;			\
	check_add_overflow((x), v, &v);		\
})

/**
 * overflows_type - helper for checking the overflows between value, variables,
 *		    or data type
 *
 * @n: source constant value or variable to be checked
 * @T: destination variable or data type proposed to store @x
 *
 * Compares the @x expression for whether or not it can safely fit in
 * the storage of the type in @T. @x and @T can have different types.
 * If @x is a constant expression, this will also resolve to a constant
 * expression.
 *
 * Returns: true if overflow can occur, false otherwise.
 */
#define overflows_type(n, T)					\
	__builtin_choose_expr(__is_constexpr(n),		\
			      __overflows_type_constexpr(n, T),	\
			      __overflows_type(n, T))

#endif	/* HAVE_OVERFLOWS_TYPE */

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
#endif /* _COMPAT_LINUX_OVERFLOW_H */
