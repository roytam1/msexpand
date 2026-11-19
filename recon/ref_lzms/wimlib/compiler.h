/*
 * compiler.h -- minimal MSVC6 (VC98) shim for wimlib's compiler.h
 *
 * Provides just the macros the copied wimlib C sources need.  No GNU
 * extensions: no statement expressions, no __attribute__, no builtins.
 */
#ifndef _WIMLIB_COMPILER_H
#define _WIMLIB_COMPILER_H

/* MSVC6 C has no 'restrict' keyword. */
#ifndef restrict
#define restrict
#endif

/* 'inline' is C++-only in MSVC6; __inline is the supported extension. */
#define forceinline  __inline
#define noinline
#define noinline_for_stack

/* No branch hints. */
#define likely(x)    (x)
#define unlikely(x)  (x)
#define prefetchr(x)
#define prefetchw(x)

#define _format_attribute(type, format_str, format_start)

/* This reference build targets little-endian x86 with cheap unaligned loads. */
#define CPU_IS_BIG_ENDIAN()     0
#define CPU_IS_LITTLE_ENDIAN()  1
#define UNALIGNED_ACCESS_IS_FAST 1

#define _bitwise_attr
#define _force_attr

/* Classic C89 compile-time assertion (used as a statement). */
#define STATIC_ASSERT(expr)  ((void)sizeof(char[1 - 2 * !(expr)]))

/* Used inside constant expressions to size decode tables; the checks are
 * redundant for this fixed build, so just yield 0. */
#define STATIC_ASSERT_ZERO(expr) 0

#define CONCAT_IMPL(s1, s2)  s1##s2
#define CONCAT(s1, s2)       CONCAT_IMPL(s1, s2)

/* MSVC6 has no GNU statement expressions.  These arguments are side-effect
 * free at all use sites in the copied sources. */
#undef min
#undef MIN
#undef max
#undef MAX
#define min(a, b)  ((a) < (b) ? (a) : (b))
#define MIN(a, b)  min((a), (b))
#define max(a, b)  ((a) > (b) ? (a) : (b))
#define MAX(a, b)  max((a), (b))
#define max3(a, b, c)  max(max((a), (b)), (c))

#ifndef swap
#define swap(a, b)  do { typeof(a) _t = (a); (a) = (b); (b) = _t; } while (0)
#endif
#define SWAP(a, b)  swap((a), (b))

#endif /* _WIMLIB_COMPILER_H */
