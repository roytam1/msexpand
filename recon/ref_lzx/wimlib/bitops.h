#ifndef _WIMLIB_BITOPS_H
#define _WIMLIB_BITOPS_H
#include "wimlib/compiler.h"
#include "wimlib/types.h"

/* Minimal C89 implementation needed by lzx_common.c. */
static forceinline unsigned
ilog2_ceil(size_t n)
{
	unsigned r = 0;
	size_t v = n;
	if (n <= 1)
		return 0;
	v--;
	while (v) {
		++r;
		v >>= 1;
	}
	return r;
}

#endif
