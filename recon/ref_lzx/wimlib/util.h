/*
 * util.h -- minimal shim for wimlib's util.h
 *
 * Only the aligned-allocation macros are needed; implemented in main.c.
 */
#ifndef _WIMLIB_UTIL_H
#define _WIMLIB_UTIL_H

#include <stddef.h>

void *wimlib_aligned_malloc(size_t size, size_t alignment);
void wimlib_aligned_free(void *ptr);

#define ALIGNED_MALLOC  wimlib_aligned_malloc
#define ALIGNED_FREE    wimlib_aligned_free

#endif /* _WIMLIB_UTIL_H */
