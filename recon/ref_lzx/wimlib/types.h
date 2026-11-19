/*
 * types.h -- minimal MSVC6 shim for wimlib's types.h
 *
 * VC98 has no <stdint.h> / <stdbool.h>; use its native 64-bit type and a
 * plain int for bool.
 */
#ifndef _WIMLIB_TYPES_H
#define _WIMLIB_TYPES_H

#include <stddef.h>
#include "wimlib/compiler.h"

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned __int64   u64;

typedef signed char        s8;
typedef signed short       s16;
typedef signed int         s32;
typedef signed __int64     s64;

typedef u16 le16;
typedef u32 le32;
typedef u64 le64;
typedef u16 be16;
typedef u32 be32;
typedef u64 be64;

typedef le16 utf16lechar;

typedef int bool;
#ifndef true
#define true  1
#endif
#ifndef false
#define false 0
#endif

typedef struct WIMStruct WIMStruct;

/* 32-bit build: machine word == size_t == 4 bytes. */
typedef size_t machine_word_t;
#define WORDBYTES  sizeof(machine_word_t)
#define WORDBITS   (8 * WORDBYTES)

#endif /* _WIMLIB_TYPES_H */
