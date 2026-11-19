/*
 * unaligned.h -- minimal MSVC6 shim for wimlib's unaligned.h
 *
 * x86 allows unaligned loads; bytewise reconstruction is used for the
 * explicitly little-endian accessors so endianness handling is unambiguous.
 */
#ifndef _WIMLIB_UNALIGNED_H
#define _WIMLIB_UNALIGNED_H

#include <string.h>
#include "wimlib/compiler.h"
#include "wimlib/types.h"

#define DEFINE_UNALIGNED_TYPE(type)                                  \
static forceinline type load_##type##_unaligned(const void *p)        \
{                                                                    \
        type v;                                                      \
        memcpy(&v, p, sizeof(v));                                    \
        return v;                                                    \
}                                                                    \
static forceinline void store_##type##_unaligned(type v, void *p)     \
{                                                                    \
        memcpy(p, &v, sizeof(v));                                    \
}

DEFINE_UNALIGNED_TYPE(u16)
DEFINE_UNALIGNED_TYPE(u32)
DEFINE_UNALIGNED_TYPE(u64)
DEFINE_UNALIGNED_TYPE(le16)
DEFINE_UNALIGNED_TYPE(le32)
DEFINE_UNALIGNED_TYPE(le64)
DEFINE_UNALIGNED_TYPE(be16)
DEFINE_UNALIGNED_TYPE(be32)
DEFINE_UNALIGNED_TYPE(be64)
DEFINE_UNALIGNED_TYPE(size_t)
DEFINE_UNALIGNED_TYPE(machine_word_t)

#define load_word_unaligned   load_machine_word_t_unaligned
#define store_word_unaligned  store_machine_word_t_unaligned

static forceinline u16
get_unaligned_le16(const u8 *p)
{
        return (u16)(((u16)p[1] << 8) | p[0]);
}

static forceinline u32
get_unaligned_le32(const u8 *p)
{
        return ((u32)p[3] << 24) | ((u32)p[2] << 16) |
               ((u32)p[1] << 8)  | (u32)p[0];
}

static forceinline u32
get_unaligned_be32(const u8 *p)
{
        return ((u32)p[0] << 24) | ((u32)p[1] << 16) |
               ((u32)p[2] << 8)  | (u32)p[3];
}

static forceinline void
put_unaligned_le16(u16 v, u8 *p)
{
        p[0] = (u8)(v >> 0);
        p[1] = (u8)(v >> 8);
}

static forceinline void
put_unaligned_le32(u32 v, u8 *p)
{
        p[0] = (u8)(v >> 0);
        p[1] = (u8)(v >> 8);
        p[2] = (u8)(v >> 16);
        p[3] = (u8)(v >> 24);
}

static forceinline void
put_unaligned_be32(u32 v, u8 *p)
{
        p[0] = (u8)(v >> 24);
        p[1] = (u8)(v >> 16);
        p[2] = (u8)(v >> 8);
        p[3] = (u8)(v >> 0);
}

#endif /* _WIMLIB_UNALIGNED_H */
