/*
 * LZX decoder for Microsoft Cabinet files.
 *
 * Plain C89 port of CabLzx.cpp, written from the published format
 * description.  No C++ runtime is needed.
 */
#ifndef LZXDEC_H
#define LZXDEC_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*LzxFillFn)(void *ctx, unsigned char *buf, unsigned long want);

typedef struct LzxDecoder LzxDecoder;

LzxDecoder *LzxCreate(int windowBits, unsigned long totalLength,
                      LzxFillFn fill, void *fillCtx);
void LzxDestroy(LzxDecoder *d);
int LzxDecode(LzxDecoder *d, unsigned char *out, unsigned long len);
/* Decode one CFDATA payload (cbData compressed bytes -> cbUncomp bytes),
   resetting the bit buffer as FDI's LZX_Decode does. */
int LzxDecodeBlock(LzxDecoder *d, unsigned char *out, unsigned long uncomp,
                   const unsigned char *in, unsigned long comp);
int LzxRawDecompress(const unsigned char *in, unsigned long inLen,
                     unsigned char *out, unsigned long outLen, int windowBits);

#ifdef __cplusplus
}
#endif

#endif
