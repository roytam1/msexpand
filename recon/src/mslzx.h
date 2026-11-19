#ifndef MSLZX_H
#define MSLZX_H

/* mspatcha's LZX variant decompression (C89).
 *
 * in         : raw patch LZX bitstream (per-group E8 header included).
 * out        : output buffer; outLen bytes will be produced.
 * windowBits : LZX window order (15..25).
 * seed/seedLen: source bytes placed at the end of the LZX window.
 */
int MsLzxDecompressSeeded(const unsigned char *in, unsigned long inLen,
                          unsigned char *out, unsigned long outLen,
                          int windowBits, const unsigned char *seed,
                          unsigned long seedLen);
int MsLzxRawDecompress(const unsigned char *in, unsigned long inLen,
                       unsigned char *out, unsigned long outLen, int windowBits);

/* Multi-chunk variant: chunks are the raw LZXD chunk payloads (the 2-byte
 * size prefixes are excluded).  Decoder state carries across chunk
 * boundaries, as mspatcha does for large patches. */
int MsLzxDecompressSeededMulti(const unsigned char *const *chunks,
                               const unsigned long *sizes, unsigned long nchunks,
                               unsigned char *out, unsigned long outLen,
                               int windowBits, const unsigned char *seed,
                               unsigned long seedLen);

#endif
