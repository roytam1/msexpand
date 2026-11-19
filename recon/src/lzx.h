#ifndef LZX_H
#define LZX_H

/* CAB LZX decompression (MSB-first bitstream, with CAB E8 header bit).
 *
 * windowBits : LZX window order, 15 .. 25.
 * Returns 0 on success, -1 on error.
 */
int LzxRawDecompress(const unsigned char *in, unsigned long inLen,
                     unsigned char *out, unsigned long outLen, int windowBits);
int LzxDecompressSeeded(const unsigned char *in, unsigned long inLen,
                        unsigned char *out, unsigned long outLen, int windowBits,
                        const unsigned char *seed, unsigned long seedLen);

#endif
