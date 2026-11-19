#ifndef LZMS_H
#define LZMS_H

/* Raw LZMS block decompression.  Returns 0 on success, -1 on error. */
int LzmsRawDecompress(const unsigned char *in, unsigned long inLen,
                      unsigned char *out, unsigned long outLen);
/* Decompress a raw block or dpx's chunk-framed LZMS stream. */
int LzmsDecompressData(const unsigned char *in, unsigned long inLen,
                       unsigned char *out, unsigned long outLen);

#endif
