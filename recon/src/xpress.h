#ifndef XPRESS_H
#define XPRESS_H

/* XPRESS (MS-XCA) raw decompression.  Returns 0 on success, -1 on error. */
int XpressDecompress(const unsigned char *in, unsigned long inLen,
                     unsigned char *out, unsigned long outCap,
                     unsigned long *outLen);
int XpressHuffmanDecompress(const unsigned char *in, unsigned long inLen,
                            unsigned char *out, unsigned long outLen);

#endif
