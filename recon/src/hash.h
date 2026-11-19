#ifndef HASH_H
#define HASH_H

unsigned long Crc32(const unsigned char *data, unsigned long len);
int HexToBytes(const char *hex, unsigned char *out, int maxOut);
void Md5(const unsigned char *data, unsigned long len, unsigned char out[16]);

#endif
