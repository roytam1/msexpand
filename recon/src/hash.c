/* hash.c -- CRC32 and hex decoding for CIX hash verification. */
#include "expand.h"
#include "hash.h"

static unsigned long g_crcTable[256];
static int g_crcReady = 0;

static void InitCrc32(void)
{
    unsigned long c;
    int n, k;
    for (n = 0; n < 256; ++n)
    {
        c = (unsigned long)n;
        for (k = 0; k < 8; ++k)
            c = (c & 1) ? (0xEDB88320UL ^ (c >> 1)) : (c >> 1);
        g_crcTable[n] = c;
    }
    g_crcReady = 1;
}

unsigned long Crc32(const unsigned char *data, unsigned long len)
{
    unsigned long crc = 0xFFFFFFFFUL;
    unsigned long i;
    if (!g_crcReady)
        InitCrc32();
    for (i = 0; i < len; ++i)
        crc = g_crcTable[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFUL;
}

static int HexVal(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode a hex blob (spaces, '0x' and ':' separators tolerated). */
int HexToBytes(const char *hex, unsigned char *out, int maxOut)
{
    int n = 0;
    int high = -1;
    int v;

    if (!hex)
        return 0;
    while (*hex)
    {
        if (*hex == ' ' || *hex == '\t' || *hex == ':' || *hex == '-' ||
            *hex == '\r' || *hex == '\n')
        {
            ++hex;
            continue;
        }
        if (*hex == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        {
            hex += 2;
            continue;
        }
        v = HexVal(*hex);
        if (v < 0)
            return 0;
        if (high < 0)
            high = v;
        else
        {
            if (n >= maxOut)
                return 0;
            out[n++] = (unsigned char)((high << 4) | v);
            high = -1;
        }
        ++hex;
    }
    return n;
}
