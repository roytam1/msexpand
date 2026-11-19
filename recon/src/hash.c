/* hash.c -- CRC32, MD5 and hex decoding for package hash verification. */
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

/* ------------------------------------------------------------------ */
/* MD5, used by SFX [Verify] entries.  Self-contained C89 so the EXE
 * needs no CryptoAPI or external crypto library.                        */
/* ------------------------------------------------------------------ */

static const unsigned long g_md5K[64] = {
    0xd76aa478UL,0xe8c7b756UL,0x242070dbUL,0xc1bdceeeUL,
    0xf57c0fafUL,0x4787c62aUL,0xa8304613UL,0xfd469501UL,
    0x698098d8UL,0x8b44f7afUL,0xffff5bb1UL,0x895cd7beUL,
    0x6b901122UL,0xfd987193UL,0xa679438eUL,0x49b40821UL,
    0xf61e2562UL,0xc040b340UL,0x265e5a51UL,0xe9b6c7aaUL,
    0xd62f105dUL,0x02441453UL,0xd8a1e681UL,0xe7d3fbc8UL,
    0x21e1cde6UL,0xc33707d6UL,0xf4d50d87UL,0x455a14edUL,
    0xa9e3e905UL,0xfcefa3f8UL,0x676f02d9UL,0x8d2a4c8aUL,
    0xfffa3942UL,0x8771f681UL,0x6d9d6122UL,0xfde5380cUL,
    0xa4beea44UL,0x4bdecfa9UL,0xf6bb4b60UL,0xbebfbc70UL,
    0x289b7ec6UL,0xeaa127faUL,0xd4ef3085UL,0x04881d05UL,
    0xd9d4d039UL,0xe6db99e5UL,0x1fa27cf8UL,0xc4ac5665UL,
    0xf4292244UL,0x432aff97UL,0xab9423a7UL,0xfc93a039UL,
    0x655b59c3UL,0x8f0ccc92UL,0xffeff47dUL,0x85845dd1UL,
    0x6fa87e4fUL,0xfe2ce6e0UL,0xa3014314UL,0x4e0811a1UL,
    0xf7537e82UL,0xbd3af235UL,0x2ad7d2bbUL,0xeb86d391UL
};

static const int g_md5S[64] = {
     7,12,17,22,  7,12,17,22,  7,12,17,22,  7,12,17,22,
     5, 9,14,20,  5, 9,14,20,  5, 9,14,20,  5, 9,14,20,
     4,11,16,23,  4,11,16,23,  4,11,16,23,  4,11,16,23,
     6,10,15,21,  6,10,15,21,  6,10,15,21,  6,10,15,21
};

#define MD5_ROL(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

static void Md5Transform(unsigned long st[4], const unsigned char block[64])
{
    unsigned long m[16], a, b, c, d, f, g, t;
    int i;

    for (i = 0; i < 16; ++i)
        m[i] = (unsigned long)block[i * 4] |
               ((unsigned long)block[i * 4 + 1] << 8) |
               ((unsigned long)block[i * 4 + 2] << 16) |
               ((unsigned long)block[i * 4 + 3] << 24);

    a = st[0]; b = st[1]; c = st[2]; d = st[3];
    for (i = 0; i < 64; ++i)
    {
        if (i < 16)
        {
            f = (b & c) | (~b & d);
            g = (unsigned long)i;
        }
        else if (i < 32)
        {
            f = (d & b) | (~d & c);
            g = (unsigned long)((5 * i + 1) & 15);
        }
        else if (i < 48)
        {
            f = b ^ c ^ d;
            g = (unsigned long)((3 * i + 5) & 15);
        }
        else
        {
            f = c ^ (b | ~d);
            g = (unsigned long)((7 * i) & 15);
        }
        t = d;
        d = c;
        c = b;
        b = b + MD5_ROL(a + f + g_md5K[i] + m[g], g_md5S[i]);
        a = t;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
}

void Md5(const unsigned char *data, unsigned long len, unsigned char out[16])
{
    unsigned long st[4] = { 0x67452301UL, 0xefcdab89UL,
                            0x98badcfeUL, 0x10325476UL };
    unsigned long bitLo = (len << 3) & 0xFFFFFFFFUL;
    unsigned long bitHi = len >> 29;
    unsigned long i, nblocks, rem, tailLen;
    unsigned char tail[128];

    nblocks = len >> 6;
    for (i = 0; i < nblocks; ++i)
        Md5Transform(st, data + (i << 6));

    rem = len & 63;
    tailLen = (rem < 56) ? (64 - rem) : (128 - rem);
    memset(tail, 0, sizeof(tail));
    if (rem)
        memcpy(tail, data + (len - rem), (size_t)rem);
    tail[rem] = 0x80;
    for (i = 0; i < 4; ++i)
    {
        tail[tailLen - 8 + i] = (unsigned char)(bitLo >> (8 * i));
        tail[tailLen - 4 + i] = (unsigned char)(bitHi >> (8 * i));
    }
    for (i = 0; i < tailLen; i += 64)
        Md5Transform(st, tail + i);

    for (i = 0; i < 4; ++i)
    {
        out[i * 4]     = (unsigned char)(st[i] & 0xFF);
        out[i * 4 + 1] = (unsigned char)((st[i] >> 8) & 0xFF);
        out[i * 4 + 2] = (unsigned char)((st[i] >> 16) & 0xFF);
        out[i * 4 + 3] = (unsigned char)((st[i] >> 24) & 0xFF);
    }
}
