/* hash.c -- CRC32, MD5, SHA256 and hex decoding for package hash
 * verification (C89 / VC98, no CryptoAPI dependency). */
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
    /* Length goes in the last 8 bytes of the final 64-byte block. */
    tailLen = (rem < 56) ? 64 : 128;
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

/* ------------------------------------------------------------------ */
/* SHA-256, used by the SHA256 hashes in _manifest_.cix.xml.            */
/* ------------------------------------------------------------------ */

static const unsigned long g_shaK[64] = {
    0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,
    0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
    0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,
    0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
    0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,
    0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
    0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,
    0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
    0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,
    0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
    0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,
    0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
    0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,
    0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
    0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
    0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

#define SH_ROR(x,n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define SH_BS0(x)    (SH_ROR((x),2) ^ SH_ROR((x),13) ^ SH_ROR((x),22))
#define SH_BS1(x)    (SH_ROR((x),6) ^ SH_ROR((x),11) ^ SH_ROR((x),25))
#define SH_SS0(x)    (SH_ROR((x),7) ^ SH_ROR((x),18) ^ ((x) >> 3))
#define SH_SS1(x)    (SH_ROR((x),17) ^ SH_ROR((x),19) ^ ((x) >> 10))

static void Sha256Block(unsigned long h[8], const unsigned char block[64])
{
    unsigned long w[64];
    unsigned long a, b, c, d, e, f, g, hh, t1, t2;
    unsigned long i;

    for (i = 0; i < 16; ++i)
        w[i] = ((unsigned long)block[i * 4] << 24) |
               ((unsigned long)block[i * 4 + 1] << 16) |
               ((unsigned long)block[i * 4 + 2] << 8) |
               (unsigned long)block[i * 4 + 3];
    for (i = 16; i < 64; ++i)
        w[i] = SH_SS1(w[i - 2]) + w[i - 7] + SH_SS0(w[i - 15]) + w[i - 16];

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];
    for (i = 0; i < 64; ++i)
    {
        t1 = hh + SH_BS1(e) + ((e & f) ^ (~e & g)) + g_shaK[i] + w[i];
        t2 = SH_BS0(a) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void Sha256(const unsigned char *data, unsigned long len, unsigned char out[32])
{
    unsigned long h[8] = {
        0x6a09e667UL,0xbb67ae85UL,0x3c6ef372UL,0xa54ff53aUL,
        0x510e527fUL,0x9b05688cUL,0x1f83d9abUL,0x5be0cd19UL
    };
    unsigned long bitLo = len << 3;
    unsigned long bitHi = len >> 29;
    unsigned long nblocks = len >> 6;
    unsigned long i, rem, tailLen;
    unsigned char tail[128];

    for (i = 0; i < nblocks; ++i)
        Sha256Block(h, data + (i << 6));

    rem = len & 63;
    /* The 64-bit bit length always occupies the last 8 bytes of the final
     * block, not the bytes immediately after the payload. */
    tailLen = (rem < 56) ? 64 : 128;
    memset(tail, 0, sizeof(tail));
    if (rem)
        memcpy(tail, data + (len - rem), (size_t)rem);
    tail[rem] = 0x80;
    for (i = 0; i < 4; ++i)
    {
        tail[tailLen - 8 + i] = (unsigned char)(bitHi >> (8 * (3 - i)));
        tail[tailLen - 4 + i] = (unsigned char)(bitLo >> (8 * (3 - i)));
    }
    for (i = 0; i < tailLen; i += 64)
        Sha256Block(h, tail + i);

    for (i = 0; i < 8; ++i)
    {
        out[i * 4]     = (unsigned char)(h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)h[i];
    }
}
