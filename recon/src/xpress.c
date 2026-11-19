/*
 * xpress.c -- C89 port of the XPRESS (MS-XCA) decompressors from
 * go-ntfs/parser/xpress.go (Apache-2.0, based on MS-XCA spec).
 *
 * Two variants:
 *   - plain LZ77  (COMPRESSION_FORMAT_XPRESS, algId 3), self-terminating
 *   - LZ77+Huffman (COMPRESSION_FORMAT_XPRESS_HUFF, algId 4), needs the
 *     uncompressed size up front
 */
#include "expand.h"
#include "xpress.h"

static unsigned short Rd16(const unsigned char *p)
{
    return (unsigned short)((unsigned short)p[0] |
                           ((unsigned short)p[1] << 8));
}

static unsigned long Rd32(const unsigned char *p)
{
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) |
           ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

/* ------------------------------------------------------------------ */
int XpressDecompress(const unsigned char *in, unsigned long inLen,
                     unsigned char *out, unsigned long outCap,
                     unsigned long *outLen)
{
    long pendingNibble;
    unsigned long flags;
    int flagsLeft;
    unsigned long i;
    unsigned long op;
    unsigned long mb;
    unsigned long moff;
    unsigned long mlen;
    unsigned long v;
    unsigned long start;
    unsigned long j;
    unsigned long nibbleByte;

    pendingNibble = -1;
    flags = 0;
    flagsLeft = 0;
    i = 0;
    op = 0;

    for (;;)
    {
        if (flagsLeft == 0)
        {
            if (inLen - i < 4)
                return -1;
            flags = Rd32(in + i);
            i += 4;
            flagsLeft = 32;
        }
        --flagsLeft;
        if ((flags & (1UL << flagsLeft)) == 0)
        {
            /* Literal. */
            if (i >= inLen || op >= outCap)
                return -1;
            out[op++] = in[i++];
            continue;
        }

        /* A set flag with no input left is the end-of-data marker. */
        if (i >= inLen)
            break;
        if (inLen - i < 2)
            return -1;
        mb = Rd16(in + i);
        i += 2;
        moff = (mb >> 3) + 1;
        mlen = (mb & 7) + 3;

        if ((mb & 7) == 7)
        {
            unsigned long nib;
            if (pendingNibble < 0)
            {
                if (i >= inLen)
                    return -1;
                nib = (unsigned long)(in[i] & 0x0F);
                nibbleByte = i;
                pendingNibble = (long)nibbleByte;
                ++i;
            }
            else
            {
                nib = (unsigned long)(in[pendingNibble] >> 4);
                pendingNibble = -1;
            }
            if (nib == 15)
            {
                if (i >= inLen)
                    return -1;
                v = in[i++];
                if (v == 255)
                {
                    if (inLen - i < 2)
                        return -1;
                    v = Rd16(in + i);
                    i += 2;
                    if (v == 0)
                    {
                        if (inLen - i < 4)
                            return -1;
                        v = Rd32(in + i);
                        i += 4;
                    }
                    if (v < 22)
                        return -1;
                    mlen = v + 3;
                }
                else
                {
                    mlen = v + 25;
                }
            }
            else
            {
                mlen = nib + 10;
            }
        }

        if (moff > 8192 || moff > op)
            return -1;
        if (mlen > outCap - op)
            return -1;
        start = op - moff;
        for (j = 0; j < mlen; ++j)
            out[op++] = out[start + j];
    }
    if (outLen)
        *outLen = op;
    return 0;
}

/* ------------------------------------------------------------------ */
#define XPRESS_TABLE_BITS 15
#define XPRESS_TABLE_SIZE (1 << XPRESS_TABLE_BITS)
#define XPRESS_NUM_SYMBOLS 512

int XpressHuffmanDecompress(const unsigned char *in, unsigned long inLen,
                            unsigned char *out, unsigned long outLen)
{
    unsigned short *table;
    unsigned short lens[XPRESS_NUM_SYMBOLS];
    unsigned long i;
    unsigned long op;
    unsigned long entry;
    int l;
    int s;
    unsigned long k;
    unsigned long bits;
    int nbits;
    unsigned long word;
    unsigned long sym;
    unsigned long clen;
    unsigned long hb;
    unsigned long mlen;
    unsigned long moff;
    unsigned long v;
    unsigned long start;
    unsigned long j;
    int result;

    if (inLen < 256)
        return -1;
    for (l = 0; l < 256; ++l)
    {
        lens[l * 2] = (unsigned short)(in[l] & 0x0F);
        lens[l * 2 + 1] = (unsigned short)(in[l] >> 4);
    }
    i = 256;

    table = (unsigned short *)calloc(XPRESS_TABLE_SIZE,
                                     sizeof(unsigned short));
    if (!table)
        return -1;
    entry = 0;
    for (l = 1; l <= XPRESS_TABLE_BITS; ++l)
    {
        for (s = 0; s < XPRESS_NUM_SYMBOLS; ++s)
        {
            if (lens[s] != (unsigned short)l)
                continue;
            k = (unsigned long)1 << (XPRESS_TABLE_BITS - l);
            while (k > 0)
            {
                if (entry >= XPRESS_TABLE_SIZE)
                {
                    free(table);
                    return -1;
                }
                table[entry++] = (unsigned short)s;
                --k;
            }
        }
    }
    if (entry != XPRESS_TABLE_SIZE)
    {
        free(table);
        return -1;
    }

    bits = 0;
    nbits = 0;
    for (;;)
    {
        if (nbits >= 32)
            break;
        if (inLen - i < 2)
        {
            free(table);
            return -1;
        }
        word = Rd16(in + i);
        i += 2;
        bits |= word << (16 - nbits);
        nbits += 16;
    }

    op = 0;
    result = 0;
    for (;;)
    {
        while (nbits < 15)
        {
            if (inLen - i < 2)
            {
                result = -1;
                break;
            }
            word = Rd16(in + i);
            i += 2;
            bits |= word << (16 - nbits);
            nbits += 16;
        }
        if (result != 0)
            break;

        sym = table[(bits >> 17) & 0x7FFFUL];
        clen = lens[sym];
        bits <<= clen;
        nbits -= (int)clen;

        if (sym < 256)
        {
            if (op >= outLen)
            {
                result = -1;
                break;
            }
            out[op++] = (unsigned char)sym;
            continue;
        }

        if (sym == 256)
        {
            if (op == outLen)
                break;
            if (op == 0 || outLen - op < 3)
            {
                result = -1;
                break;
            }
            start = op - 1;
            for (j = 0; j < 3; ++j)
                out[op++] = out[start + j];
            continue;
        }

        hb = (sym - 256) / 16;
        mlen = (sym - 256) % 16;
        if (mlen == 15)
        {
            if (i >= inLen)
            {
                result = -1;
                break;
            }
            v = in[i++];
            if (v == 255)
            {
                if (inLen - i < 2)
                {
                    result = -1;
                    break;
                }
                v = Rd16(in + i);
                i += 2;
                if (v == 0)
                {
                    if (inLen - i < 4)
                    {
                        result = -1;
                        break;
                    }
                    v = Rd32(in + i);
                    i += 4;
                }
                mlen = v + 3;
            }
            else
            {
                mlen = v + 18;
            }
        }
        else
        {
            mlen += 3;
        }

        while (nbits < (int)hb)
        {
            if (inLen - i < 2)
            {
                result = -1;
                break;
            }
            word = Rd16(in + i);
            i += 2;
            bits |= word << (16 - nbits);
            nbits += 16;
        }
        if (result != 0)
            break;

        moff = 0;
        if (hb > 0)
        {
            moff = (bits >> (32 - hb)) & ((1UL << hb) - 1UL);
            bits <<= hb;
            nbits -= (int)hb;
        }
        moff += 1UL << hb;

        if (moff > op || mlen > outLen - op)
        {
            result = -1;
            break;
        }
        start = op - moff;
        for (j = 0; j < mlen; ++j)
            out[op++] = out[start + j];
    }
    free(table);
    return result;
}
