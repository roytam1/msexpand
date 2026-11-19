/* delta.c -- PA30 / PA19 delta blob application (C89). */
#include "expand.h"
#include "delta.h"
#include "lzx.h"
#include "mslzx.h"
#include "hash.h"
#include "pefix.h"

/* ---------- LSB-first bit reader over little-endian byte stream ---------- */
typedef struct tagBITR
{
    const unsigned char *p;
    const unsigned char *end;
    unsigned long bitpos;
} BITR;

static void br_init(BITR *b, const unsigned char *p, unsigned long n)
{
    b->p = p;
    b->end = p + n;
    b->bitpos = 3;      /* skip the 3-bit zero leader */
}

static unsigned br_bit(const BITR *b, unsigned long idx)
{
    unsigned long bp = b->bitpos + idx;
    unsigned long byteIdx = bp >> 3;
    if (b->p + byteIdx >= b->end)
        return 0;
    return (unsigned)((b->p[byteIdx] >> (bp & 7)) & 1U);
}

static unsigned br_peek(const BITR *b, unsigned n)
{
    unsigned v = 0;
    unsigned i;
    for (i = 0; i < n; ++i)
        v |= br_bit(b, i) << i;
    return v;
}

static void br_skip(BITR *b, unsigned n)
{
    b->bitpos += n;
}

static unsigned br_read(BITR *b, unsigned n)
{
    unsigned v = br_peek(b, n);
    br_skip(b, n);
    return v;
}

/* Unary-coded, nibble-granularity integer (compo IntFunctions::ReadBit). */
static unsigned br_read_int(BITR *b)
{
    unsigned n = 0;
    while (!br_peek(b, 1))
    {
        ++n;
        br_skip(b, 1);
        if (n >= 16)
            return 0xFFFFFFFFU;
    }
    br_skip(b, 1);
    if (n < 8)
        return br_read(b, 4 * n + 4);
    {
        unsigned v = br_read(b, 32);
        br_skip(b, 4 * n - 28);
        return v;
    }
}

static void br_align(BITR *b)
{
    b->bitpos = (b->bitpos + 7) & ~7UL;
}

/* BitReadBuffer: int-coded length, byte-align, then raw bytes. */
static int br_read_blob(BITR *b, unsigned char *out, unsigned cap,
                        unsigned *len)
{
    unsigned n = br_read_int(b);
    if (n == 0xFFFFFFFFU || n > cap)
        return -1;
    br_align(b);
    if (b->p + (b->bitpos >> 3) + n > b->end)
        return -1;
    if (out && n)
        memcpy(out, b->p + (b->bitpos >> 3), n);
    b->bitpos += (unsigned long)n * 8;
    *len = n;
    return 0;
}

/* ---------- PA30 header --------------------------------------------------- */
typedef struct tagPA30
{
    unsigned version;
    unsigned code;
    unsigned flags;
    unsigned targetSize;
    unsigned hashAlg;
    unsigned char hash[32];
    unsigned hashLen;
    unsigned long payloadOff;   /* byte offset of payload in delta blob */
} PA30;

static int Pa30ParseHeader(const unsigned char *d, unsigned long n, PA30 *h)
{
    BITR br;
    unsigned hlen;

    memset(h, 0, sizeof(*h));
    if (n < 12 || memcmp(d, "PA30", 4) != 0)
        return -1;
    br_init(&br, d + 12, n - 12);
    h->version = br_read_int(&br);
    h->code = br_read_int(&br);
    h->flags = br_read_int(&br);
    h->targetSize = br_read_int(&br);
    h->hashAlg = br_read_int(&br);
    br_read_blob(&br, h->hash, (unsigned)sizeof(h->hash), &hlen);
    h->hashLen = hlen;
    h->payloadOff = 12 + (br.bitpos >> 3);
    if (h->targetSize == 0 || h->targetSize > 0x10000000UL)
        return -1;
    return 0;
}

/* ---------- compo IntFormat (custom static Huffman integer codec) -------- */
#define IF_NUM_SYMS 252

typedef struct tagINTFORMAT
{
    unsigned char len[IF_NUM_SYMS];
    unsigned short count[17];
    unsigned short first[17];
    unsigned short sym[IF_NUM_SYMS];
} INTFORMAT;

static int if_build(INTFORMAT *f)
{
    unsigned len, i, index;
    int left;
    for (len = 0; len <= 16; ++len)
        f->count[len] = 0;
    for (i = 0; i < IF_NUM_SYMS; ++i)
        ++f->count[f->len[i]];
    f->count[0] = 0;
    left = 0;
    for (len = 1; len <= 16; ++len)
    {
        left = (left + (int)f->count[len - 1]) << 1;
        f->first[len] = (unsigned short)left;
    }
    index = 0;
    for (i = 0; i < IF_NUM_SYMS; ++i)
        f->sym[index++] = (unsigned short)i;   /* ordered by length below */
    index = 0;
    for (len = 1; len <= 16; ++len)
    {
        for (i = 0; i < IF_NUM_SYMS; ++i)
        {
            if (f->len[i] == len)
                f->sym[index++] = (unsigned short)i;
        }
    }
    return (index == IF_NUM_SYMS) ? 0 : -1;
}

static unsigned if_decode(const INTFORMAT *f, BITR *br)
{
    unsigned code = 0;
    unsigned first = 0;
    unsigned index = 0;
    unsigned len, countv;
    /* Huffman code bits are consumed MSB-first from the 32-bit window. */
    for (len = 1; len <= 16; ++len)
    {
        code = (code << 1) | br_bit(br, 0);
        br_skip(br, 1);
        countv = f->count[len];
        if (code - countv < first)
            return f->sym[index + (code - first)];
        index += countv;
        first += countv;
        first <<= 1;
    }
    return 0;
}

static __int64 if_read_number(INTFORMAT *f, BITR *br)
{
    unsigned s = if_decode(f, br);
    unsigned neg;
    __int64 v;
    br_skip(br, f->len[s]);
    neg = (s >= 126);
    if (neg)
        s -= 126;
    if (s >= 4)
    {
        unsigned extra = (s >> 1) - 1;
        v = (__int64)((((s & 1) + 2) << extra) | br_peek(br, extra));
        br_skip(br, extra);
    }
    else
    {
        v = s;
    }
    return neg ? ~v : v;
}

static int if_read(INTFORMAT *f, BITR *br)
{
    unsigned n1, n2, run;
    unsigned char base;
    unsigned i;

    memset(f, 0, sizeof(*f));
    n1 = br_read(br, 8);
    n2 = br_read(br, 8);
    run = br_read(br, 8);
    if (n1 > 0x7E || n2 > 0x7E || run > 252u - n1 - n2)
        return -1;
    for (i = 0; i < n1; ++i)
        f->len[i] = (unsigned char)(br_read(br, 4) + 1);
    base = (unsigned char)(br_read(br, 4) + 1);
    for (i = 0; i < n2; ++i)
        f->len[126 + i] = (unsigned char)(br_read(br, 4) + 1);
    if (base > 16)
        return -1;
    for (i = n1; i < 126; ++i)
    {
        if (run-- == 0)
        {
            --base;
            run = 252u - i - n2;
        }
        f->len[i] = base;
    }
    for (i = n2; i < 126; ++i)
    {
        if (run-- == 0)
        {
            --base;
            run = 126u - i;
        }
        f->len[126 + i] = base;
    }
    return if_build(f);
}

typedef struct tagRIFTENTRY
{
    __int64 left;
    __int64 right;
} RIFTENTRY;

static int rift_read(BITR *br, RIFTENTRY **out, unsigned *outn)
{
    INTFORMAT fa, fb;
    unsigned n, i;
    __int64 left = 0, rift = 0;
    RIFTENTRY *tab;

    *out = NULL;
    *outn = 0;
    if (br_read(br, 1) == 0)
        return 0;                       /* empty table */
    if (if_read(&fa, br) != 0 || if_read(&fb, br) != 0)
        return -1;
    n = br_read_int(br);
    if (n == 0xFFFFFFFFU || n > 0x0FFFFFFFUL)
        return -1;
    tab = (RIFTENTRY *)calloc(n ? (size_t)n : 1, sizeof(*tab));
    if (!tab)
        return -1;
    for (i = 0; i < n; ++i)
    {
        left += if_read_number(&fa, br);
        rift += if_read_number(&fb, br);
        tab[i].left = left;
        tab[i].right = left + rift;
    }
    *out = tab;
    *outn = n;
    return 0;
}

/* ---------- generic canonical Huffman (bit-reversed, LSB-first) ----------- */
#define HUFF_MAX_SYMS 872
#define HUFF_MAX_BITS 16

typedef struct tagHUFF
{
    unsigned n;
    unsigned maxBits;
    unsigned char len[HUFF_MAX_SYMS];
    unsigned int code[HUFF_MAX_SYMS];   /* bit-reversed canonical codes */
    unsigned int msb[HUFF_MAX_SYMS];    /* canonical codes, MSB-first */
} HUFF;

static int huff_build(HUFF *h, const unsigned char *lens, unsigned n,
                      unsigned maxBits)
{
    unsigned cnt[HUFF_MAX_BITS + 2];
    unsigned first[HUFF_MAX_BITS + 2];
    unsigned i, len;
    unsigned nextCode;

    if (n > HUFF_MAX_SYMS || maxBits > HUFF_MAX_BITS)
        return -1;
    h->n = n;
    h->maxBits = maxBits;
    memset(h->len, 0, sizeof(h->len));
    memcpy(h->len, lens, (size_t)n);
    for (i = 0; i <= maxBits + 1; ++i)
        cnt[i] = 0;
    for (i = 0; i < n; ++i)
        ++cnt[h->len[i]];
    {
        unsigned left = 2;
        for (len = 1; len <= maxBits; ++len)
        {
            if (cnt[len] > left)
                return -1;
            left = 2 * (left - cnt[len]);
        }
    }
    nextCode = 0;
    for (len = maxBits + 1; len > 0; --len)
    {
        first[len] = nextCode;
        nextCode = (nextCode + cnt[len]) >> 1;
    }
    for (i = 0; i < n; ++i)
    {
        unsigned l = h->len[i];
        h->code[i] = 0;
        if (l)
        {
            unsigned c = first[l]++;
            unsigned r = 0;
            unsigned k;
            h->msb[i] = c;
            for (k = 0; k < l; ++k)
            {
                r = (r << 1) | (c & 1);
                c >>= 1;
            }
            h->code[i] = r;
        }
    }
    return 0;
}

static unsigned huff_decode(const HUFF *h, BITR *br)
{
    unsigned code = 0;
    unsigned len;
    unsigned i;
    for (len = 1; len <= h->maxBits; ++len)
    {
        code |= br_read(br, 1) << (len - 1);
        for (i = 0; i < h->n; ++i)
        {
            if (h->len[i] == len && h->code[i] == code)
                return i;
        }
    }
    return 0;
}

/* The meta-code stream is consumed MSB-first (like the IntFormat codes). */
static unsigned huff_decode_msb(const HUFF *h, BITR *br)
{
    unsigned code = 0;
    unsigned len;
    unsigned i;
    for (len = 1; len <= h->maxBits; ++len)
    {
        code = (code << 1) | br_read(br, 1);
        for (i = 0; i < h->n; ++i)
        {
            if (h->len[i] == len && h->msb[i] == code)
                return i;
        }
    }
    return 0;
}

/* CompressionFormat::ReadNumber(br, n): l=lowest_set_bit(bits);
 * Consume(l+1); return (1<<(l+n)) | Read(l+n). */
static unsigned cf_read_number(BITR *br, unsigned n)
{
    unsigned l = 0;
    unsigned v;
    while (l < 31 && !(br_peek(br, 1) & 1))
    {
        ++l;
        br_skip(br, 1);
    }
    br_skip(br, 1);
    v = (1U << (l + n)) | br_peek(br, l + n);
    br_skip(br, l + n);
    return v;
}

/* ---------- CompressionLengths::Read ------------------------------------- */
static int cl_read(unsigned char *lens, BITR *br, const HUFF *meta,
                   const unsigned char *baseline)
{
    unsigned pos = 0;
    memset(lens, 0, 872);
    while (pos < 872)
    {
        unsigned sym = huff_decode_msb(meta, br);
        if (sym < 17)
        {
            lens[pos++] = (unsigned char)sym;
        }
        else if (sym < 23)
        {
            unsigned prev = baseline[pos];
            unsigned v;
            if (sym < 20)
                v = prev + (sym - 16);
            else
                v = prev - (sym - 19);
            if (v > 16)
                return -1;
            lens[pos++] = (unsigned char)v;
        }
        else
        {
            unsigned k = (sym - 23) & 7;
            unsigned run;
            const unsigned char *src;
            unsigned i;
            if (k < 3)
                run = k + 1;
            else
                run = (1U << (k - 1)) | br_peek(br, k - 1);
            br_skip(br, k < 3 ? 0 : k - 1);
            if (pos + run > 872)
                return -1;
            if (sym >= 31)
                src = baseline;
            else
            {
                if (pos == 0)
                    return -1;
                src = lens;
            }
            for (i = 0; i < run; ++i)
                lens[pos + i] = src[src == lens ? pos - 1 + i : pos + i];
            pos += run;
        }
    }
    return 0;
}

/* ---------- compo CompositeFormat ---------------------------------------- */
typedef struct tagCOMPFMT
{
    unsigned nSeg;
    unsigned boundary[32];
    unsigned char metaLen[39];
    unsigned char lens[32][872];
} COMPFMT;

static int compfmt_read(COMPFMT *f, BITR *br)
{
    HUFF meta;
    unsigned char initial[872];
    const unsigned char *baseline;
    unsigned i;

    memset(f, 0, sizeof(*f));
    if (br_read(br, 1))
    {
        f->nSeg = 1;
        f->boundary[0] = 0;
        return 0;                   /* default format */
    }
    f->nSeg = br_read_int(br);
    if (f->nSeg == 0 || f->nSeg > 32)
        return -1;
    /* Boundaries are absolute output offsets in this stream. */
    for (i = 0; i < f->nSeg; ++i)
        f->boundary[i] = (unsigned)br_read_int(br);
    for (i = 0; i < 39; ++i)
        f->metaLen[i] = (unsigned char)br_read(br, 4);
    if (huff_build(&meta, f->metaLen, 39, 15) != 0)
        return -1;

    /* Each segment's length set is delta-coded against the previous one.
     * The encoder starts from Init(Val=1), which memset()s the lengths to 0. */
    memset(initial, 0, sizeof(initial));
    baseline = initial;
    for (i = 0; i < f->nSeg; ++i)
    {
        if (cl_read(f->lens[i], br, &meta, baseline) != 0)
            return -1;
        baseline = f->lens[i];
    }
    return 0;
}

/* ---------- CompressionFormat::ReadSymbol -------------------------------- */
typedef struct tagCOMPRESSIONFORMAT
{
    HUFF main;
    HUFF len;
    HUFF dist;
} COMPF;

static int compf_build(COMPF *cf, const unsigned char *lens)
{
    unsigned char tmp[HUFF_MAX_SYMS];
    unsigned i;
    memset(tmp, 0, sizeof(tmp));
    memset(cf, 0, sizeof(*cf));
    if (huff_build(&cf->main, lens, 600, 16) != 0 ||
        huff_build(&cf->len, lens + 600, 256, 16) != 0 ||
        huff_build(&cf->dist, lens + 856, 16, 16) != 0)
        return -1;
    (void)i;
    (void)tmp;
    return 0;
}

/* Build the fixed ("default") length sets: ResetLengths(Size, Val=0). */
static void make_fixed_lengths(unsigned char *out, unsigned n)
{
    unsigned bits = 0;
    unsigned v = n - 1;
    unsigned half;
    while (v) { ++bits; v >>= 1; }
    half = (1U << bits) - n;
    memset(out, (unsigned char)(bits - 1), (size_t)half);
    memset(out + half, (unsigned char)bits, (size_t)(n - half));
}

typedef struct tagSYMBOL
{
    unsigned long value;
    unsigned length;
} SYMBOL;

static int cf_read_symbol(COMPF *cf, BITR *br, SYMBOL *sym)
{
    unsigned s = huff_decode(&cf->main, br);
    unsigned v8, k, number;
    long d;

    if (s < 0x100)
    {
        sym->value = s;
        sym->length = 1;
        return 0;
    }
    v8 = s - 256;
    k = v8 >> 3;
    number = v8 & 7;

    if (k < 3)
    {
        if (k == 0)
            d = (long)br_read(br, 14) - 0x2000;
        else if (k == 1)
        {
            long t = (long)br_read(br, 16) - 0x8000;
            d = t < 0x8000 ? t + 0x2000 : t;
        }
        else
        {
            long t = (long)br_read(br, 18) - 0x20000;
            d = t >= 0x20000 ? t - 40960 : t + 40960;
        }
        sym->value = (unsigned long)(d + 172032);   /* +0x2A000 */
    }
    else if (k < 7)
    {
        sym->value = 0x54000UL + (k - 3);   /* rift or repeat sentinel */
    }
    else
    {
        unsigned v15 = k - 7;
        unsigned v20;
        if (v15 == 0)
        {
            unsigned v16;
            if (br_read(br, 1))
            {
                unsigned v17;
                if (br_read(br, 1))
                    v17 = br_read(br, 4) + 8;
                else
                    v17 = br_read(br, 3);
                v16 = v17 + 4;
            }
            else
            {
                v16 = br_read(br, 2);
            }
            v15 = v16 + 36;
        }
        if (v15 >= 0x40)
            return -1;
        if (v15 >= 4)
        {
            unsigned v21 = (v15 >> 1) - 1;
            unsigned v22 = (v15 & 1) + 2;
            if (v21 >= 4)
            {
                unsigned ds;
                v22 = br_read(br, v21 - 4) | (v22 << (v21 - 4));
                ds = huff_decode(&cf->dist, br);
                v20 = ds | (16 * v22);
            }
            else
            {
                v20 = (v22 << v21) | br_read(br, v21);
            }
        }
        else
        {
            v20 = v15;
        }
        sym->value = (unsigned long)v20 + 344067UL;   /* +0x54003 */
    }

    if (number == 0)
    {
        unsigned ls = huff_decode(&cf->len, br);
        number = ls;
        if (number == 0)
            number = cf_read_number(br, 8);
        number += 7;
    }
    sym->length = number + 1;
    return 0;
}

/* Reverse DELTA_FLAG_E8 translation once the whole target is decoded. */
static void e8_untranslate(unsigned char *out, unsigned long outLen)
{
    unsigned long i;
    for (i = 0; i + 4 < outLen; ++i)
    {
        unsigned long raw;
        long rel;
        if (out[i] != 0xE8)
            continue;
        raw = (unsigned long)out[i + 1] |
              ((unsigned long)out[i + 2] << 8) |
              ((unsigned long)out[i + 3] << 16) |
              ((unsigned long)out[i + 4] << 24);
        rel = (raw & 0x80000000UL) ? (long)raw - 0x100000000L : (long)raw;
        if (rel < -0x8000 || rel >= 0x8000)
            continue;               /* ordinary data, not a CALL rel32 */
        rel -= (long)i;
        out[i + 1] = (unsigned char)(rel & 0xFF);
        out[i + 2] = (unsigned char)((rel >> 8) & 0xFF);
        out[i + 3] = (unsigned char)((rel >> 16) & 0xFF);
        out[i + 4] = (unsigned char)((rel >> 24) & 0xFF);
    }
}

/* ---------- Decompress ---------------------------------------------------- */
static int compo_decompress(BITR *br, const COMPFMT *fmt,
                            const unsigned char *src, unsigned long srcLen,
                            const RIFTENTRY *rift, unsigned riftN,
                            unsigned char *out, unsigned long outLen,
                            int e8Translate)
{
    unsigned long pos = 0;
    long hist[3] = { 0, 0, 0 };
    COMPF cf;
    unsigned char lens[872];
    unsigned segIndex = 0;
    int currentSeg = -1;
    int rc;

    while (pos < outLen)
    {
        SYMBOL sym;
        while (segIndex + 1 < fmt->nSeg &&
               pos >= fmt->boundary[segIndex + 1])
            ++segIndex;
        if ((int)segIndex != currentSeg)
        {
            if (fmt->nSeg == 1 && fmt->boundary[0] == 0)
            {
                make_fixed_lengths(lens, 600);
                make_fixed_lengths(lens + 600, 256);
                make_fixed_lengths(lens + 856, 16);
            }
            else
            {
                memcpy(lens, fmt->lens[segIndex], sizeof(lens));
            }
            if (compf_build(&cf, lens) != 0)
                return -1;
            currentSeg = (int)segIndex;
        }

        rc = cf_read_symbol(&cf, br, &sym);
        if (rc != 0)
            return -1;


        if (sym.length == 1)
        {
            out[pos++] = (unsigned char)sym.value;
            continue;
        }
        {
            unsigned long len = sym.length;   /* type is the byte count */
            long dist = 0;
            long riftOff = 0;
            unsigned ri;
            for (ri = 0; ri < riftN; ++ri)
            {
                if ((unsigned long)rift[ri].right >= pos)
                {
                    riftOff = (long)(rift[ri].right - rift[ri].left);
                    break;
                }
            }
            if (sym.value == 0x54000UL)
            {
                /* With an empty rift table the identity map applies to the
                 * combined source+output window: positions below srcLen read
                 * the source, later positions read already-decoded output. */
                long sp = (long)pos + riftOff;
                unsigned long j;
                if (sp < 0 || (unsigned long)(sp + (long)len) > srcLen + pos)
                    return -1;
                if (len > outLen - pos)
                    len = outLen - pos;
                for (j = 0; j < len; ++j)
                {
                    long ap = sp + (long)j;
                    if (ap < (long)srcLen)
                        out[pos + j] = src[ap];
                    else
                        out[pos + j] = out[ap - (long)srcLen];
                }
            }
            else if (sym.value < 0x54000UL)
            {
                dist = (long)(sym.value - 172032UL) - riftOff;
            }
            else if (sym.value < 0x54004UL)
            {
                dist = hist[sym.value - 0x54001UL];
            }
            else
            {
                dist = (long)(sym.value - 344067UL);
            }
            if (sym.value != 0x54000UL)
            {
                unsigned long i;
                /* The match window is the source file followed by the
                 * bytes decoded so far, so a distance larger than `pos`
                 * reaches back into the source. */
                if (dist == 0 || dist > (long)(pos + srcLen) ||
                    dist < -(long)srcLen)
                    return -1;
                if (len > outLen - pos)
                    len = outLen - pos;
                for (i = 0; i < len; ++i)
                {
                    long ap = (long)pos + (long)i - dist;
                    if (ap >= 0)
                        out[pos + i] = out[ap];
                    else
                        out[pos + i] = src[srcLen + ap];
                }
            }
            /* Mirrors InternalProcess: the third slot is not overwritten
             * when the old second slot already equals the new distance. */
            if (hist[0] != dist)
            {
                unsigned long oldSecond = hist[1];
                hist[1] = hist[0];
                if (oldSecond != dist)
                    hist[2] = oldSecond;
                hist[0] = dist;
            }
            pos += len;
        }
    }
    if (e8Translate)
        e8_untranslate(out, outLen);
    return 0;
}

/* ---------- PA19 legacy patch -------------------------------------------- */
typedef struct tagP19RANGE
{
    unsigned long off;
    unsigned long len;
    unsigned long offNew;
} P19RANGE;

typedef struct tagP19SECTION
{
    unsigned long sourceOffset;
    unsigned long targetCrc;
    unsigned long compressedLen;
    unsigned long extraCount;
    unsigned long *rift;            /* 2*extraCount {OldFileRva,NewFileRva} */
    unsigned long retainCount;
    P19RANGE ignore[16];
    P19RANGE retain[16];
    unsigned long groups[3 * 16];
    unsigned long groupCount;
} P19SECTION;

static unsigned long rd32(const unsigned char *p)
{
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) |
           ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

static unsigned short rd16(const unsigned char *p)
{
    return (unsigned short)(p[0] | (p[1] << 8));
}

/* unsigned LEB128-like: bit7 = continuation, 7 data bits */
static const unsigned char *uvar(const unsigned char *p, const unsigned char *end,
                                 unsigned long *out)
{
    unsigned long v = 0;
    int sh = 0;
    unsigned char b;
    do
    {
        if (p >= end) { *out = 0; return p; }
        b = *p++;
        v |= (unsigned long)(b & 0x7F) << sh;
        sh += 7;
    } while (!(b & 0x80) && sh < 32);
    *out = v;
    return p;
}

/* signed: first byte 6 data bits, bit6 sign, bit7 continuation */
static const unsigned char *svar(const unsigned char *p, const unsigned char *end,
                                 long *out)
{
    unsigned char b0;
    long v;
    unsigned char b = 0;
    int sh = 6;
    const unsigned char *q;
    if (p >= end) { *out = 0; return p; }
    b0 = *p;
    v = b0 & 0x3F;
    q = p + 1;
    if ((signed char)b0 >= 0)
    {
        do
        {
            if (q >= end) break;
            b = *q++;
            v |= (long)(b & 0x7F) << sh;
            sh += 7;
        } while (!(b & 0x80) && sh < 32);
    }
    if (b0 & 0x40)
        v = -v;
    *out = v;
    return q;
}

/* Mirrors mspatcha's LzxWindowSize() + LzxMaxWindowSize(). */
static int Pa19WindowBits(unsigned long oldSize, unsigned long newSize,
                          unsigned long flags1)
{
    unsigned long maxWin = (flags1 & 4) ? 0x2000000UL : 0x800000UL;
    unsigned long need = newSize + ((oldSize + 0x7FFFUL) & 0xFFFF8000UL);
    unsigned long w = maxWin;
    int bits;
    while ((w >> 1) >= need)
        w >>= 1;
    if (w < 0x20000UL)
        w = 0x20000UL;
    bits = 0;
    while ((1UL << bits) < w && bits < 25)
        ++bits;
    return bits < 15 ? 15 : bits;
}

/* The original expand.exe delegates PA19 application to mspatcha.dll.
 * Use the OS implementation when present: it is authoritative and keeps us
 * byte-exact even where the in-tree LZX variant differs.  The native path
 * below remains as a fallback for systems without mspatcha.dll. */
typedef BOOL (WINAPI *PFN_APPLY_PATCH_BUFFERS)(
    unsigned char *, ULONG, unsigned char *, ULONG,
    unsigned char **, ULONG, ULONG *, FILETIME *, ULONG, void *, void *);

static int Pa19ApplyViaOS(const unsigned char *d, unsigned long n,
                          const unsigned char *src, unsigned long srcLen,
                          unsigned char **out, unsigned long *outLen)
{
    HMODULE h;
    PFN_APPLY_PATCH_BUFFERS fn;
    unsigned char *buf;
    ULONG cap = 128UL * 1024UL * 1024UL, actual = 0;
    BOOL ok;

    if (getenv("PA19_NO_OS"))
        return -1;
    h = LoadLibraryA("mspatcha.dll");
    if (!h)
        return -1;
    fn = (PFN_APPLY_PATCH_BUFFERS)GetProcAddress(h,
                                                "ApplyPatchToFileByBuffers");
    if (!fn) { FreeLibrary(h); return -1; }
    buf = (unsigned char *)malloc((size_t)cap);
    if (!buf) { FreeLibrary(h); return -1; }
    ok = fn((unsigned char *)d, (ULONG)n, (unsigned char *)src, (ULONG)srcLen,
            &buf, cap, &actual, NULL, 0, NULL, NULL);
    FreeLibrary(h);
    if (!ok || !actual) { free(buf); return -1; }
    *out = buf;
    *outLen = actual;
    return 0;
}

static int Pa19Apply(const unsigned char *d, unsigned long n,
                     const unsigned char *src, unsigned long srcLen,
                     unsigned char **out, unsigned long *outLen)
{
    const unsigned char *p = d + 4;
    const unsigned char *end = d + n;
    unsigned long flags1, flags2 = 0, newSize, crc, sectionCount;
    unsigned long dataOff;
    P19SECTION secs[16];
    unsigned long i, j;
    unsigned char *result;
    const unsigned char *comp;
    unsigned long windowBits = 15;
    int windowExplicit = 0;
    unsigned long k;
    unsigned long coffTime = 0, coffBase = 0, coffTimeVal = 0;
    unsigned char *preparedSrc = NULL;
    int hasExtraFlags = 0;

    if (Pa19ApplyViaOS(d, n, src, srcLen, out, outLen) == 0)
        return 0;
    if (n < 16 || memcmp(d, "PA19", 4) != 0)
        return -1;
    flags1 = rd32(p) ^ 0x00800000UL;
    p += 4;
    if (flags1 & 0x80000000UL)
    {
        hasExtraFlags = 1;
        if (p + 4 > end) return -1;
        flags2 = rd32(p);
        p += 4;
    }
    if (!(flags1 & 0x00800000UL))
    {
        if (p + 4 > end) return -1;
        coffTime = rd32(p);
        p += 4;                     /* target FILETIME / new COFF time */
    }
    if (!(flags1 & 0x00040000UL))
    {
        coffBase = (unsigned long)rd16(p) << 16;   /* newFileCoffBase */
        p += 2;
        {
            long d;
            p = svar(p, end, &d);                   /* NewFileTime - CoffTime */
            coffTimeVal = (unsigned long)((long)coffTime - d);
        }
    }
    if (!(flags1 & 0x00400000UL))
    {
        p = svar(p, end, (long *)&k); /* peHint */
    }
    p = uvar(p, end, &newSize);
    if (p + 4 > end) return -1;
    crc = rd32(p);
    p += 4;
    if (flags2 & 0x00010000UL)
    {
        if (p >= end) return -1;
        windowBits = *p++;
        windowExplicit = 1;
    }
    if (!windowExplicit)
        windowBits = (unsigned)Pa19WindowBits(srcLen, newSize, flags1);
    if (p >= end) return -1;
    sectionCount = *p++;
    if (sectionCount == 0 || sectionCount > 16)
        return -1;
    memset(secs, 0, sizeof(secs));
    for (i = 0; i < sectionCount; ++i)
    {
        P19SECTION *s = &secs[i];
        long delta;
        long acc = 0;
        p = svar(p, end, &delta);
        s->sourceOffset = (unsigned long)((long)newSize + delta);
        if (p + 4 > end) return -1;
        s->targetCrc = rd32(p);
        p += 4;
        if (p >= end) return -1;
        {
            unsigned long ic = *p++;
            if (ic > 16) return -1;
            for (j = 0; j < ic; ++j)
            {
                p = svar(p, end, &delta);
                s->ignore[j].off = (unsigned long)(acc + delta);
                p = uvar(p, end, &s->ignore[j].len);
                acc += delta + (long)s->ignore[j].len;
            }
        }
        if (p >= end) return -1;
        {
            unsigned long rc = *p++;
            if (rc > 16) return -1;
            s->retainCount = rc;
            acc = 0;
            for (j = 0; j < rc; ++j)
            {
                p = svar(p, end, &delta);
                s->retain[j].off = (unsigned long)(acc + delta);
                p = svar(p, end, &delta);
                s->retain[j].offNew =
                    (unsigned long)((long)s->retain[j].off + delta);
                p = uvar(p, end, &s->retain[j].len);
                acc += delta + (long)s->retain[j].len;
            }
        }
        p = uvar(p, end, &s->extraCount);
        if (s->extraCount)
        {
            unsigned long prevOld = 0, prevNew = 0;
            s->rift = (unsigned long *)malloc(
                (size_t)s->extraCount * 2 * sizeof(unsigned long));
            if (!s->rift) return -1;
            for (j = 0; j < s->extraCount; ++j)
            {
                unsigned long dpos;
                long dnew;
                p = uvar(p, end, &dpos);
                p = svar(p, end, &dnew);
                prevOld += dpos;
                prevNew = (unsigned long)((long)prevNew + dnew);
                s->rift[2 * j] = prevOld;
                s->rift[2 * j + 1] = prevNew;
            }
        }
        if (flags1 & 0x40000000UL)
        {
            unsigned long gc;
            p = uvar(p, end, &gc);
            if (gc > 16) return -1;
            s->groupCount = gc;
            {
                long a = 0, b = 0, c = 0, d = 0;
                for (j = 0; j < gc; ++j)
                {
                    p = svar(p, end, &delta);
                    a += delta;
                    s->groups[3 * j] = (unsigned long)a;
                    p = svar(p, end, &delta);
                    b += delta;
                    c += b;
                    s->groups[3 * j + 1] = (unsigned long)c;
                    p = svar(p, end, &delta);
                    d += delta << 15;
                    s->groups[3 * j + 2] = (unsigned long)d;
                }
            }
            if (gc > 0)
                s->groups[3 * (gc - 1) + 2] =
                    newSize - s->groups[3 * (gc - 1)];
        }
        else
        {
            s->groupCount = 1;
            s->groups[0] = 0;
            s->groups[1] = srcLen < (1UL << windowBits) ?
                            srcLen : (1UL << windowBits);
            s->groups[2] = newSize;
        }
        p = uvar(p, end, &s->compressedLen);
    }
    dataOff = (unsigned long)(p - d);
    comp = d + dataOff;
    if (newSize == 0 || newSize > 0x10000000UL)
        return -1;
    result = (unsigned char *)malloc((size_t)newSize);
    if (!result)
        return -1;
    memset(result, 0, (size_t)newSize);

    /* The reference patcher prepares a *copy* of the old-file image before
     * seeding LZxD: it normalises PE headers (timestamp/checksum/rebase) and,
     * when the patch carries a RIFT map, applies the PE transform (relocs,
     * relative branches, imports, exports).  The stream was encoded against
     * that transformed image, so seed the decoder with the same bytes. */
    if (srcLen)
    {
        preparedSrc = (unsigned char *)malloc((size_t)srcLen);
        if (!preparedSrc)
        {
            free(result);
            return -1;
        }
        memcpy(preparedSrc, src, (size_t)srcLen);
        if (PeFixPrepareSeed(preparedSrc, srcLen, flags1, flags2,
                             coffBase, coffTimeVal,
                             secs[0].rift, secs[0].extraCount) < 0)
        {
            free(preparedSrc);
            free(result);
            return -1;
        }
    }

    for (i = 0; i < sectionCount; ++i)
    {
        P19SECTION *s = &secs[i];
        const unsigned char *cp = comp;
        unsigned long outOff = 0;
        unsigned long g;

        if (s->compressedLen > (unsigned long)(end - comp))
        {
            if (getenv("PA19_DEBUG")) fprintf(stderr, "FAIL compressedLen\n");
            free(result);
            return -1;
        }
        {
            unsigned long maxChunks = s->compressedLen / 2 + 2;
            const unsigned char **chunks = (const unsigned char **)
                malloc((size_t)maxChunks * sizeof(*chunks));
            unsigned long *sizes = (unsigned long *)
                malloc((size_t)maxChunks * sizeof(*sizes));
            unsigned long nchunks = 0;
            unsigned long totalOut = 0;

            if (!chunks || !sizes) { free((void *)chunks); free((void *)sizes); free(result); return -1; }
            cp = comp;
            while (cp + 2 <= comp + s->compressedLen)
            {
                unsigned long h = rd16(cp);
                const unsigned char *blk = cp + 2;
                if (h > (unsigned long)(comp + s->compressedLen - blk)) break;
                chunks[nchunks] = blk;
                sizes[nchunks] = h;
                ++nchunks;
                cp = blk + h;
            }
            for (g = 0; g < s->groupCount; ++g)
                totalOut += s->groups[3 * g + 2];

            if (s->groupCount == 1 && nchunks > 0 && totalOut == newSize)
            {
                if (MsLzxDecompressSeededMulti(chunks, sizes, nchunks,
                                               result + outOff, totalOut,
                                               (int)windowBits,
                                               s->groups[1] ? (preparedSrc ? preparedSrc : src) + s->groups[0] : NULL,
                                               s->groups[1]) != 0)
                {
                        free((void *)chunks); free((void *)sizes); free(result);
                    return -1;
                }
                outOff += totalOut;
            }
            else if (nchunks == 0)
            {
                /* header-test patch: target is just the (normalized) source */
                if (totalOut > srcLen) { free((void *)chunks); free((void *)sizes); free(result); return -1; }
                memcpy(result + outOff, preparedSrc ? preparedSrc : src, (size_t)totalOut);
                outOff += totalOut;
            }
            else
            {
                free((void *)chunks); free((void *)sizes); free(result);
                return -1;
            }
            free((void *)chunks);
            free((void *)sizes);
        }
        comp += s->compressedLen;
    }
    free(preparedSrc);
    for (i = 0; i < sectionCount; ++i)
        free(secs[i].rift);
    (void)windowExplicit;
    (void)crc;
    *out = result;
    *outLen = newSize;
    return 0;
}

/* ---------- OS PA30 delegation -------------------------------------------- */
/* The native compo decoder in this tree only implements the default
 * CompositeFormat.  Real deltas (e.g. the ones in Windows Update MSU
 * packages) carry explicit per-segment code lengths, so fall back to the
 * system msdelta.dll, exactly as the PA19 path falls back to mspatcha.dll.
 * Set PA30_NO_OS=1 to exercise the native path anyway. */
typedef BOOL (WINAPI *PFN_APPLY_DELTA_A)(__int64, LPCSTR, LPCSTR, LPCSTR);

static int Pa30ApplyViaOS(const unsigned char *d, unsigned long n,
                          const unsigned char *src, unsigned long srcLen,
                          unsigned char **out, unsigned long *outLen)
{
    HMODULE h;
    PFN_APPLY_DELTA_A fn;
    char tmpDir[MAX_PATH];
    char srcPath[MAX_PATH];
    char deltaPath[MAX_PATH];
    char outPath[MAX_PATH];
    FILE *f;
    BOOL ok;
    unsigned char *buf;
    long size;

    if (getenv("PA30_NO_OS"))
        return -1;
    h = LoadLibraryA("msdelta.dll");
    if (!h)
        return -1;
    fn = (PFN_APPLY_DELTA_A)GetProcAddress(h, "ApplyDeltaA");
    if (!fn)
    {
        FreeLibrary(h);
        return -1;
    }
    GetTempPathA(MAX_PATH, tmpDir);
    GetTempFileNameA(tmpDir, "d30", 0, srcPath);
    GetTempFileNameA(tmpDir, "d30", 0, deltaPath);
    GetTempFileNameA(tmpDir, "d30", 0, outPath);
    f = fopen(srcPath, "wb");
    if (!f) goto fail;
    if (srcLen && fwrite(src, 1, (size_t)srcLen, f) != (size_t)srcLen)
    { fclose(f); goto fail; }
    fclose(f);
    f = fopen(deltaPath, "wb");
    if (!f) goto fail;
    if (fwrite(d, 1, (size_t)n, f) != (size_t)n)
    { fclose(f); goto fail; }
    fclose(f);

    ok = fn(0, srcPath, deltaPath, outPath);
    if (!ok)
        goto fail;
    f = fopen(outPath, "rb");
    if (!f) goto fail;
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0)
    { fclose(f); goto fail; }
    buf = (unsigned char *)malloc((size_t)size ? (size_t)size : 1);
    if (!buf || (size && fread(buf, 1, (size_t)size, f) != (size_t)size))
    {
        free(buf);
        fclose(f);
        goto fail;
    }
    fclose(f);
    DeleteFileA(srcPath);
    DeleteFileA(deltaPath);
    DeleteFileA(outPath);
    FreeLibrary(h);
    *out = buf;
    *outLen = (unsigned long)size;
    return 0;

fail:
    DeleteFileA(srcPath);
    DeleteFileA(deltaPath);
    DeleteFileA(outPath);
    FreeLibrary(h);
    return -1;
}

/* ---------- public API ---------------------------------------------------- */
int DeltaIsDelta(const unsigned char *delta, unsigned long deltaLen)
{
    if (deltaLen < 4)
        return 0;
    return (memcmp(delta, "PA30", 4) == 0 ||
            memcmp(delta, "PA19", 4) == 0);
}

int DeltaApply(const unsigned char *delta, unsigned long deltaLen,
               const unsigned char *source, unsigned long sourceLen,
               unsigned char **out, unsigned long *outLen)
{
    PA30 h;
    BITR br;
    unsigned preLen, patchLen;
    unsigned char *pre;
    unsigned char *patch;
    unsigned char *result;
    int rc;

    *out = NULL;
    *outLen = 0;
    if (deltaLen >= 4 && memcmp(delta, "PA19", 4) == 0)
        return Pa19Apply(delta, deltaLen, source, sourceLen, out, outLen);
    if (Pa30ApplyViaOS(delta, deltaLen, source, sourceLen, out, outLen) == 0)
        return 0;
    if (Pa30ParseHeader(delta, deltaLen, &h) != 0)
        return -1;

    br_init(&br, delta + h.payloadOff, deltaLen - h.payloadOff);
    br.bitpos = 0;   /* continue the header bit reader (already byte-aligned) */
    pre = (unsigned char *)malloc(h.targetSize + 1024);
    patch = (unsigned char *)malloc(h.targetSize + 1024);
    if (!pre || !patch)
    {
        free(pre);
        free(patch);
        return -1;
    }
    rc = br_read_blob(&br, pre, h.targetSize + 1024, &preLen);
    if (rc == 0)
        rc = br_read_blob(&br, patch, h.targetSize + 1024, &patchLen);
    if (rc != 0)
    {
        free(pre);
        free(patch);
        return -1;
    }
    {
        BITR pbr;
        RIFTENTRY *rt = NULL;
        unsigned rn = 0;
        COMPFMT cf;

        br_init(&pbr, patch, patchLen);
        rc = rift_read(&pbr, &rt, &rn);
        if (rc == 0)
            rc = compfmt_read(&cf, &pbr);
        if (rc == 0)
        {
            result = (unsigned char *)malloc(h.targetSize);
            if (!result)
                rc = -1;
            else
                rc = compo_decompress(&pbr, &cf,
                    (const unsigned char *)source, sourceLen,
                    rt, rn, result, h.targetSize, (int)(h.flags & 0x1));
            if (rc != 0)
            {
                free(result);
                result = NULL;
            }
        }
        free(rt);
        if (rc != 0)
        {
            free(pre);
            free(patch);
            return -1;
        }
    }

    free(pre);
    free(patch);
    *out = result;
    *outLen = h.targetSize;
    return 0;
}




