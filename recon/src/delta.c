/* delta.c -- PA30 / PA19 delta blob application (C89). */
#include "expand.h"
#include "delta.h"
#include "lzx.h"
#include "mslzx.h"
#include "hash.h"
#include "pefix.h"

#ifndef INT64_MIN
#define INT64_MIN  ((__int64)0x8000000000000000i64)
#endif
#ifndef INT64_MAX
#define INT64_MAX  ((__int64)0x7FFFFFFFFFFFFFFFi64)
#endif

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
    if (getenv("PA30_DEBUG")) fprintf(stderr,
        "HDR code=%u flags=%06X target=%u hashAlg=%u hashLen=%u payloadOff=%lu\n",
        h->code, h->flags, h->targetSize, h->hashAlg, h->hashLen, h->payloadOff);
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
    /* The DLL's statichuffman::Codes::CalculateCodes computes first codes
     * top-down: first[maxLen]=0, first[L]=(first[L+1]+count[L+1])>>1.  This
     * is NOT the textbook bottom-up recurrence; it assigns e.g. first[2]=2,
     * first[3]=1 for a 2/3-bit tree. */
    {
        unsigned maxLen = 0;
        for (len = 1; len <= 16; ++len)
            if (f->count[len]) maxLen = len;
        left = 0;
        for (len = maxLen; len >= 1; --len)
        {
            f->first[len] = (unsigned short)left;
            left = (left + (int)f->count[len]) >> 1;
        }
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
    unsigned index = 0;
    unsigned len;
    /* Huffman code bits are consumed MSB-first from the 32-bit window.
     * The first[] table comes from if_build()'s top-down recurrence (the
     * DLL's statichuffman::Codes::CalculateCodes), not the textbook one. */
    for (len = 1; len <= 16; ++len)
    {
        code = (code << 1) | br_bit(br, len - 1);   /* peek, no consume */
        if (f->count[len] && code >= f->first[len] &&
            code - f->first[len] < f->count[len])
        {
            unsigned si = index + (code - f->first[len]);
            return f->sym[si];
        }
        index += f->count[len];
    }
    return 0;
}

static __int64 if_read_number(INTFORMAT *f, BITR *br)
{
    unsigned s = if_decode(f, br);
    unsigned neg;
    __int64 v;
    if (getenv("PA30_IFDBG")) fprintf(stderr,
        "  IFNUM s=%u len=%u bitpos=%lu\n", s, f->len[s], br->bitpos);
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
    if (getenv("PA30_DEBUG")) fprintf(stderr,
        "  IF n1=%u n2=%u run=%u at bit %lu\n", n1, n2, run, br->bitpos);
    if (n1 > 0x7E || n2 > 0x7E || run > 252u - n1 - n2)
        return -1;
    for (i = 0; i < n1; ++i)
        f->len[i] = (unsigned char)(br_read(br, 4) + 1);
    /* The DLL reads the n2 large-symbol lengths first, then the `base`
     * value used to fill the remaining slots (InternalFromBitReader). */
    for (i = 0; i < n2; ++i)
        f->len[126 + i] = (unsigned char)(br_read(br, 4) + 1);
    base = (unsigned char)(br_read(br, 4) + 1);
    if (base > 16)
        return -1;
    if (getenv("PA30_IFDBG"))
    {
        unsigned j;
        fprintf(stderr, "IFREAD n1=%u n2=%u run=%u base=%u lens:",
                n1, n2, run, base);
        for (j = 0; j < IF_NUM_SYMS; ++j)
            if (f->len[j] <= 3) fprintf(stderr, " [%u]=%u", j, f->len[j]);
        fprintf(stderr, "\n");
    }
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
    if (getenv("PA30_IFDBG"))
    {
        unsigned j;
        fprintf(stderr, "IFBUILT lens:");
        for (j = 0; j < IF_NUM_SYMS; ++j)
            if (f->len[j] <= 3) fprintf(stderr, " [%u]=%u", j, f->len[j]);
        fprintf(stderr, "\n");
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
    {
        if (getenv("PA30_DEBUG")) fprintf(stderr, "  RIFT empty at bit %lu\n", br->bitpos);
        return 0;                       /* empty table */
    }
    if (getenv("PA30_DEBUG")) fprintf(stderr, "  RIFT nonempty at bit %lu\n", br->bitpos);
    if (if_read(&fa, br) != 0 || if_read(&fb, br) != 0)
        return -1;
    n = br_read_int(br);
    if (getenv("PA30_DEBUG")) fprintf(stderr, "  RIFT n=%u at bit %lu\n", n, br->bitpos);
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
        if (getenv("PA30_DEBUG") && i < 8) fprintf(stderr,
            "    RIFT[%u] left=%I64d rift=%I64d at bit %lu\n",
            i, left, rift, br->bitpos);
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
    unsigned defaultFormat;
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
        f->defaultFormat = 1;
        return 0;                   /* default format */
    }
    f->nSeg = br_read_int(br);
    if (f->nSeg == 0 || f->nSeg > 32)
        return -1;
    /* Boundaries are cumulative endpoints in the combined [source][output]
     * buffer, encoded as successive deltas.  The first delta is the source
     * length; convert each accumulated endpoint to an output-relative
     * switch offset by subtracting it. */
    {
        unsigned long acc = 0, base = 0;
        for (i = 0; i < f->nSeg; ++i)
        {
            unsigned long d = br_read_int(br);
            acc += d;
            if (i == 0)
                base = acc;
            f->boundary[i] = (unsigned)(acc - base);
        }
    }
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
        {
            d = (long)br_read(br, 14) - 0x2000;
        }
        else if (k == 1)
        {
            unsigned long t = br_read(br, 16);
            /* DLL compares (unsigned)(t - 0x8000) >= 0x8000: a value below
             * the bias underflows and takes the first branch. */
            if ((unsigned long)(t - 0x8000UL) >= 0x8000UL)
                d = (long)t - 40960;
            else
                d = (long)t - 0x8000 + 0x2000;
        }
        else
        {
            unsigned long t = br_read(br, 18);
            if ((unsigned long)(t - 0x20000UL) >= 0x20000UL)
                d = (long)t - 172032;
            else
                d = (long)t - 0x20000 + 40960;
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

/* DELTA_FLAG_E8 post-processing, mirroring the DLL's
 * PostProcessI386E8Component::InternalProcess: scan for E8 opcodes and
 * adjust their rel32 by the byte position (or by the buffer size for a
 * negative encoded value). */
static void e8_untranslate(unsigned char *out, unsigned long outLen)
{
    unsigned long i = 0;
    long v1 = 0;                       /* byte position of the current E8 */
    long v5 = (long)(outLen < 0x40000000UL ? outLen : 0x40000000UL);
    long v7 = v5;

    while (v7 > 0)
    {
        /* advance to the next 0xE8 opcode */
        while (v7 > 0 && i + 1 < outLen && out[i] != 0xE8)
        {
            ++i;
            ++v1;
            --v7;
        }
        if (v7 < 5 || i + 5 > outLen)
            break;
        {
            long v9 = (long)rd32(out + i + 1);
            if (v9 + v1 >= 0 && v5 > v9)
            {
                long nv = (v9 < 0) ? v9 + v5 : v9 - v1;
                out[i + 1] = (unsigned char)(nv & 0xFF);
                out[i + 2] = (unsigned char)((nv >> 8) & 0xFF);
                out[i + 3] = (unsigned char)((nv >> 16) & 0xFF);
                out[i + 4] = (unsigned char)((nv >> 24) & 0xFF);
            }
        }
        v7 -= 5;
        i += 5;
        v1 += 5;
    }
}

static unsigned long rd32(const unsigned char *p);
static unsigned short rd16(const unsigned char *p);

/* ---------- PA30 PE seed transform ---------------------------------------- */
/* RiftTable::Map: add the rift of the nearest entry whose left <= rva. */
static __int64 rift_map(const RIFTENTRY *t, unsigned n, __int64 x)
{
    unsigned i;
    __int64 rift = 0;
    for (i = 0; i < n; ++i)
    {
        if (t[i].left <= x)
            rift = t[i].right - t[i].left;
        else
            break;
    }
    return x + rift;
}

static int rift_cmp(const void *a, const void *b)
{
    const RIFTENTRY *x = (const RIFTENTRY *)a;
    const RIFTENTRY *y = (const RIFTENTRY *)b;
    if (x->left < y->left) return -1;
    if (x->left > y->left) return 1;
    return 0;
}

/* Invert a RiftTable: Map^-1(y) = y - (right-left) = y + (left-right).
 * Faithful port of compo::RiftTable::Reverse (msdelta.dll.c:23595-23950)
 * with a2 = a3 = 0: it sweeps the input, emitting the swapped entries plus
 * extra (x, x - rift) entries for breakpoints that fall inside a rift
 * interval, keeping a pending-entry work list in `temp`. */
static unsigned rift_reverse(const RIFTENTRY *a, unsigned an, RIFTENTRY *out)
{
    unsigned temp[4096];            /* 4 dwords per pending entry */
    unsigned on = 0;
    unsigned v13, v14, v16, v18, v22, v24, v27, v28, v32, v34, v38, v41, v43, v47, v48, v51, v63, v65;
    __int64 v19;
    __int64 startPos = 0;

    if (an == 0) return 0;

    if (an == 1)
    {
        out[on].left = startPos;
        out[on].right = startPos + (a[0].right - a[0].left);
        return 1;
    }
    {
        unsigned k;
        int allsame = 1;
        for (k = 1; k < an; ++k)
            if (a[k].left != a[0].left) { allsame = 0; break; }
        if (allsame)
        {
            out[on].left = startPos;
            out[on].right = startPos + (a[0].right - a[0].left);
            return 1;
        }
    }

    memset(temp, 0, sizeof(temp));
    v65 = 0;
    v14 = an;

    v13 = 0;
    do {
        if (a[v13].left > startPos) break;
        ++v13;
    } while (v14 > v13);
    if (v13 == 0) v13 = v14;

    v16 = (v13 < v14) ? 1u : 0u;
    v43 = v13 - 1;
    v48 = v13 - 1;

    for (;;)
    {
        v18 = v16 ? v13 : 0;
        v47 = v18;

        for (;;)
        {
            __int64 delta, cursor, rcursor;
            unsigned v61, v56, v62, v64, v53, v57;

            v19 = a[v48].right - a[v48].left;

            delta = a[v18].left - startPos;
            v56 = (unsigned)delta;
            v61 = (unsigned)((unsigned __int64)delta >> 32);

            cursor = startPos + v19;
            v62 = (unsigned)cursor;
            v64 = (unsigned)((unsigned __int64)cursor >> 32);

            if (cursor != INT64_MIN)
            {
                unsigned __int64 limit = (unsigned __int64)INT64_MIN
                                       - (unsigned __int64)v19
                                       - (unsigned __int64)startPos;
                if ((unsigned __int64)delta > limit)
                {
                    delta = (__int64)limit;
                    v61 = (unsigned)((unsigned __int64)delta >> 32);
                    v56 = (unsigned)delta;
                }
            }
            cursor = ((__int64)v64 << 32) | v62;
            rcursor = cursor + delta;
            v53 = (unsigned)rcursor;
            v57 = (unsigned)((unsigned __int64)rcursor >> 32);

            if (delta != 0)
            {
                unsigned *v49, *v25, *v26;

                v22 = 0;
                v51 = 0;
                if (v65)
                {
                    unsigned *v23 = temp + 2;
                    do {
                        if (!*v23 && v23[1] == 0x80000000u) break;
                        if (*(__int64 *)v23 >= cursor) break;
                        ++v22; v23 += 4;
                    } while (v65 > v22);
                    v51 = v22;
                }
                v63 = v22;
                v24 = v22;
                if (v65 <= v22) goto LABEL_61;

                v49 = temp + 4 * v22;
                v25 = v49;
                do {
                    if ((v53 || v57 != 0x80000000u) &&
                        *(__int64 *)v25 > rcursor) break;
                    ++v24; v25 += 4;
                } while (v65 > v24);
                v26 = v49;
                v63 = v24;
                if (v22 == v24)
                {
LABEL_61:
                    out[on].left = cursor;
                    out[on].right = startPos;
                    ++on;
                }
                else
                {
                    if (cursor >= *(__int64 *)v49)
                    {
                        v62 = v49[0]; v64 = v49[1];
                        cursor = ((__int64)v64 << 32) | v62;
                    }
                    else
                    {
                        out[on].left = cursor;
                        out[on].right = startPos;
                        ++on;
                        v26 = v49;
                    }
                    v27 = v63 - 1;
                    if (v63 - 1 > v22)
                    {
                        __int64 *v29 = (__int64 *)(v26 + 2);
                        v28 = v27 - v22;
                        do {
                            out[on].left = *v29;
                            out[on].right = *v29 - v19;
                            ++on;
                            v29 += 2;
                            --v28;
                        } while (v28);
                        v22 = v51;
                    }
                    {
                        unsigned v30 = temp[4 * v63 - 2];
                        unsigned v31 = temp[4 * v63 - 1];
                        __int64 tl = ((__int64)v31 << 32) | v30;
                        if ((!v30 && v31 == 0x80000000u) ||
                            ((v53 || v57 != 0x80000000u) && (tl >= rcursor)))
                        {
                            rcursor = tl;
                            v53 = v30; v57 = v31;
                        }
                        else
                        {
                            out[on].left = tl;
                            out[on].right = tl - v19;
                            ++on;
                        }
                    }
                    v24 = v63;
                }

                if (v22 == v24)
                {
                    v32 = v65;
                    if (v65 > v22)
                    {
                        unsigned *v33 = temp + 4 * v65;
                        v34 = v65 - v22;
                        do {
                            unsigned *v35 = v33;
                            v33 -= 4;
                            *v35++ = *v33;
                            *v35++ = v33[1];
                            *v35 = v33[2];
                            v35[1] = v33[3];
                            --v34;
                        } while (v34);
                        v24 = v63;
                        goto LABEL_73;
                    }
                }
                else
                {
                    if (v22 + 1 == v24)
                    {
LABEL_73:
                        v32 = v65;
                        goto LABEL_74;
                    }
                    v32 = v65;
                    if (v24 < v65)
                    {
                        unsigned *v36 = temp + 4 * v24;
                        unsigned *v37 = temp + 4 * v22 + 4;
                        v38 = v65 - v24;
                        do {
                            unsigned *v39 = v36;
                            unsigned *v40 = v37;
                            v36 += 4; v37 += 4;
                            *v40 = *v39++;
                            *++v40 = *v39++;
                            *++v40 = *v39;
                            v40[1] = v39[1];
                            --v38;
                        } while (v38);
                        v22 = v51;
                        v24 = v63;
                        goto LABEL_73;
                    }
                }
LABEL_74:
                v18 = v47;
                v41 = 2 * v22;
                v65 = (v22 - v24) + 1 + v32;
                temp[2 * v41] = v62;
                temp[2 * v41 + 1] = v64;
                temp[2 * v41 + 2] = v53;
                temp[2 * v41 + 3] = v57;
            }

            {
                __int64 newStart = (((__int64)v61 << 32) | v56) + startPos;
                startPos = newStart;
                if (newStart == a[v18].left) break;
            }
        }

        v48 = v18;
        if (v43 != v18)
        {
            v13 = v18 + 1;
            v16 = ((v18 + 1) < an) ? 1u : 0u;
            continue;
        }
        break;
    }
    return on;
}

/* RiftTable::GetRift: return the rift of the entry with the largest
 * left <= pos, and store the successor's left - 1 in *end (or INT64_MAX
 * for the last entry).  When pos precedes every entry the DLL returns
 * the last entry's rift and *end = t[0].left - 1. */
static __int64 rift_get_rift(const RIFTENTRY *t, unsigned n, __int64 pos,
                             __int64 *end)
{
    unsigned lo, hi, idx;
    if (!n)
    {
        *end = INT64_MAX;
        return 0;
    }
    if (pos >= t[0].left)
    {
        lo = 0;
        hi = n - 1;
        while (lo < hi)
        {
            unsigned mid = (lo + hi + 1) >> 1;
            if (t[mid].left <= pos) lo = mid;
            else hi = mid - 1;
        }
        idx = lo;
        *end = (n - idx > 1) ? t[idx + 1].left - 1 : INT64_MAX;
        return t[idx].right - t[idx].left;
    }
    *end = t[0].left - 1;
    return t[n - 1].right - t[n - 1].left;
}

/* Compose two RiftTables: result(x) = b(a(x)).
 * Faithful port of compo::RiftTable::Multiply (msdelta.dll.c:23952-24157).
 * The sentinel block emits the entries below a[0].left; the main loop walks
 * each A interval, emitting the mapped breakpoint and every B breakpoint that
 * falls inside it. */
static unsigned rift_multiply(const RIFTENTRY *a, unsigned an,
                              const RIFTENTRY *b, unsigned bn,
                              RIFTENTRY *out)
{
    unsigned on = 0, i;

    if (!an) { if (bn) memcpy(out, b, (size_t)bn * sizeof(*out)); return bn; }
    if (!bn) { memcpy(out, a, (size_t)an * sizeof(*out)); return an; }

    /* Sentinel block (msdelta.dll.c:24042-24087 / asm 0x1002F38C-0x1002F46C):
     * emits the entries below a[0].left by walking B's breakpoints. */
    if (a[0].left != INT64_MIN)
    {
        __int64 lastRift = a[an - 1].right - a[an - 1].left;
        __int64 x = lastRift + INT64_MIN;
        __int64 endB, rift, acc, d, endA = a[0].left - 1;

        rift = rift_get_rift(b, bn, x, &endB);
        out[on].left = INT64_MIN;
        out[on].right = x + rift;
        ++on;
        acc = INT64_MIN;
        d = endB - x;
        if ((unsigned __int64)(endA + INT64_MIN) > (unsigned __int64)d)
        {
            while (on < 400)
            {
                __int64 pos;
                acc += d + 1;
                pos = endB + 1;
                rift = rift_get_rift(b, bn, pos, &endB);
                out[on].left = acc;
                out[on].right = pos + rift;
                ++on;
                d = endB - pos;
                if ((unsigned __int64)(endA - acc) <= (unsigned __int64)d)
                    break;
            }
        }
    }

    /* Main loop (msdelta.dll.c:24088-24151). */
    for (i = 0; i < an; ++i)
    {
        __int64 left_i = a[i].left, right_i = a[i].right, end_i;
        __int64 endB, rift, prevLeft, prevPos, prevEnd;

        if (i + 1 >= an)
            end_i = 0x7FFFFFFFFFFFFFFF;
        else if (a[i + 1].left == left_i)
            continue;                   /* duplicate-left entry is skipped */
        else
            end_i = a[i + 1].left - 1;

        rift = rift_get_rift(b, bn, right_i, &endB);
        out[on].left = left_i;
        out[on].right = right_i + rift;
        ++on;

        prevLeft = left_i;
        prevPos = right_i;
        prevEnd = endB;
        while (on < 400 &&
               (unsigned __int64)(end_i - prevLeft) >
               (unsigned __int64)(prevEnd - prevPos))
        {
            __int64 nl = prevLeft + (prevEnd - prevPos) + 1;
            __int64 np = prevEnd + 1;
            __int64 ne, r2 = rift_get_rift(b, bn, np, &ne);
            out[on].left = nl;
            out[on].right = np + r2;
            ++on;
            prevLeft = nl;
            prevPos = np;
            prevEnd = ne;
        }
    }

    qsort(out, on, sizeof(*out), rift_cmp);
    {
        unsigned k = 0;
        for (i = 1; i < on; ++i)
        {
            if (out[i].left == out[k].left) out[k].right = out[i].right;
            else out[++k] = out[i];
        }
        on = k + 1;
    }
    return on;
}

static unsigned long pa30_map_rva(const RIFTENTRY *rt, unsigned rn,
                                  unsigned long rva)
{
    unsigned i;
    long rift = 0;
    for (i = 0; i < rn; ++i)
    {
        if (rt[i].left <= (__int64)rva)
            rift = (long)(rt[i].right - rt[i].left);
        else
            break;
    }
    return (unsigned long)((long)rva + rift);
}

/* PE relocations list every VA-bearing field.  Build a per-byte mask of
 * type-3 (HIGHLOW) and type-10 (DIR64) relocation sites so the inferred
 * pointer rewrite touches only those dwords, not incidental 4-byte windows
 * that happen to look like an image VA. */
static void pa30_reloc_mask(const unsigned char *buf, unsigned long len,
                            unsigned char *mask)
{
    unsigned long pe, opt, rrva, rsize, off, end;
    if (len < 0x40) return;
    pe = rd32(buf + 0x3C);
    if (pe + 24 > len || memcmp(buf + pe, "PE\0\0", 4)) return;
    opt = pe + 24;
    if (rd16(buf + opt) != 0x10B || opt + 0x90 > len) return;
    rrva = rd32(buf + opt + 0x60 + 5 * 8);
    rsize = rd32(buf + opt + 0x60 + 5 * 8 + 4);
    if (!rrva || !rsize) return;
    off = pa30_rva_off(buf, len, rrva);
    if (off == 0xFFFFFFFFUL || off + rsize > len) return;
    end = off + rsize;
    while (off + 8 <= end)
    {
        unsigned long page = rd32(buf + off);
        unsigned long bsize = rd32(buf + off + 4);
        unsigned long e;
        if (bsize < 8 || bsize > end - off) break;
        for (e = 8; e + 2 <= bsize; e += 2)
        {
            unsigned long entry = rd16(buf + off + e);
            unsigned long type = entry >> 12;
            unsigned long roff = entry & 0xFFF;
            if (type == 3 || type == 10 || type == 1 || type == 2 || type == 4)
            {
                unsigned long fo = pa30_rva_off(buf, len, page + roff);
                unsigned long k, width = (type == 3) ? 4 :
                                         (type == 10) ? 8 : 2;
                if (fo != 0xFFFFFFFFUL && fo + width <= len)
                    for (k = 0; k < width; ++k)
                        mask[fo + k] |= 0x03U;   /* handled + skip in scan */
            }
            if (type == 4) ++e;
        }
        off += bsize;
    }

    /* RiftTransformResource marks every resource byte as handled; the
     * relative-call/jump passes skip targets with this hint bit set. */
    {
        unsigned long rr = rd32(buf + opt + 0x60 + 2 * 8);
        unsigned long rsz = rd32(buf + opt + 0x60 + 2 * 8 + 4);
        unsigned long nsec = rd16(buf + pe + 6);
        unsigned long sh = opt + rd16(buf + pe + 20);
        unsigned long s;
        if (rr && rsz)
            for (s = 0; s < nsec && sh + 40 * s + 40 <= len; ++s)
            {
                unsigned long o = sh + 40 * s;
                unsigned long va = rd32(buf + o + 12);
                unsigned long vs = rd32(buf + o + 8);
                unsigned long raw = rd32(buf + o + 20);
                unsigned long rs = rd32(buf + o + 16);
                if (rr >= va && rr < va + vs)
                {
                    unsigned long n = rs;
                    if (n > len - raw) n = len - raw;
                    if (raw < len)
                        memset(mask + raw, 0x01, (size_t)n);
                    break;
                }
            }
    }
}

/* Mirrors the DLL's RiftTransformRelocationsI386Component::
 * TransformInferredRelocations: scan from SizeOfHeaders, rewriting any
 * aligned dword that is a VA inside the old image to
 * MapRva(va - oldBase) + newBase.  A packed hint array prevents overlapping
 * hits from being rewritten twice. */
static void pa30_transform_pointers(unsigned char *buf, unsigned long len,
                                    const RIFTENTRY *rt, unsigned rn,
                                    unsigned long oldBase,
                                    unsigned long newBase,
                                    unsigned long sizeOfImage,
                                    unsigned long sizeOfHeaders,
                                    const unsigned char *relocMask)
{
    unsigned char *hint;
    unsigned long pos;
    unsigned long end = len >= 4 ? len - 4 : 0;

    if (!sizeOfHeaders || sizeOfHeaders >= end || !sizeOfImage)
        return;
    hint = (unsigned char *)calloc((size_t)len, 1);
    if (!hint) return;
    if (relocMask) memcpy(hint, relocMask, len);
    pos = sizeOfHeaders;
    while (pos < end)
    {
        unsigned long v = rd32(buf + pos);
        /* The DLL's hint map marks instruction operands as already handled;
         * skip dwords immediately following common immediate-carrying x86
         * opcodes so their operands are not mistaken for pointers. */
        if (pos && getenv("PA30_SKIPIMM") &&
            ((buf[pos - 1] >= 0xB8 && buf[pos - 1] <= 0xBF) ||
             buf[pos - 1] == 0x68 || buf[pos - 1] == 0xE8 ||
             buf[pos - 1] == 0xE9 || buf[pos - 1] == 0x05 ||
             buf[pos - 1] == 0x0D || buf[pos - 1] == 0x15 ||
             buf[pos - 1] == 0x1D || buf[pos - 1] == 0x25 ||
             buf[pos - 1] == 0x2D || buf[pos - 1] == 0x35 ||
             buf[pos - 1] == 0x3D))
        {
            ++pos;
            continue;
        }
        if (v >= oldBase && v < oldBase + sizeOfImage)
        {
            unsigned k;
            unsigned long nv;
            if (((hint[pos] | hint[pos + 1] | hint[pos + 2] | hint[pos + 3])
                 & 0x02) == 0)
            {
                nv = pa30_map_rva(rt, rn, v - oldBase) + newBase;
                for (k = 0; k < 4; ++k)
                {
                    buf[pos + k] = (unsigned char)(nv >> (8 * k));
                    hint[pos + k] |= 0x01;
                }
            }
            pos += 4;
        }
        else
            pos += 1;
    }
    free(hint);
}

/* MarkNonExe: the DLL adds IMAGE_SCN_MEM_WRITE to the section that holds
 * the import directory, so the rewritten import RVAs can be stored. */
static void pa30_mark_import_section(unsigned char *buf, unsigned long len)
{
    unsigned long lfa, opt, nrva, imp, nsec, sh, s;
    if (len < 0x40) return;
    lfa = rd32(buf + 0x3C);
    if (lfa + 24 > len || memcmp(buf + lfa, "PE\0\0", 4)) return;
    nsec = rd16(buf + lfa + 6);
    opt = lfa + 24;
    if (rd16(buf + opt) != 0x10B || opt + 0x50 > len) return;
    imp = rd32(buf + opt + 0x60 + 8);   /* Import Table RVA (data dir 1) */
    if (getenv("PA30_DEBUG")) fprintf(stderr, "IMPORT RVA=%08lX\n", imp);
    if (!imp) return;
    nrva = rd32(buf + opt + 0x38);      /* SizeOfImage */
    sh = opt + rd16(buf + lfa + 20);
    for (s = 0; s < nsec; ++s)
    {
        unsigned long o = sh + 40 * s;
        unsigned long va, vs, rs, ch;
        if (o + 40 > len) break;
        va = rd32(buf + o + 12);
        vs = rd32(buf + o + 8);
        rs = rd32(buf + o + 16);
        if (imp >= va && imp < va + (vs ? vs : rs))
        {
            ch = rd32(buf + o + 36);
            if (!(ch & 0x80000000UL))
            {
                ch |= 0x80000000UL;
                buf[o + 36] = (unsigned char)(ch & 0xFF);
                buf[o + 37] = (unsigned char)((ch >> 8) & 0xFF);
                buf[o + 38] = (unsigned char)((ch >> 16) & 0xFF);
                buf[o + 39] = (unsigned char)((ch >> 24) & 0xFF);
            }
            break;
        }
    }
    (void)nrva;
}

/* Rewrite the actual import directory structures (descriptor fields and
 * thunk entries) through MapRva, leaving unrelated data alone. */
static unsigned long pa30_rva_off(const unsigned char *b, unsigned long len,
                                  unsigned long rva)
{
    unsigned long pe, opt, sh, nsec, s;
    if (len < 0x40) return 0xFFFFFFFFUL;
    pe = rd32(b + 0x3C);
    if (pe + 24 > len || memcmp(b + pe, "PE\0\0", 4)) return 0xFFFFFFFFUL;
    nsec = rd16(b + pe + 6);
    opt = pe + 24;
    sh = opt + rd16(b + pe + 20);
    for (s = 0; s < nsec && sh + 40 * s + 40 <= len; ++s)
    {
        unsigned long o = sh + 40 * s;
        unsigned long va = rd32(b + o + 12);
        unsigned long vs = rd32(b + o + 8);
        unsigned long rs = rd32(b + o + 16);
        unsigned long raw = rd32(b + o + 20);
        unsigned long span = vs ? vs : rs;
        if (rva >= va && rva < va + span)
            return raw + (rva - va);
    }
    return 0xFFFFFFFFUL;
}

static void pa30_set_u32(unsigned char *b, unsigned long off, unsigned long v)
{
    b[off] = (unsigned char)(v & 0xFF);
    b[off + 1] = (unsigned char)((v >> 8) & 0xFF);
    b[off + 2] = (unsigned char)((v >> 16) & 0xFF);
    b[off + 3] = (unsigned char)((v >> 24) & 0xFF);
}

static void pa30_rewrite_imports(unsigned char *buf, unsigned long len,
                                 const RIFTENTRY *rt, unsigned rn)
{
    unsigned long pe, opt, imp, off, d;
    if (len < 0x40) return;
    pe = rd32(buf + 0x3C);
    if (pe + 24 > len || memcmp(buf + pe, "PE\0\0", 4)) return;
    opt = pe + 24;
    if (rd16(buf + opt) != 0x10B || opt + 0x70 > len) return;
    imp = rd32(buf + opt + 0x60 + 8);
    if (!imp) return;
    off = pa30_rva_off(buf, len, imp);
    if (off == 0xFFFFFFFFUL) return;
    for (d = 0; d < 256 && off + 20 * (d + 1) <= len; ++d)
    {
        unsigned long o = off + 20 * d;
        unsigned long oft = rd32(buf + o);
        unsigned long name = rd32(buf + o + 12);
        unsigned long ft = rd32(buf + o + 16);
        unsigned long k;
        if (!oft && !name && !ft) break;
        if (oft) pa30_set_u32(buf, o, pa30_map_rva(rt, rn, (long)oft));
        if (name) pa30_set_u32(buf, o + 12, pa30_map_rva(rt, rn, (long)name));
        if (ft) pa30_set_u32(buf, o + 16, pa30_map_rva(rt, rn, (long)ft));
        for (k = 0; k < 2; ++k)
        {
            unsigned long t = k ? ft : oft;
            unsigned long to = t ? pa30_rva_off(buf, len, t) : 0xFFFFFFFFUL;
            unsigned i;
            if (to == 0xFFFFFFFFUL) continue;
            for (i = 0; i < 4096 && to + 4 * (i + 1) <= len; ++i)
            {
                unsigned long v = rd32(buf + to + 4 * i);
                if (!v) break;
                if (!(v & 0x80000000UL))
                    pa30_set_u32(buf, to + 4 * i,
                                 pa30_map_rva(rt, rn, (long)v));
            }
        }
    }
}

/* Blind RVA scan (kept for comparison via PA30_BLIND). */
static void pa30_transform_rvas(unsigned char *buf, unsigned long len,
                                const RIFTENTRY *rt, unsigned rn,
                                unsigned long sizeOfImage,
                                unsigned long sizeOfHeaders)
{
    unsigned long pos, start = sizeOfHeaders;
    unsigned long end = len >= 4 ? len - 4 : 0;
    /* Only the section that holds the import directory gets its RVAs
     * rewritten; arbitrary .text words that look like RVAs must be left
     * alone. */
    {
        unsigned long lfa, opt, imp, nsec, sh, s;
        if (len >= 0x40)
        {
            lfa = rd32(buf + 0x3C);
            if (lfa + 24 <= len && !memcmp(buf + lfa, "PE\0\0", 4))
            {
                nsec = rd16(buf + lfa + 6);
                opt = lfa + 24;
                imp = rd32(buf + opt + 0x60 + 8);
                sh = opt + rd16(buf + lfa + 20);
                for (s = 0; s < nsec; ++s)
                {
                    unsigned long o = sh + 40 * s;
                    if (o + 40 > len) break;
                    {
                        unsigned long va = rd32(buf + o + 12);
                        unsigned long vs = rd32(buf + o + 8);
                        unsigned long raw = rd32(buf + o + 20);
                        unsigned long rs = rd32(buf + o + 16);
                        if (imp >= va && imp < va + (vs ? vs : rs))
                        {
                            start = raw;
                            end = raw + rs;
                            if (end > len) end = len;
                            break;
                        }
                    }
                }
            }
        }
    }
    for (pos = start; pos + 4 <= end; pos += 4)
    {
        unsigned long v = rd32(buf + pos);
        unsigned long nv;
        unsigned k;
        if (v < sizeOfHeaders || v >= sizeOfImage)
            continue;
        nv = pa30_map_rva(rt, rn, (long)v);
        if (nv == v) continue;
        for (k = 0; k < 4; ++k)
            buf[pos + k] = (unsigned char)(nv >> (8 * k));
    }
}

/* The DLL's RiftTransformRelocations component rebuilds the .reloc section:
 * every entry's RVA is mapped through the (reduced) RiftTable, entries are
 * sorted by mapped RVA, and blocks are regrouped by mapped page.  Without
 * this the transformed seed keeps the source RVAs and the decoder copies
 * stale bytes from those addresses. */
typedef struct tagRELOC
{
    unsigned long rva;
    unsigned short type;
    unsigned short extra;
} RELOC;

static int cmp_reloc(const void *x, const void *y)
{
    const RELOC *a = (const RELOC *)x, *b = (const RELOC *)y;
    if (a->rva < b->rva) return -1;
    if (a->rva > b->rva) return 1;
    return 0;
}

/* RiftTransformResource: resource-directory OffsetToData fields (high bit
 * set) are relative to the resource section RVA and must be rebased through
 * the same RiftTable; only the low 12 bits of the mapped RVA are kept. */
/* RiftTransformRelativeCallsI386: rewrite the rel32 of E8 CALL instructions
 * to the mapped target RVA (msdelta.dll.c:36936-37055).  Instructions whose
 * bytes are already hinted (relocation sites) are left alone. */
static void pa30_transform_relcalls(unsigned char *buf, unsigned long len,
                                    const RIFTENTRY *rt, unsigned rn,
                                    const unsigned char *hint,
                                    unsigned long sizeOfImage)
{
    unsigned long pe, opt, sh, nsec, s;
    if (len < 0x40) return;
    pe = rd32(buf + 0x3C);
    if (pe + 24 > len || memcmp(buf + pe, "PE\0\0", 4)) return;
    opt = pe + 24;
    if (rd16(buf + opt) != 0x10B) return;
    nsec = rd16(buf + pe + 6);
    sh = opt + rd16(buf + pe + 20);
    for (s = 0; s < nsec && sh + 40 * s + 40 <= len; ++s)
    {
        unsigned long o = sh + 40 * s;
        unsigned long flags = rd32(buf + o + 36);
        unsigned long vs = rd32(buf + o + 8);
        unsigned long rs = rd32(buf + o + 16);
        unsigned long raw = rd32(buf + o + 20);
        unsigned long va = rd32(buf + o + 12);
        unsigned long span, p;
        if (!(flags & 0x20000000UL)) continue;
        if (vs > rs) vs = rs;
        if (vs < 5 || raw + vs > len) continue;
        span = raw + vs;
        for (p = raw; p + 5 <= span; ++p)
        {
            long rel, newrel, siteRVA, targetRVA, mappedSite, mappedTarget;
            unsigned long to;
            if (buf[p] != 0xE8) continue;
            /* Skip a 0xE8 that is actually the disp8 of 8B/8D 45 xx. */
            if (p >= raw + 2 && (buf[p - 2] == 0x8B || buf[p - 2] == 0x8D) &&
                buf[p - 1] == 0x45)
                continue;
            if (hint && (hint[p] | hint[p + 1] | hint[p + 2] |
                         hint[p + 3] | hint[p + 4]) & 0x01)
                continue;
            rel = (long)rd32(buf + p + 1);
            siteRVA = (long)(va + (p - raw) + 5);
            targetRVA = siteRVA + rel;
            if (targetRVA < 0 || (unsigned long)targetRVA >= sizeOfImage)
                continue;
            to = pa30_rva_off(buf, len, (unsigned long)targetRVA);
            if (to == 0xFFFFFFFFUL || to >= len ||
                (hint && (hint[to] & 0x01))) continue;
            mappedSite = (long)pa30_map_rva(rt, rn, (unsigned long)siteRVA);
            mappedTarget = (long)pa30_map_rva(rt, rn,
                                              (unsigned long)targetRVA);
            newrel = mappedTarget - mappedSite;
            if (newrel != rel)
                pa30_set_u32(buf, p + 1, (unsigned long)newrel);
            p += 4;
        }
    }
}

/* RiftTransformExports: map the RVAs in IMAGE_EXPORT_DIRECTORY (Name,
 * AddressOfFunctions/AddressOfNames table pointers and their entries). */
static void pa30_transform_exports(unsigned char *buf, unsigned long len,
                                   const RIFTENTRY *rt, unsigned rn)
{
    unsigned long pe, opt, er, es, off, i;
    if (len < 0x40) return;
    pe = rd32(buf + 0x3C);
    if (pe + 24 > len || memcmp(buf + pe, "PE\0\0", 4)) return;
    opt = pe + 24;
    if (rd16(buf + opt) != 0x10B || opt + 0x90 > len) return;
    er = rd32(buf + opt + 0x60);
    es = rd32(buf + opt + 0x60 + 4);
    if (!er || es < 40) return;
    off = pa30_rva_off(buf, len, er);
    if (off == 0xFFFFFFFFUL || off + 40 > len) return;
    {
        unsigned long nf = rd32(buf + off + 20);
        unsigned long nn = rd32(buf + off + 24);
        unsigned long af = rd32(buf + off + 28);
        unsigned long an = rd32(buf + off + 32);
        unsigned long fo, no;
        for (i = 0; i < 40; i += 4)
        {
            unsigned long v = rd32(buf + off + i);
            if (!v || (i != 12 && i != 28 && i != 32 && i != 36)) continue;
            pa30_set_u32(buf, off + i,
                         (unsigned long)pa30_map_rva(rt, rn, (long)v));
        }
        if (nf && af)
        {
            fo = pa30_rva_off(buf, len, af);
            for (i = 0; i < nf && fo != 0xFFFFFFFFUL &&
                        fo + 4 * (i + 1) <= len; ++i)
            {
                unsigned long v = rd32(buf + fo + 4 * i);
                if (v)
                    pa30_set_u32(buf, fo + 4 * i,
                                 (unsigned long)pa30_map_rva(rt, rn, (long)v));
            }
        }
        if (nn && an)
        {
            no = pa30_rva_off(buf, len, an);
            for (i = 0; i < nn && no != 0xFFFFFFFFUL &&
                        no + 4 * (i + 1) <= len; ++i)
            {
                unsigned long v = rd32(buf + no + 4 * i);
                if (v)
                    pa30_set_u32(buf, no + 4 * i,
                                 (unsigned long)pa30_map_rva(rt, rn, (long)v));
            }
        }
    }
}

/* RiftTransformRelativeJmpsI386: map the target of E9 near jumps
 * (msdelta.dll.c:48542-48692). */
static void pa30_transform_reljmps(unsigned char *buf, unsigned long len,
                                   const RIFTENTRY *rt, unsigned rn,
                                   const unsigned char *hint,
                                   unsigned long sizeOfImage)
{
    unsigned long pe, opt, sh, nsec, s;
    if (len < 0x40) return;
    pe = rd32(buf + 0x3C);
    if (pe + 24 > len || memcmp(buf + pe, "PE\0\0", 4)) return;
    opt = pe + 24;
    if (rd16(buf + opt) != 0x10B) return;
    nsec = rd16(buf + pe + 6);
    sh = opt + rd16(buf + pe + 20);
    for (s = 0; s < nsec && sh + 40 * s + 40 <= len; ++s)
    {
        unsigned long o = sh + 40 * s;
        unsigned long flags = rd32(buf + o + 36);
        unsigned long vs = rd32(buf + o + 8);
        unsigned long rs = rd32(buf + o + 16);
        unsigned long raw = rd32(buf + o + 20);
        unsigned long va = rd32(buf + o + 12);
        unsigned long span, p;
        if (!(flags & 0x20000000UL)) continue;
        if (vs > rs) vs = rs;
        if (vs < 5 || raw + vs > len) continue;
        span = raw + vs;
        for (p = raw; p + 5 <= span; ++p)
        {
            long rel, newrel, siteRVA, targetRVA, mappedSite, mappedTarget;
            unsigned long to, opLen = 5, hintAt = p;
            /* Skip bytes that are really a ModRM disp8 of a [EBP+disp8]
             * instruction (8B/8D 45 xx); the byte scan otherwise mistakes
             * the displacement 0xE8/0xE9 for an opcode. */
            if (p >= raw + 2 && (buf[p - 2] == 0x8B || buf[p - 2] == 0x8D) &&
                buf[p - 1] == 0x45)
                continue;
            if (buf[p] == 0x0F && p + 6 <= span &&
                (buf[p + 1] & 0xF0) == 0x80)
            {
                opLen = 6; hintAt = p + 1;
            }
            else if (buf[p] != 0xE9)
                continue;
            if (hint && (hint[hintAt] | hint[hintAt + 1] |
                         hint[hintAt + 2] | hint[hintAt + 3] |
                         hint[hintAt + 4]) & 0x01)
                continue;
            rel = (long)rd32(buf + hintAt + 1);
            siteRVA = (long)(va + (p - raw) + opLen);
            targetRVA = siteRVA + rel;
            if (targetRVA < 0 || (unsigned long)targetRVA >= sizeOfImage)
                continue;
            to = pa30_rva_off(buf, len, (unsigned long)targetRVA);
            if (to == 0xFFFFFFFFUL || to >= len ||
                (hint && (hint[to] & 0x01))) continue;
            mappedSite = (long)pa30_map_rva(rt, rn, (unsigned long)siteRVA);
            mappedTarget = (long)pa30_map_rva(rt, rn,
                                              (unsigned long)targetRVA);
            newrel = mappedTarget - mappedSite;
            if (newrel != rel)
                pa30_set_u32(buf, hintAt + 1, (unsigned long)newrel);
            p += opLen - 1;
        }
    }
}

static void pa30_res_walk(unsigned char *buf, unsigned long base,
                          unsigned long rsize, unsigned long rrva,
                          const RIFTENTRY *rt, unsigned rn,
                          unsigned long relOff, int depth)
{
    unsigned long d = base + relOff, n, i, mbase;
    if (depth > 16 || d + 16 > base + rsize) return;
    mbase = (unsigned long)pa30_map_rva(rt, rn, (long)rrva);
    n = (unsigned long)rd16(buf + d + 12) + rd16(buf + d + 14);
    if (n > 4096) return;
    for (i = 0; i < n; ++i)
    {
        unsigned long e = d + 16 + 8 * i;
        unsigned long name, target;
        if (e + 8 > base + rsize) break;
        name = rd32(buf + e);
        target = rd32(buf + e + 4);
        if (name & 0x80000000UL)
        {
            unsigned long so = name & 0x7FFFFFFFUL;
            unsigned long nr = (unsigned long)pa30_map_rva(rt, rn,
                                            (long)(rrva + so));
            pa30_set_u32(buf, e, 0x80000000UL |
                         (nr >= mbase ? nr - mbase : 0));
        }
        if (target & 0x80000000UL)
        {
            unsigned long sub = target & 0x7FFFFFFFUL;
            unsigned long nr = (unsigned long)pa30_map_rva(rt, rn,
                                            (long)(rrva + sub));
            pa30_set_u32(buf, e + 4,
                         0x80000000UL | (nr >= mbase ? nr - mbase : 0));
            pa30_res_walk(buf, base, rsize, rrva, rt, rn, sub, depth + 1);
        }
        else if (target < rsize)
        {
            unsigned long de = base + target;
            if (de + 4 <= base + rsize)
            {
                unsigned long v = rd32(buf + de);
                /* RiftTransformResourceRecursive maps data-entry OffsetToData
                 * by MapRva(resourceBase + offset) - MapRva(resourceBase). */
                unsigned long nr = (unsigned long)pa30_map_rva(rt, rn,
                                                (long)(rrva + v));
                pa30_set_u32(buf, de,
                             nr >= mbase ? nr - mbase : 0);
            }
        }
    }
}

static void pa30_transform_resources(unsigned char *buf, unsigned long len,
                                     const RIFTENTRY *rt, unsigned rn)
{
    unsigned long pe, opt, rrva, rsize, off;
    if (len < 0x40) return;
    pe = rd32(buf + 0x3C);
    if (pe + 24 > len || memcmp(buf + pe, "PE\0\0", 4)) return;
    opt = pe + 24;
    if (rd16(buf + opt) != 0x10B || opt + 0x90 > len) return;
    rrva = rd32(buf + opt + 0x60 + 2 * 8);      /* Resource directory */
    rsize = rd32(buf + opt + 0x60 + 2 * 8 + 4);
    if (!rrva || !rsize) return;
    off = pa30_rva_off(buf, len, rrva);
    if (off == 0xFFFFFFFFUL || off + rsize > len) return;
    pa30_res_walk(buf, off, rsize, rrva, rt, rn, 0, 0);
}

static void pa30_transform_relocs(unsigned char *buf, unsigned long len,
                                  const RIFTENTRY *rt, unsigned rn,
                                  unsigned long oldBase,
                                  unsigned long newBase,
                                  unsigned long sizeOfImage)
{
    unsigned long pe, opt, rrva, rsize, off, end, n = 0, i, w, cap = 0;
    RELOC *rel;

    if (len < 0x40) return;
    pe = rd32(buf + 0x3C);
    if (pe + 24 > len || memcmp(buf + pe, "PE\0\0", 4)) return;
    opt = pe + 24;
    if (rd16(buf + opt) != 0x10B || opt + 0x90 > len) return;
    rrva = rd32(buf + opt + 0x60 + 5 * 8);      /* Base Relocation Table */
    rsize = rd32(buf + opt + 0x60 + 5 * 8 + 4);
    if (!rrva || !rsize) return;
    off = pa30_rva_off(buf, len, rrva);
    if (off == 0xFFFFFFFFUL || off + rsize > len) return;
    end = off + rsize;
    /* The rebuild may extend past the directory size into the section's
     * raw padding; the DLL bounds it by the section, not the directory. */
    {
        unsigned long nsec = rd16(buf + pe + 6);
        unsigned long sh = opt + rd16(buf + pe + 20);
        unsigned long s;
        for (s = 0; s < nsec && sh + 40 * s + 40 <= len; ++s)
        {
            unsigned long o = sh + 40 * s;
            unsigned long va = rd32(buf + o + 12);
            unsigned long vs = rd32(buf + o + 8);
            unsigned long raw = rd32(buf + o + 20);
            unsigned long secEnd = raw + rd32(buf + o + 16);
            if (rrva >= va && rrva < va + vs)
            {
                if (secEnd > len) secEnd = len;
                if (secEnd > end) end = secEnd;
                break;
            }
        }
    }

    /* Count entries first: large PEs can have tens of thousands of them. */
    {
        unsigned long o = off;
        while (o + 8 <= end)
        {
            unsigned long bs = rd32(buf + o + 4);
            if (bs < 8 || bs > end - o) break;
            cap += (bs - 8) / 2;
            o += bs;
        }
    }
    if (!cap) return;
    rel = (RELOC *)malloc((size_t)cap * sizeof(*rel));
    if (!rel) return;

    while (off + 8 <= end)
    {
        unsigned long page = rd32(buf + off);
        unsigned long bsize = rd32(buf + off + 4);
        unsigned long e;
        if (bsize < 8 || bsize > end - off) break;
        for (e = 8; e + 2 <= bsize; e += 2)
        {
            unsigned long entry = rd16(buf + off + e);
            unsigned long type = entry >> 12;
            unsigned long roff = entry & 0xFFF;
            if (!type) continue;
            /* The DLL's ReadRelocationEntries rebases the VA stored at the
             * relocation site itself (msdelta.dll.c:35375). */
            {
                unsigned long fo = pa30_rva_off(buf, len, page + roff);
                if (fo != 0xFFFFFFFFUL && fo + 4 <= len)
                {
                    unsigned long v = rd32(buf + fo);
                    if (v >= oldBase && v < oldBase + sizeOfImage)
                        pa30_set_u32(buf, fo,
                            (unsigned long)pa30_map_rva(rt, rn,
                                (long)(v - oldBase)) + newBase);
                }
            }
            rel[n].rva = (unsigned long)pa30_map_rva(rt, rn,
                                                     (long)(page + roff));
            rel[n].type = (unsigned short)type;
            rel[n].extra = (type == 4 && e + 4 <= bsize)
                         ? rd16(buf + off + e + 2) : 0;
            if (type == 4) ++e;
            ++n;
        }
        off += bsize;
    }
    if (!n) { free(rel); return; }
    qsort(rel, n, sizeof(rel[0]), cmp_reloc);

    off = pa30_rva_off(buf, len, rrva);
    w = off;
    i = 0;
    while (i < n && w + 8 <= end)
    {
        unsigned long page = rel[i].rva & 0xFFFFF000UL;
        unsigned long j = i, k, cnt, bsize, wp, words = 0;
        while (j < n && (rel[j].rva & 0xFFFFF000UL) == page) ++j;
        cnt = j - i;
        for (k = i; k < j; ++k)
            words += (rel[k].type == 4) ? 2 : 1;
        bsize = 8 + 2 * words;
        if (bsize & 2) bsize += 2;
        if (w + bsize > end) break;
        pa30_set_u32(buf, w, page);
        pa30_set_u32(buf, w + 4, bsize);
        wp = w + 8;
        for (k = i; k < j; ++k)
        {
            unsigned long v = (rel[k].rva & 0xFFF) | (rel[k].type << 12);
            buf[wp] = (unsigned char)(v & 0xFF);
            buf[wp + 1] = (unsigned char)(v >> 8);
            wp += 2;
            if (rel[k].type == 4)
            {
                buf[wp] = (unsigned char)(rel[k].extra & 0xFF);
                buf[wp + 1] = (unsigned char)(rel[k].extra >> 8);
                wp += 2;
            }
        }
        if ((wp - w) & 2)
        {
            buf[wp] = 0; buf[wp + 1] = 0;
            wp += 2;
        }
        w = wp;
        i = j;
    }
    free(rel);
}

/* ---------- Decompress ---------------------------------------------------- */
static void compo_partial_dump(const unsigned char *out, unsigned long pos)
{
    const char *p = getenv("PA30_PARTIAL");
    FILE *f;
    if (!p) return;
    f = fopen(p, "wb");
    if (!f) return;
    if (pos) fwrite(out, 1, (size_t)pos, f);
    fclose(f);
}

static int compo_decompress(BITR *br, const COMPFMT *fmt,
                            const unsigned char *src, unsigned long srcLen,
                            const RIFTENTRY *rift, unsigned riftN,
                            unsigned char *out, unsigned long outLen,
                            int e8Translate)
{
    unsigned long pos = 0;
    long hist[3] = { 1, 1, 1 };
    COMPF cf;
    unsigned char lens[872];
    unsigned segIndex = 0;
    int currentSeg = -1;
    int rc;
    unsigned long symLo = 0, symHi = 100000;
    {
        const char *s = getenv("PA30_SYMLO");
        const char *e = getenv("PA30_SYMHI");
        if (s) symLo = strtoul(s, NULL, 0);
        if (e) symHi = strtoul(e, NULL, 0);
    }

    while (pos < outLen)
    {
        SYMBOL sym;
        while (segIndex + 1 < fmt->nSeg &&
               pos >= fmt->boundary[segIndex + 1])
            ++segIndex;
        if ((int)segIndex != currentSeg)
        {
            if (fmt->defaultFormat)
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
        {
            if (getenv("PA30_DEBUG")) fprintf(stderr,
                "DECOMP fail: pos=%lu seg=%u symval=%lu len=%lu bitpos=%lu\n",
                pos, segIndex, sym.value, sym.length, br->bitpos);
            return -1;
        }


        if (getenv("PA30_SYMDBG") && pos >= symLo && pos < symHi)
            fprintf(stderr, "SYM pos=%lu val=%lu len=%lu bitpos=%lu\n",
                    pos, sym.value, sym.length, br->bitpos);
        if (sym.length == 1)
        {
            out[pos++] = (unsigned char)sym.value;
            continue;
        }
        {
            unsigned long len = sym.length;   /* type is the byte count */
            long dist = 0;
            long riftOff = 0;
            long cpos;
            long riftLimit = 0;
            unsigned ri;
            /* The DLL's OffsetRiftTable is keyed by the COMBINED position
             * (srcLen + output position), mapping it to a combined source
             * position.  Pick the entry with the largest left <= cpos. */
            cpos = (long)pos + (long)srcLen;
            /* An empty table means the implicit identity rift: the combined
             * position maps back to the output position (off = -srcLen). */
            riftOff = -(long)srcLen;
            for (ri = 0; ri < riftN; ++ri)
            {
                if (rift[ri].left <= cpos)
                    riftOff = (long)(rift[ri].right - rift[ri].left);
                else
                    break;
            }
            if (sym.value == 0x54000UL && ri < riftN)
                riftLimit = (long)(rift[ri].left - cpos);

            if (sym.value == 0x54000UL)
            {
                unsigned long done = 0;
                unsigned curi;
                long curOff;

                /* InternalProcess stores -rift into the distance history on
                 * a RIFT symbol (msdelta.dll.c:48252,48392); the k<3 history
                 * slots read that value back. */
                dist = -riftOff;
                if (len > outLen - pos)
                    len = outLen - pos;
                /* The DLL's copy loop re-reads the OffsetRiftTable at every
                 * entry boundary (msdelta.dll.c:48253-48311): a single RIFT
                 * symbol may span several entries, each with a different
                 * source mapping.  Freezing the first rift for the whole
                 * copy silently corrupts the bytes past the first boundary. */
                while (done < len)
                {
                    unsigned long j, chunk = len - done;
                    long cpos2 = (long)pos + (long)srcLen + (long)done;
                    long limit, sp;

                    curOff = -(long)srcLen;
                    for (curi = 0; curi < riftN; ++curi)
                    {
                        if (rift[curi].left <= cpos2)
                            curOff = (long)(rift[curi].right - rift[curi].left);
                        else
                            break;
                    }
                    limit = (curi < riftN) ? rift[curi].left - cpos2 : -1;
                    if (limit > 0 && limit < (long)chunk)
                        chunk = (unsigned long)limit;
                    sp = cpos2 + curOff;

                    if (getenv("PA30_SYMDBG") && pos >= symLo && pos < symHi)
                        fprintf(stderr,
                            "RIFT pos=%lu len=%lu done=%lu cpos=%ld ri=%u/%u off=%ld sp=%ld limit=%ld chunk=%lu bitpos=%lu\n",
                            pos, len, done, cpos2, curi, riftN, curOff, sp,
                            limit, chunk, br->bitpos);

                    if (sp < 0 ||
                        (unsigned long)(sp + (long)chunk) > srcLen + pos + done)
                    {
                        if (getenv("PA30_DEBUG")) fprintf(stderr,
                            "DECOMP riftfail: pos=%lu sp=%ld len=%lu riftOff=%ld bitpos=%lu\n",
                            pos + done, sp, chunk, curOff, br->bitpos);
                        compo_partial_dump(out, pos);
                        return -1;
                    }
                    for (j = 0; j < chunk; ++j)
                    {
                        long ap = sp + (long)j;
                        if (ap < (long)srcLen)
                            out[pos + done + j] = src[ap];
                        else
                            out[pos + done + j] = out[ap - (long)srcLen];
                    }
                    done += chunk;
                    if (limit <= 0) break;      /* no further rift boundary */
                }
            }
            else if (sym.value < 0x54000UL)
            {
                /* k<3 raw distances are measured from the rift-mapped
                 * position in the combined window. */
                dist = (long)(sym.value - 172032UL) - riftOff;
                if (getenv("PA30_SYMDBG") && pos < 512)
                    fprintf(stderr,
                        "  DIST pos=%lu raw=%ld riftOff=%ld dist=%ld len=%lu\n",
                        pos, (long)(sym.value - 172032UL), riftOff, dist, len);
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
                if (getenv("PA30_SYMDBG") && (pos == 83697 || pos == 86119))
                {
                    long ap = (long)pos - dist;
                    fprintf(stderr,
                        "MATCHDBG pos=%lu val=%lu len=%lu cpos=%ld off=%ld dist=%ld ap=%ld srcbytes=",
                        sym.value, len, cpos, riftOff, dist, ap);
                    {
                        unsigned k;
                        for (k = 0; k < 4; ++k)
                        {
                            long q = ap + (long)k;
                            fprintf(stderr, "%02X ", q >= 0 ? out[q] :
                                (srcLen + q < (long)srcLen ? src[srcLen + q] : 0));
                        }
                    }
                    fprintf(stderr, "\n");
                }
                if (dist > (long)(pos + srcLen) ||
                    dist < -(long)srcLen)
                {
                    if (getenv("PA30_DEBUG")) fprintf(stderr,
                        "DECOMP distfail: pos=%lu symval=%lu dist=%ld len=%lu bitpos=%lu\n",
                        pos, sym.value, dist, len, br->bitpos);
                    compo_partial_dump(out, pos);
                    return -1;
                }
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
    if (getenv("PA30_DEBUG")) fprintf(stderr,
        "BLOBS preLen=%u patchLen=%u rc=%d bits=%lu\n",
        preLen, patchLen, rc, br.bitpos);
    if (rc != 0)
    {
        free(pre);
        free(patch);
        return -1;
    }
    {
        BITR pbr;
        RIFTENTRY *rt = NULL;
        RIFTENTRY *tmp = NULL;
        unsigned rn = 0;
        unsigned tmpN = 0;
        COMPFMT cf;
        unsigned long peTimeStamp = 0;
        unsigned __int64 peImageBase = 0;
        const unsigned char *decompressSrc = source;
        RIFTENTRY *orift = NULL;
        unsigned oriftN = 0;

        /* The pre blob is bit-packed with the same 3-bit leader.  It holds
         * the target PE info, its RVA map, optional CLI metadata, and the
         * compression RIFT table used by 0x54000 matches. */
        if (preLen > 16)
        {
            BITR pb;
            br_init(&pb, pre, preLen);
            {
                BITR ti = pb;
                unsigned long gp;
                peImageBase = br_read(&ti, 64);
                gp = br_read(&ti, 32);
                peTimeStamp = br_read(&ti, 32);
                if (getenv("PA30_DEBUG")) fprintf(stderr,
                    "PRE img=%016I64x gp=%08lX ts=%08lX\n",
                    peImageBase, gp, peTimeStamp);
            }
            pb.bitpos += 64 + 32 + 32;   /* ImageBase, GlobalPointer, TimeStamp */
            if (getenv("PA30_DEBUG")) fprintf(stderr,
                "PRE targetinfo at bit %lu\n", pb.bitpos);
            if (rift_read(&pb, &tmp, &tmpN) == 0)
            {
                int cliPresent;
                if (getenv("PA30_DEBUG")) fprintf(stderr,
                    "PRE rift1 n=%u at bit %lu\n", tmpN, pb.bitpos);
                cliPresent = (int)br_read(&pb, 1);     /* CliMetadata present */
                if (getenv("PA30_DEBUG")) fprintf(stderr,
                    "PRE cli=%d at bit %lu\n", cliPresent, pb.bitpos);
                if (cliPresent)
                {
                    unsigned __int64 mask;
                    unsigned k;
                    unsigned nset = 0;
                    pb.bitpos += 15 * 32 + 3;
                    mask = (unsigned __int64)br_read(&pb, 32) |
                           ((unsigned __int64)br_read(&pb, 32) << 32);
                    for (k = 0; k < 64; ++k)
                        if ((mask >> k) & 1)
                        {
                            br_skip(&pb, 32);
                            ++nset;
                        }
                    if (getenv("PA30_DEBUG")) fprintf(stderr,
                        "PRE cli mask=%016I64x nset=%u at bit %lu\n",
                        mask, nset, pb.bitpos);
                }
                if (rift_read(&pb, &rt, &rn) == 0 && getenv("PA30_DEBUG"))
                {
                    unsigned qi;
                    fprintf(stderr, "PRE rift2(compression) n=%u at bit %lu\n",
                            rn, pb.bitpos);
                    for (qi = 0; qi < rn; ++qi)
                        fprintf(stderr, "  rt[%u] left=%I64d right=%I64d rift=%I64d\n",
                                qi, rt[qi].left, rt[qi].right,
                                rt[qi].right - rt[qi].left);
                }
            }
        }

        /* Build the OffsetRiftTable the DLL feeds to the decompressor:
         *   t0  = sourceOffsetToRva (from the source PE sections)
         *   t1  = t0 * compressionRiftTable
         *   t2  = t1 * targetRvaToOffset
         *   t2r = Reverse(t2)
         *   t3  = {srcLen -> 0} * t2r   (shift into combined-buffer space)
         * then keep the positive-left entries, dropping repeated rifts. */
        {
            RIFTENTRY t0[64], t1[512], t2[512], t2r[512], t3[512];
            unsigned n0 = 0, n1, n2, n2r, n3;
            unsigned long lfa0;
            if (sourceLen >= 0x40)
            {
                lfa0 = rd32(source + 0x3C);
                if (lfa0 + 24 <= sourceLen && memcmp(source + lfa0, "PE\0\0", 4) == 0)
                {
                    unsigned long nsec = rd16(source + lfa0 + 6);
                    unsigned long opt = lfa0 + 24;
                    unsigned long sh = opt + rd16(source + lfa0 + 20);
                    unsigned s;
                    t0[n0].left = 0; t0[n0].right = 0; ++n0;
                    for (s = 0; s < nsec && n0 < 60; ++s)
                    {
                        unsigned long o = sh + 40 * s;
                        unsigned long va = rd32(source + o + 12);
                        unsigned long raw = rd32(source + o + 20);
                        if (o + 40 > sourceLen) break;
                        if (raw == 0 || va == 0) continue;
                        t0[n0].left = (__int64)raw;
                        t0[n0].right = (__int64)va;
                        ++n0;
                    }
                    qsort(t0, n0, sizeof(*t0), rift_cmp);
                }
            }
            if (n0 && rt && rn)
            {
                RIFTENTRY sh;
                unsigned k, w;

                n1 = rift_multiply(t0, n0, rt, rn, t1);
                n2 = rift_multiply(t1, n1, tmp, tmpN, t2);
                if (getenv("PA30_DEBUG"))
                {
                    unsigned q;
                    fprintf(stderr, "T1 n=%u:", n1);
                    for (q = 0; q < n1 && q < 10; ++q)
                        fprintf(stderr, " (%I64d->%I64d)", t1[q].left, t1[q].right);
                    fprintf(stderr, "\nT2 n=%u:", n2);
                    for (q = 0; q < n2 && q < 10; ++q)
                        fprintf(stderr, " (%I64d->%I64d)", t2[q].left, t2[q].right);
                    fprintf(stderr, "\n");
                }
                n2r = rift_reverse(t2, n2, t2r);
                qsort(t2r, n2r, sizeof(*t2r), rift_cmp);
                if (getenv("PA30_DEBUG"))
                {
                    unsigned q;
                    fprintf(stderr, "T2R n=%u:", n2r);
                    for (q = 0; q < n2r && q < 10; ++q)
                        fprintf(stderr, " (%I64d->%I64d)", t2r[q].left, t2r[q].right);
                    fprintf(stderr, "\n");
                }
                sh.left = (__int64)sourceLen;
                sh.right = 0;
                n3 = rift_multiply(&sh, 1, t2r, n2r, t3);
                if (getenv("PA30_DEBUG"))
                {
                    unsigned q;
                    fprintf(stderr, "T3 n=%u:", n3);
                    for (q = 0; q < n3 && q < 10; ++q)
                        fprintf(stderr, " (%I64d->%I64d)", t3[q].left, t3[q].right);
                    fprintf(stderr, "\n");
                }
                /* The OffsetRiftTable input keeps only left > 0 and drops
                 * an entry whose rift repeats the previous entry's. */
                w = 0;
                for (k = 0; k < n3; ++k)
                {
                    if (t3[k].left <= 0) continue;
                    if (w && (t3[w - 1].right - t3[w - 1].left) ==
                             (t3[k].right - t3[k].left)) continue;
                    t3[w++] = t3[k];
                }
                n3 = w;
                if (getenv("PA30_DEBUG"))
                {
                    unsigned q;
                    fprintf(stderr, "ORIFT n=%u\n", n3);
                    for (q = 0; q < n3 && q < 1000; ++q)
                        fprintf(stderr, "  or[%u] %I64d -> %I64d\n",
                                q, t3[q].left, t3[q].right);
                }
                orift = (RIFTENTRY *)malloc((size_t)(n3 ? n3 : 1) * sizeof(*orift));
                if (orift)
                {
                    memcpy(orift, t3, (size_t)n3 * sizeof(*orift));
                    oriftN = n3;
                }
            }
        }

        if (getenv("PA30_ORIFT"))
        {
            FILE *rf = fopen(getenv("PA30_ORIFT"), "rb");
            if (rf)
            {
                unsigned rn2 = 0;
                RIFTENTRY tmp2[512];
                while (rn2 < 512 &&
                       fread(&tmp2[rn2], sizeof(RIFTENTRY), 1, rf) == 1)
                    ++rn2;
                fclose(rf);
                free(orift);
                orift = (RIFTENTRY *)malloc((size_t)(rn2 ? rn2 : 1) * sizeof(*orift));
                if (orift)
                {
                    memcpy(orift, tmp2, (size_t)rn2 * sizeof(*orift));
                    oriftN = rn2;
                }
                if (getenv("PA30_DEBUG")) fprintf(stderr,
                    "loaded ORIFT n=%u\n", oriftN);
            }
        }

        br_init(&pbr, patch, patchLen);
        /* The patch blob begins with its own RiftTable.  Always consume it so
         * the CompositeFormat reader starts at the right bit, but keep the
         * compression map recovered from the pre blob as the active rift. */
        if (rc == 0)
        {
            RIFTENTRY *prt = NULL;
            unsigned prn = 0;
            if (rift_read(&pbr, &prt, &prn) == 0)
            {
                if (!rt) { rt = prt; rn = prn; }
                else free(prt);
            }
        }
        if (getenv("PA30_DEBUG")) fprintf(stderr,
            "PATCH rift n=%u rc=%d at bit %lu\n", rn, rc, pbr.bitpos);
        if (rc == 0)
            rc = compfmt_read(&cf, &pbr);
        if (getenv("PA30_DEBUG")) fprintf(stderr,
            "COMPFMT nSeg=%u rc=%d at bit %lu\n", cf.nSeg, rc, pbr.bitpos);
        if (rc == 0 && sourceLen >= 0x40)
        {
            unsigned long lfa = rd32(source + 0x3C);
            if (lfa + 24 <= sourceLen && memcmp(source + lfa, "PE\0\0", 4) == 0)
            {
                unsigned char *prepared = (unsigned char *)malloc(sourceLen);
                if (prepared)
                {
                    memcpy(prepared, source, (size_t)sourceLen);
                    /* NormalizeCoffImage writes the target COFF timestamp
                     * into the source PE before the delta is decoded. */
                    prepared[lfa + 8]     = (unsigned char)(peTimeStamp & 0xFF);
                    prepared[lfa + 9]     = (unsigned char)((peTimeStamp >> 8) & 0xFF);
                    prepared[lfa + 10]    = (unsigned char)((peTimeStamp >> 16) & 0xFF);
                    prepared[lfa + 11]    = (unsigned char)((peTimeStamp >> 24) & 0xFF);
                    /* PE32 optional-header ImageBase (magic 0x10B at lfa+24,
                     * ImageBase at +0x1C) is rebased to the target image. */
                    if (rd16(prepared + lfa + 24) == 0x10B &&
                        lfa + 24 + 0x40 <= sourceLen)
                    {
                        unsigned long oldBase =
                            rd32(prepared + lfa + 24 + 0x1C);
                        unsigned long sizeOfImage =
                            rd32(prepared + lfa + 24 + 0x38);
                        unsigned long sizeOfHeaders =
                            rd32(prepared + lfa + 24 + 0x3C);
                        prepared[lfa + 24 + 0x1C] = (unsigned char)(peImageBase & 0xFF);
                        prepared[lfa + 24 + 0x1D] = (unsigned char)((peImageBase >> 8) & 0xFF);
                        prepared[lfa + 24 + 0x1E] = (unsigned char)((peImageBase >> 16) & 0xFF);
                        prepared[lfa + 24 + 0x1F] = (unsigned char)((peImageBase >> 24) & 0xFF);
                        /* NormalizeCoffImage zeroes the PE checksum. */
                        memset(prepared + lfa + 24 + 0x40, 0, 4);
                        {
                            unsigned char *hintBuf =
                                (unsigned char *)malloc(sourceLen);
                            if (hintBuf)
                            {
                                memset(hintBuf, 0x02, sourceLen);
                                pa30_reloc_mask(prepared, sourceLen, hintBuf);
                                if (getenv("PA30_HINTDUMP"))
                                {
                                    FILE *hf = fopen(getenv("PA30_HINTDUMP"), "wb");
                                    if (hf)
                                    {
                                        fwrite(hintBuf, 1, (size_t)sourceLen, hf);
                                        fclose(hf);
                                    }
                                }
                            }
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED pointers\n");
                            pa30_transform_pointers(prepared, sourceLen, rt, rn,
                                oldBase, (unsigned long)peImageBase,
                                sizeOfImage, sizeOfHeaders, hintBuf);
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED relocs\n");
                            pa30_transform_relocs(prepared, sourceLen, rt, rn,
                                oldBase, (unsigned long)peImageBase,
                                sizeOfImage);
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED resources\n");
                            pa30_transform_resources(prepared, sourceLen,
                                                     rt, rn);
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED markimports\n");
                            pa30_mark_import_section(prepared, sourceLen);
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED imports\n");
                            if (getenv("PA30_BLIND"))
                                pa30_transform_rvas(prepared, sourceLen, rt, rn,
                                    sizeOfImage, sizeOfHeaders);
                            else
                                pa30_rewrite_imports(prepared, sourceLen,
                                                     rt, rn);
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED relcalls\n");
                            pa30_transform_relcalls(prepared, sourceLen, rt,
                                                    rn, hintBuf, sizeOfImage);
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED reljmps\n");
                            pa30_transform_reljmps(prepared, sourceLen, rt,
                                                   rn, hintBuf, sizeOfImage);
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED exports\n");
                            pa30_transform_exports(prepared, sourceLen,
                                                   rt, rn);
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED done\n");
                            free(hintBuf);
                        }
                    }
                    /* Verification hook: use the DLL's dumped transformed
                     * seed instead of our computed one. */
                    if (getenv("PA30_SEEDFILE"))
                    {
                        FILE *sf = fopen(getenv("PA30_SEEDFILE"), "rb");
                        if (sf)
                        {
                            if (fread(prepared, 1, (size_t)sourceLen, sf) ==
                                (size_t)sourceLen)
                            {
                                if (getenv("PA30_DEBUG")) fprintf(stderr,
                                    "using external seed\n");
                            }
                            fclose(sf);
                        }
                    }
                    decompressSrc = prepared;
                    if (getenv("PA30_SEEDDUMP"))
                    {
                        FILE *sf = fopen(getenv("PA30_SEEDDUMP"), "wb");
                        if (sf) { fwrite(prepared, 1, (size_t)sourceLen, sf); fclose(sf); }
                    }
                    if (getenv("PA30_SEEDONLY"))
                    {
                        free(orift);
                        free(tmp);
                        free(rt);
                        free(pre); free(patch);
                        *out = NULL; *outLen = 0;
                        return 0;
                    }
                    if (getenv("PA30_DEBUG")) fprintf(stderr,
                        "PRE seedt patch TS at %08lX\n", lfa + 8);
                }
            }
        }
        if (rc == 0)
        {
            result = (unsigned char *)malloc(h.targetSize);
            if (!result)
                rc = -1;
            else
                rc = compo_decompress(&pbr, &cf, decompressSrc, sourceLen,
                    orift ? orift : rt, orift ? oriftN : rn,
                    result, h.targetSize, (int)(h.flags & 0x1));
            if (rc != 0)
            {
                free(result);
                result = NULL;
            }
        }
        if (decompressSrc != source) free((void *)decompressSrc);
        free(tmp);
        free(orift);
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




