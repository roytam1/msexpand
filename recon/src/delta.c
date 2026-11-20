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

/* Invert a RiftTable: Map^-1(y) = y - (right-left) = y + (left-right). */
static unsigned rift_reverse(const RIFTENTRY *a, unsigned an, RIFTENTRY *out)
{
    unsigned i;
    for (i = 0; i < an; ++i)
    {
        out[i].left = a[i].right;
        out[i].right = a[i].left;
    }
    qsort(out, an, sizeof(*out), rift_cmp);
    return an;
}

/* Compose two RiftTables: result(x) = b(a(x)).  Breakpoints are the union of
 * A's lefts and the preimages of B's lefts through A. */
static unsigned rift_multiply(const RIFTENTRY *a, unsigned an,
                              const RIFTENTRY *b, unsigned bn,
                              RIFTENTRY *out)
{
    unsigned on = 0, i, j, k;
    __int64 x;
    if (!an) { if (bn) memcpy(out, b, (size_t)bn * sizeof(*out)); return bn; }
    if (!bn) { memcpy(out, a, (size_t)an * sizeof(*out)); return an; }
    out[on].left = INT64_MIN;
    out[on].right = rift_map(b, bn, rift_map(a, an, INT64_MIN));
    ++on;
    for (i = 0; i < an; ++i)
    {
        out[on].left = a[i].left;
        out[on].right = rift_map(b, bn, rift_map(a, an, a[i].left));
        ++on;
    }
    for (j = 0; j < bn; ++j)
    {
        /* preimage of b[j].left under A, for each A interval */
        for (k = 0; k < an; ++k)
        {
            __int64 lo = a[k].left;
            __int64 hi = (k + 1 < an) ? a[k + 1].left : INT64_MAX;
            __int64 rift = a[k].right - a[k].left;
            x = b[j].left - rift;
            if (x >= lo && x < hi)
            {
                out[on].left = x;
                out[on].right = rift_map(b, bn, rift_map(a, an, x));
                ++on;
            }
        }
    }
    qsort(out, on, sizeof(*out), rift_cmp);
    /* collapse duplicate lefts */
    k = 0;
    for (i = 1; i < on; ++i)
    {
        if (out[i].left == out[k].left) out[k].right = out[i].right;
        else out[++k] = out[i];
    }
    return k + 1;
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
                                    unsigned long sizeOfHeaders)
{
    unsigned char *hint;
    unsigned long pos;
    unsigned long end = len >= 4 ? len - 4 : 0;

    if (!sizeOfHeaders || sizeOfHeaders >= end || !sizeOfImage)
        return;
    hint = (unsigned char *)calloc((size_t)len, 1);
    if (!hint) return;
    pos = sizeOfHeaders;
    while (pos < end)
    {
        unsigned long v = rd32(buf + pos);
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
        {
            if (getenv("PA30_DEBUG")) fprintf(stderr,
                "DECOMP fail: pos=%lu seg=%u symval=%lu len=%lu bitpos=%lu\n",
                pos, segIndex, sym.value, sym.length, br->bitpos);
            return -1;
        }


        if (getenv("PA30_SYMDBG") && pos < 100000)
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
                unsigned long j;
                long sp = cpos + riftOff;
                if (getenv("PA30_SYMDBG") && pos == 1026)
                    fprintf(stderr, "RIFT1026 cpos=%ld off=%ld sp=%ld len=%lu\n",
                            cpos, riftOff, sp, len);
                if (sp < 0 || (unsigned long)(sp + (long)len) > srcLen + pos)
                {
                    if (getenv("PA30_DEBUG")) fprintf(stderr,
                        "DECOMP riftfail: pos=%lu sp=%ld len=%lu riftOff=%ld bitpos=%lu\n",
                        pos, sp, len, riftOff, br->bitpos);
                    compo_partial_dump(out, pos);
                    return -1;
                }
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
                if (getenv("PA30_SYMDBG") && pos == 83697)
                {
                    long ap = (long)pos - dist;
                    fprintf(stderr,
                        "MATCH83697 val=%lu len=%lu cpos=%ld off=%ld dist=%ld ap=%ld srcbytes=",
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
         *   t0 = sourceOffsetToRva (from the source PE sections)
         *   t1 = t0 * compressionRiftTable
         *   t2 = t1 * targetRvaToOffset
         *   t3 = {srcLen -> 0} * t2   (shift into combined-buffer space)
         */
        {
            RIFTENTRY t0[64], t1[512], t2[512], t2r[512], t3[512];
            unsigned n0 = 0, n1, n2, n2r, n3, si;
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
                for (si = 0; si < n2r; ++si)
                {
                    t3[si].left = t2r[si].left + (__int64)sourceLen;
                    t3[si].right = t2r[si].right;
                }
                n3 = n2r;
                qsort(t3, n3, sizeof(*t3), rift_cmp);
                if (getenv("PA30_DEBUG"))
                {
                    unsigned q;
                    fprintf(stderr, "ORIFT n=%u\n", n3);
                    for (q = 0; q < n3 && q < 12; ++q)
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
        if (rc == 0 && peTimeStamp && sourceLen >= 0x40)
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
                        pa30_transform_pointers(prepared, sourceLen, rt, rn,
                            oldBase, (unsigned long)peImageBase,
                            sizeOfImage, sizeOfHeaders);
                        if (getenv("PA30_RVAREWRITE"))
                        {
                            pa30_mark_import_section(prepared, sourceLen);
                            if (getenv("PA30_BLIND"))
                                pa30_transform_rvas(prepared, sourceLen, rt, rn,
                                    sizeOfImage, sizeOfHeaders);
                            else
                                pa30_rewrite_imports(prepared, sourceLen, rt, rn);
                        }
                    }
                    decompressSrc = prepared;
                    if (getenv("PA30_SEEDDUMP"))
                    {
                        FILE *sf = fopen(getenv("PA30_SEEDDUMP"), "wb");
                        if (sf) { fwrite(prepared, 1, (size_t)sourceLen, sf); fclose(sf); }
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




