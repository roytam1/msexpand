#include <time.h>
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

/* PE32+ moves the data directories from opt+0x60 to opt+0x70. */
#define PA30_MAGIC_OK(m)  ((m) == 0x10B || (m) == 0x20B)
#define PA30_DD(buf,opt)  ((opt) + (rd16((buf) + (opt)) == 0x20B ? 0x70U : 0x60U))

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

/* br_read() only returns 32 bits; a 64-bit field must be assembled from two
 * halves or the high half gets OR-ed into the low one. */
static unsigned __int64 br_read64(BITR *b)
{
    unsigned long lo = br_read(b, 32);
    unsigned long hi = br_read(b, 32);
    return ((unsigned __int64)hi << 32) | (unsigned __int64)lo;
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
#define HUFF_TABLE_BITS 12

typedef struct tagHUFF
{
    unsigned n;
    unsigned maxBits;
    unsigned char len[HUFF_MAX_SYMS];
    unsigned int code[HUFF_MAX_SYMS];   /* bit-reversed canonical codes */
    unsigned int msb[HUFF_MAX_SYMS];    /* canonical codes, MSB-first */
    unsigned short count[HUFF_MAX_BITS + 2];
    unsigned short firstCode[HUFF_MAX_BITS + 2];
    unsigned short sym[HUFF_MAX_SYMS];  /* symbols ordered by code length */
    unsigned short tblSym[1 << HUFF_TABLE_BITS];
    unsigned char tblLen[1 << HUFF_TABLE_BITS];
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
    memset(h->tblLen, 0, sizeof(h->tblLen));
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
    for (len = 0; len <= HUFF_MAX_BITS + 1; ++len)
    {
        h->count[len] = 0;
        h->firstCode[len] = 0;
    }
    for (len = 1; len <= maxBits; ++len)
    {
        h->count[len] = (unsigned short)cnt[len];
        h->firstCode[len] = (unsigned short)first[len];
    }
    {
        unsigned idx = 0;
        for (len = 1; len <= maxBits; ++len)
            for (i = 0; i < n; ++i)
                if (h->len[i] == len) h->sym[idx++] = (unsigned short)i;
    }
    for (i = 0; i < n; ++i)
    {
        unsigned l = h->len[i];
        unsigned r = 0;
        h->code[i] = 0;
        if (l)
        {
            unsigned c = first[l]++;
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
    /* fill shortest codes first so they win ambiguous table slots */
    for (i = 0; i < n; ++i)
    {
        unsigned si = h->sym[i];
        unsigned l = h->len[si];
        unsigned r = h->code[si];
        if (l && l <= HUFF_TABLE_BITS)
        {
            unsigned idx;
            for (idx = r; idx < (1u << HUFF_TABLE_BITS); idx += 1u << l)
                if (!h->tblLen[idx])
                {
                    h->tblSym[idx] = (unsigned short)si;
                    h->tblLen[idx] = (unsigned char)l;
                }
        }
    }
    return 0;
}

static unsigned huff_decode(const HUFF *h, BITR *br)
{
    unsigned pk = br_peek(br, HUFF_TABLE_BITS);
    if (h->tblLen[pk])
    {
        br_skip(br, h->tblLen[pk]);
        return h->tblSym[pk];
    }
    /* no table entry: decode from the start with the linear scan */
    {
        unsigned code = 0;
        unsigned len, i;
        for (len = 1; len <= h->maxBits; ++len)
        {
            code |= br_read(br, 1) << (len - 1);
            for (i = 0; i < h->n; ++i)
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
    unsigned len, i;
    for (len = 1; len <= h->maxBits; ++len)
    {
        code = (code << 1) | br_read(br, 1);
        for (i = 0; i < h->n; ++i)
            if (h->len[i] == len && h->msb[i] == code)
                return i;
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
    unsigned boundary[128];
    unsigned char metaLen[39];
    unsigned char lens[128][872];
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
    if (f->nSeg == 0 || f->nSeg > 128)
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
static unsigned __int64 rd64(const unsigned char *p);
static unsigned short rd16(const unsigned char *p);
static void pa30_set_u32(unsigned char *b, unsigned long off, unsigned long v);

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

/* ---------- CLI metadata and the compression rift it induces ------------
 * .NET deltas carry the target's CliMetadata fields (row counts and heap
 * offsets) plus a CliMap in the pre buffer.  Replaying the DLL's
 * CompressionRiftTableFromCliMap turns those into extra
 * (target offset -> source offset) rift entries for the metadata heaps and
 * tables, which the decompressor needs for 0x54000 matches inside .NET
 * assemblies.  The table schema below is the DLL's static CLI schema
 * (msdelta.dll: dword_10011DD8 / dword_10014E50 / dword_10014E54). */

#define CLI_MAX_COLS 16

typedef struct tagCLIMETA
{
    unsigned d3, d4, d5;            /* metadata offset, length, spare */
    unsigned nStream;               /* number of metadata streams */
    unsigned strmTable;             /* start of the stream table */
    unsigned stringsOff, stringsLen;
    unsigned usOff, usLen;
    unsigned blobOff, blobLen;
    unsigned guidOff, guidLen;
    unsigned tablesOff, tablesLen;
    unsigned char heapSizes;
    unsigned __int64 mask;
    unsigned rows[64];
    unsigned toff[64];              /* absolute table data offset */
    unsigned stride[64];            /* bytes per row */
    unsigned char is4[64][CLI_MAX_COLS];
    unsigned char coff[64][CLI_MAX_COLS];
    int empty;
} CLIMETA;

typedef struct tagCLIMAP
{
    RIFTENTRY *heap[4];
    unsigned heapN[4];
    RIFTENTRY *tbl[64];
    unsigned tblN[64];
} CLIMAP;

static const unsigned char g_cliNCols[64] = {
    5, 3, 6, 1, 3, 1, 6, 1, 3, 2, 3, 3, 3, 2, 3, 3,
    2, 1, 2, 1, 3, 2, 1, 3, 3, 3, 1, 1, 4, 2, 2, 1,
    9, 1, 3, 9, 2, 4, 3, 5, 4, 2, 5, 2, 2, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static const unsigned char g_cliColType[64][16] = {
    { 0, 3, 5, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 7, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 3, 3, 7, 6, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 2, 0, 0, 3, 4, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 6, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 7, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 7, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 7, 7, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 7, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 7, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 1, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 6, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 3, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 6, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 6, 7, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 7, 3, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 2, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 0, 0, 0, 0, 1, 4, 3, 3, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 1, 4, 3, 3, 4, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 1, 1, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 1, 3, 3, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 1, 3, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 6, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 7, 3, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 7, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 6, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

static const unsigned char g_cliColIdx[64][16] = {
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 4, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 1, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 5, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 2, 10, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 3, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 2, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 2, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 6, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 2, 7, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 8, 0, 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 11, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 35, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 35, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

static const unsigned char g_cliCodedBits[13] = { 2, 2, 5, 1, 2, 3, 1, 1, 1, 2, 3, 2, 1 };
static const unsigned char g_cliCodedCount[13] = { 3, 3, 22, 2, 3, 5, 2, 2, 2, 3, 5, 4, 2 };

static const unsigned char g_cliCodedMem[13][22] = {
    { 2, 1, 27, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 4, 8, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43 },
    { 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 2, 6, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 2, 1, 26, 6, 27, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 20, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 6, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 4, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 38, 35, 39, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 64, 64, 6, 10, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 26, 35, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 2, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

static unsigned cli_popcount64(unsigned __int64 v)
{
    unsigned n = 0;
    while (v) { v &= v - 1; ++n; }
    return n;
}

/* Recompute the derived table layout (CliMetadata::InitDependent). */
static void cli_meta_derive(CLIMETA *m)
{
    unsigned codedMax[13];
    unsigned t, c, i;

    for (i = 0; i < 13; ++i)
    {
        unsigned mx = 0, k;
        for (k = 0; k < g_cliCodedCount[i]; ++k)
        {
            unsigned idx = g_cliCodedMem[i][k];
            if (idx < 64 && m->rows[idx] > mx) mx = m->rows[idx];
        }
        codedMax[i] = mx;
    }
    memset(m->toff, 0, sizeof(m->toff));
    memset(m->stride, 0, sizeof(m->stride));
    memset(m->is4, 0, sizeof(m->is4));
    memset(m->coff, 0, sizeof(m->coff));
    for (t = 0; t < 64; ++t)
    {
        unsigned s = 0;
        if (!m->rows[t]) continue;
        for (c = 0; c < g_cliNCols[t]; ++c)
        {
            unsigned ty = g_cliColType[t][c];
            unsigned ix = g_cliColIdx[t][c];
            unsigned is4 = 0;
            switch (ty)
            {
            case 0:  is4 = 0; break;
            case 1:  case 2: is4 = 1; break;
            case 3:  is4 = (m->heapSizes & 1) != 0; break;
            case 4:  is4 = (m->heapSizes & 4) != 0; break;
            case 5:  is4 = (m->heapSizes & 2) != 0; break;
            case 6:  is4 = (ix < 64 && m->rows[ix] >= 0x10000UL); break;
            case 7:  is4 = (ix < 13 && codedMax[ix] >= (0x10000UL >> g_cliCodedBits[ix])); break;
            default: is4 = 0; break;
            }
            m->coff[t][c] = (unsigned char)s;
            m->is4[t][c] = (unsigned char)is4;
            s += 2 + 2 * is4;
        }
        m->stride[t] = s;
    }
    {
        unsigned v28 = 24 + 4 * cli_popcount64(m->mask);
        for (t = 0; t < 64; ++t)
        {
            if (!m->rows[t]) continue;
            m->toff[t] = m->tablesOff + v28;
            v28 += m->stride[t] * m->rows[t];
        }
    }
}

/* Parse the CLI metadata at [off, off+len) of buf (CliMetadata::Init). */
static void cli_meta_init(CLIMETA *m, const unsigned char *buf,
                          unsigned long bufLen, unsigned long off,
                          unsigned long len)
{
    unsigned long p, end;
    unsigned nStream, i, k;

    memset(m, 0, sizeof(*m));
    m->d3 = (unsigned)off;
    m->d4 = (unsigned)len;
    if (len < 0x18 || off + 0x10 > bufLen || off + len > bufLen)
    {
        m->empty = 1;
        return;
    }
    if (memcmp(buf + off, "BSJB", 4) != 0)
    {
        m->empty = 1;
        return;
    }
    {
        unsigned long verLen = rd32(buf + off + 12);
        if (verLen > 0xFF)
        {
            m->empty = 1;
            return;
        }
        p = off + 20 + ((verLen + 3) & ~3UL);
    }
    if (p < off + 20 || p > bufLen || p > off + len)
    {
        m->empty = 1;
        return;
    }
    nStream = rd16(buf + p - 2);
    m->nStream = nStream;
    m->strmTable = (unsigned)p;
    end = off + len;
    if (end > bufLen) end = bufLen;
    for (i = 0; i < nStream; ++i)
    {
        unsigned long soff, ssize, q, nlen;
        const unsigned char *name;

        if (p + 8 > end) break;
        soff = rd32(buf + p);
        ssize = rd32(buf + p + 4);
        q = p + 8;
        while (q < end && buf[q]) ++q;
        if (q >= end) break;
        nlen = q - (p + 8) + 1;      /* the DLL counts the terminator */
        name = buf + p + 8;
        p = (q + 1 + 3) & ~3UL;
        if (soff > len || ssize > len - soff) continue;
        if (nlen == 9 && memcmp(name, "#Strings", 9) == 0)
        { m->stringsOff = (unsigned)(off + soff); m->stringsLen = (unsigned)ssize; }
        else if (nlen == 4 && memcmp(name, "#US", 4) == 0)
        { m->usOff = (unsigned)(off + soff); m->usLen = (unsigned)ssize; }
        else if (nlen == 6 && memcmp(name, "#Blob", 6) == 0)
        { m->blobOff = (unsigned)(off + soff); m->blobLen = (unsigned)ssize; }
        else if (nlen == 6 && memcmp(name, "#GUID", 6) == 0)
        { m->guidOff = (unsigned)(off + soff); m->guidLen = (unsigned)ssize; }
        else if (nlen == 3 && memcmp(name, "#~", 3) == 0)
        { m->tablesOff = (unsigned)(off + soff); m->tablesLen = (unsigned)ssize; }
    }
    if (m->tablesOff && m->tablesLen >= 0x18 &&
        (unsigned long)m->tablesOff + 0x18 <= bufLen)
    {
        const unsigned char *tp = buf + m->tablesOff;
        unsigned long q = (unsigned long)m->tablesOff + 24;
        m->heapSizes = tp[6];
        m->mask = (unsigned __int64)rd32(tp + 8) |
                  ((unsigned __int64)rd32(tp + 12) << 32);
        for (k = 0; k < 64; ++k)
            if ((m->mask >> k) & 1)
            {
                if (q + 4 <= bufLen) m->rows[k] = rd32(buf + q);
                q += 4;
                if (m->rows[k] > 0x100000UL)
                {
                    memset(m->rows, 0, sizeof(m->rows));
                    m->mask = 0;
                    m->empty = 1;
                    return;
                }
            }
    }
    m->empty = !(m->d3 | m->d4 | m->d5 | m->nStream | m->strmTable |
                 m->stringsOff | m->stringsLen | m->usOff | m->usLen |
                 m->blobOff | m->blobLen | m->guidOff | m->guidLen |
                 m->tablesOff | m->tablesLen | m->heapSizes | (unsigned)m->mask);
}

static long cli_rva_to_off(const unsigned char *pe, unsigned long len,
                           unsigned long rva)
{
    unsigned long lfa, nsec, opt, sh, i;

    if (len < 0x40) return -1;
    lfa = rd32(pe + 0x3C);
    if (lfa + 24 > len || memcmp(pe + lfa, "PE\0\0", 4) != 0) return -1;
    nsec = rd16(pe + lfa + 6);
    opt = lfa + 24;
    sh = opt + rd16(pe + lfa + 20);
    for (i = 0; i < nsec; ++i)
    {
        unsigned long o = sh + 40 * i;
        unsigned long vs, va, rs, ra;
        if (o + 40 > len) break;
        vs = rd32(pe + o + 8);
        va = rd32(pe + o + 12);
        rs = rd32(pe + o + 16);
        ra = rd32(pe + o + 20);
        if (rva >= va && rva < va + (vs > rs ? vs : rs))
            return (long)(ra + (rva - va));
    }
    return -1;
}

/* Locate and parse the CLI metadata of a PE (ExtractCliMetadata path). */
static void cli_meta_from_pe(CLIMETA *m, const unsigned char *pe,
                             unsigned long len)
{
    unsigned long lfa, opt, dd, rva, size, off, metaOff, metaSize;

    memset(m, 0, sizeof(*m));
    m->empty = 1;
    if (len < 0x40) return;
    lfa = rd32(pe + 0x3C);
    if (lfa + 24 > len || memcmp(pe + lfa, "PE\0\0", 4) != 0) return;
    opt = lfa + 24;
    dd = (rd16(pe + opt) == 0x20B) ? opt + 0x70 : opt + 0x60;
    dd += 14 * 8;
    if (dd + 8 > len) return;
    rva = rd32(pe + dd);
    size = rd32(pe + dd + 4);
    if (!rva || !size) return;
    off = (unsigned long)cli_rva_to_off(pe, len, rva);
    if ((long)off < 0 || off + 16 > len) return;
    metaOff = (unsigned long)cli_rva_to_off(pe, len, rd32(pe + off + 8));
    metaSize = rd32(pe + off + 12);
    if ((long)metaOff < 0 || !metaSize) return;
    cli_meta_init(m, pe, len, metaOff, metaSize);
}

/* Read the target CliMetadata stored in the pre buffer. */
static void cli_meta_from_bits(CLIMETA *m, BITR *br)
{
    unsigned k;

    memset(m, 0, sizeof(*m));
    if (br_read(br, 1))
    {
        unsigned d[15];
        for (k = 0; k < 15; ++k) d[k] = br_read(br, 32);
        m->d3 = d[0]; m->d4 = d[1]; m->d5 = d[2];
        m->nStream = d[3]; m->strmTable = d[4];
        m->stringsOff = d[5]; m->stringsLen = d[6];
        m->usOff = d[7]; m->usLen = d[8];
        m->blobOff = d[9]; m->blobLen = d[10];
        m->guidOff = d[11]; m->guidLen = d[12];
        m->tablesOff = d[13]; m->tablesLen = d[14];
        m->heapSizes = (unsigned char)(br_read(br, 1) |
                                       (br_read(br, 1) << 1) |
                                       (br_read(br, 1) << 2));
        m->mask = (unsigned __int64)br_read(br, 32) |
                  ((unsigned __int64)br_read(br, 32) << 32);
        for (k = 0; k < 64; ++k)
            if ((m->mask >> k) & 1)
            {
                m->rows[k] = br_read(br, 32);
                if (m->rows[k] > 0x100000UL)
                {
                    memset(m->rows, 0, sizeof(m->rows));
                    m->mask = 0;
                    m->empty = 1;
                    return;
                }
            }
    }
    m->empty = !(m->d3 | m->d4 | m->d5 | m->nStream | m->strmTable |
                 m->stringsOff | m->stringsLen | m->usOff | m->usLen |
                 m->blobOff | m->blobLen | m->guidOff | m->guidLen |
                 m->tablesOff | m->tablesLen | m->heapSizes | (unsigned)m->mask);
}

/* RiftTable::FromBitReaderWithFormat: no presence bit, shared formats. */
static int rift_read_fmt(RIFTENTRY **out, unsigned *outn, INTFORMAT *fa,
                         INTFORMAT *fb, BITR *br)
{
    unsigned n, i;
    __int64 left = 0, rift = 0;
    RIFTENTRY *tab;

    *out = NULL;
    *outn = 0;
    n = br_read_int(br);
    if (n == 0xFFFFFFFFU || n > 0x0FFFFFFFUL)
        return -1;
    tab = (RIFTENTRY *)calloc(n ? (size_t)n : 1, sizeof(*tab));
    if (!tab)
        return -1;
    for (i = 0; i < n; ++i)
    {
        left += if_read_number(fa, br);
        rift += if_read_number(fb, br);
        tab[i].left = left;
        tab[i].right = left + rift;
    }
    *out = tab;
    *outn = n;
    return 0;
}

/* CliMap::InternalFromBitReader: four shared codecs, three heap maps, one
 * GUID map, then one map per metadata table. */
static int cli_map_read(CLIMAP *cm, BITR *br)
{
    INTFORMAT fa, fb, fc, fd;
    unsigned i, t;

    memset(cm, 0, sizeof(*cm));
    if (br_read(br, 1) == 0)
        return 0;
    if (if_read(&fa, br) != 0 || if_read(&fb, br) != 0 ||
        if_read(&fc, br) != 0 || if_read(&fd, br) != 0)
        return -1;
    for (i = 0; i < 4; ++i)
    {
        INTFORMAT *x = (i < 3) ? &fa : &fc;
        INTFORMAT *y = (i < 3) ? &fb : &fd;
        if (rift_read_fmt(&cm->heap[i], &cm->heapN[i], x, y, br) != 0)
            return -1;
    }
    for (t = 0; t < 64; ++t)
        if (rift_read_fmt(&cm->tbl[t], &cm->tblN[t], &fc, &fd, br) != 0)
            return -1;
    return 0;
}

typedef struct tagRIFTBUF
{
    RIFTENTRY *a;
    unsigned n, cap;
} RIFTBUF;

static int riftbuf_add(RIFTBUF *b, __int64 l, __int64 r)
{
    if (b->n == b->cap)
    {
        unsigned nc = b->cap ? b->cap * 2 : 512;
        RIFTENTRY *na = (RIFTENTRY *)realloc(b->a, (size_t)nc * sizeof(*na));
        if (!na)
            return -1;
        b->a = na;
        b->cap = nc;
    }
    b->a[b->n].left = l;
    b->a[b->n].right = r;
    ++b->n;
    return 0;
}

/* AddHeapMap: one entry per heap-map breakpoint, in target-heap space. */
static void cli_add_heap(RIFTBUF *o, __int64 a2, __int64 a3,
                         const RIFTENTRY *rift, unsigned n)
{
    unsigned v4 = 0, i, v8;

    if (!n)
    {
        riftbuf_add(o, a3, a2);
        return;
    }
    while (v4 < n && rift[v4].left <= 0) ++v4;
    v8 = v4 ? v4 - 1 : n - 1;
    riftbuf_add(o, a3 + (rift[v8].right - rift[v8].left), a2);
    for (i = v4; i < n; ++i)
    {
        if ((unsigned __int64)(rift[i].left >> 32) > 0) break;
        riftbuf_add(o, a3 + rift[i].right, a2 + rift[i].left);
    }
}

/* AddTableMap (sparse form): maps only the table map's breakpoints. */
static void cli_add_table_sparse(RIFTBUF *o, __int64 a2, __int64 a3,
                                 __int64 stride, const RIFTENTRY *rift,
                                 unsigned n)
{
    unsigned v4 = 0, i, v8;

    if (!n)
    {
        riftbuf_add(o, a3, a2);
        return;
    }
    while (v4 < n && rift[v4].left <= 1) ++v4;
    v8 = v4 ? v4 - 1 : n - 1;
    riftbuf_add(o, a3 + (rift[v8].right - rift[v8].left) * stride, a2);
    for (i = v4; i < n; ++i)
    {
        if ((unsigned __int64)(rift[i].left >> 32) > 0) break;
        riftbuf_add(o, a3 + (rift[i].right - 1) * stride,
                       a2 + (rift[i].left - 1) * stride);
    }
}

/* AddTableMap (detailed form): used when the row layouts differ, i.e. a
 * heap or coded-index column changed between 2 and 4 bytes.  Maps the rows
 * and the affected column cells.  The DLL reads two uninitialised fields
 * (+40/+44) as the source position of a grown last column; they held 5 on
 * every observed delta, so use that. */
static void cli_add_table_full(RIFTBUF *o, const CLIMETA *src,
                               const CLIMETA *tgt, unsigned t,
                               const RIFTENTRY *rift, unsigned n)
{
    __int64 strideS = (__int64)src->stride[t];
    __int64 strideT = (__int64)tgt->stride[t];
    __int64 sBase = (__int64)src->toff[t];
    __int64 tBase = (__int64)tgt->toff[t];
    unsigned rc = src->rows[t];
    unsigned c, i;
    __int64 rv, end;

    rv = rift_get_rift(rift, n, 0, &end);
    if (rc > 1)
    {
        for (i = 1; i < rc; ++i)
        {
            if ((__int64)i > end) rv = rift_get_rift(rift, n, (__int64)i, &end);
            riftbuf_add(o, tBase + (rv + (__int64)i - 1) * strideT,
                           sBase + ((__int64)i - 1) * strideS);
        }
    }
    for (c = 0; c < g_cliNCols[t]; ++c)
    {
        unsigned si = src->is4[t][c];
        unsigned ti = tgt->is4[t][c];
        int last = (g_cliNCols[t] <= c + 1);
        __int64 sCol, tCol;

        if (si == ti) continue;
        if (si && last) continue;
        sCol = sBase + src->coff[t][c];
        tCol = tBase + tgt->coff[t][c];
        if (si)
        {
            rv = rift_get_rift(rift, n, 0, &end);
            if (rc > 1)
            {
                for (i = 1; i < rc; ++i)
                {
                    if ((__int64)i > end) rv = rift_get_rift(rift, n, (__int64)i, &end);
                    riftbuf_add(o, tCol + (rv + (__int64)i - 1) * strideT + 2,
                                   sCol + ((__int64)i - 1) * strideS + 4);
                }
            }
        }
        else
        {
            rv = rift_get_rift(rift, n, 0, &end);
            if (rc > 1)
            {
                for (i = 1; i < rc; ++i)
                {
                    __int64 base;
                    if ((__int64)i > end) rv = rift_get_rift(rift, n, (__int64)i, &end);
                    base = tCol + (rv + (__int64)i - 1) * strideT;
                    if (last)
                        riftbuf_add(o, base + 2, 5);
                    riftbuf_add(o, base + 4,
                                   sCol + ((__int64)i - 1) * strideS + 2);
                }
            }
        }
    }
}

/* Stable merge sort by left.  The DLL's RiftTable::Sort is a stable radix
 * sort, and the order among equal lefts decides which mapping survives the
 * reduction below. */
static void rift_stable_sort(RIFTENTRY *a, unsigned n, RIFTENTRY *tmp)
{
    unsigned width, i;
    for (width = 1; width < n; width *= 2)
    {
        for (i = 0; i < n; i += 2 * width)
        {
            unsigned lo = i;
            unsigned mid = i + width;
            unsigned hi = i + 2 * width;
            unsigned x = lo, y = mid, k = lo;
            if (mid > n) mid = n;
            if (hi > n) hi = n;
            while (x < mid && y < hi)
            {
                if (a[y].left < a[x].left) tmp[k++] = a[y++];
                else tmp[k++] = a[x++];
            }
            while (x < mid) tmp[k++] = a[x++];
            while (y < hi) tmp[k++] = a[y++];
        }
        memcpy(a, tmp, (size_t)n * sizeof(*a));
    }
}

/* IL operand kinds (DisassemblerCli::oneByteParam / twoByteParam /
 * paramLength, msdelta.dll).  Kinds 1, 4, 8, 10 and 11 carry a
 * metadata token; 9 is a switch whose 4-byte count follows. */
static const unsigned char g_cliIlParam1[256] = {
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 16, 16,
    16, 16, 16, 16, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 14,
    2, 3, 15, 6, 5, 5, 5, 4, 4, 7, 5, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 9, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 4,
    11, 11, 8, 4, 11, 11, 5, 5, 5, 11, 5, 1, 1, 1, 1, 1,
    1, 11, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 11, 11, 5, 11,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 11, 11, 11, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 11, 5, 5, 5, 11, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    10, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 0, 13, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
};

static const unsigned char g_cliIlParam2[256] = {
    5, 5, 5, 5, 5, 5, 4, 4, 5, 12, 12, 12, 12, 12, 12, 5,
    5, 5, 14, 5, 5, 11, 11, 5, 5, 5, 5, 5, 11, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
};

static const unsigned char g_cliIlParamLen[18] = { 4, 4, 4, 8, 4, 0, 8, 4, 4, 4, 4, 4, 2, 1, 1, 4, 1, 0 };
static unsigned rift_map_value(const RIFTENTRY *t, unsigned n, unsigned v)
{
    unsigned lo, hi, idx;
    if (!n) return v;
    if ((__int64)v < t[0].left)
        idx = n - 1;                 /* the DLL uses the last rift here */
    else
    {
        lo = 0;
        hi = n - 1;
        while (lo < hi)
        {
            unsigned mid = (lo + hi + 1) >> 1;
            if (t[mid].left <= (__int64)v) lo = mid;
            else hi = mid - 1;
        }
        idx = lo;
    }
    return (unsigned)((__int64)v + (t[idx].right - t[idx].left));
}

/* CliMetadata::GetCellValue: read one column value of one row. */
static unsigned cli_get_cell(const CLIMETA *m, const unsigned char *buf,
                             unsigned long bufLen, unsigned table,
                             unsigned row, unsigned col)
{
    unsigned long off;
    if (table >= 64 || col >= g_cliNCols[table] || row == 0 ||
        row > m->rows[table])
        return 0;
    off = (unsigned long)m->toff[table] +
          (unsigned long)(row - 1) * m->stride[table] + m->coff[table][col];
    if (off + 4 > bufLen)
        return 0;
    if (m->is4[table][col])
        return rd32(buf + off);
    return rd16(buf + off);
}

static unsigned long cli_rva_max_size(const unsigned char *pe,
                                      unsigned long len, unsigned long rva)
{
    unsigned long lfa, nsec, opt, sh, i, sizeOfHeaders;

    if (len < 0x40) return 0;
    lfa = rd32(pe + 0x3C);
    if (lfa + 24 > len || memcmp(pe + lfa, "PE\0\0", 4) != 0) return 0;
    nsec = rd16(pe + lfa + 6);
    opt = lfa + 24;
    sh = opt + rd16(pe + lfa + 20);
    sizeOfHeaders = rd32(pe + opt + 0x3C);
    if (rva < sizeOfHeaders) return sizeOfHeaders - rva;
    for (i = 0; i < nsec; ++i)
    {
        unsigned long o = sh + 40 * i;
        unsigned long vs, va, rs;
        if (o + 40 > len) break;
        vs = rd32(pe + o + 8);
        va = rd32(pe + o + 12);
        rs = rd32(pe + o + 16);
        if (rva >= va && rva < va + (vs > rs ? vs : rs))
            return va + rs - rva;
    }
    return 0;
}

/* CliHelper::GetMethodOffset: locate a CLI method body by RVA. */
static unsigned long cli_method_offset(const unsigned char *buf,
                                       unsigned long bufLen,
                                       unsigned long rva,
                                       unsigned long *hdr,
                                       unsigned long *codeSize)
{
    long o;
    unsigned long off, maxSize, h, cs, b0;

    *hdr = 0;
    *codeSize = 0;
    o = cli_rva_to_off(buf, bufLen, rva);
    if (o < 0) return 0;
    off = (unsigned long)o;
    maxSize = cli_rva_max_size(buf, bufLen, rva);
    if (!maxSize || off >= bufLen) return 0;
    b0 = buf[off];
    switch (b0 & 3)
    {
    case 2:
        h = 1;
        cs = b0 >> 2;
        break;
    case 3:
        if (maxSize < 0xC || off + 8 > bufLen) return 0;
        h = 4UL * (buf[off + 1] >> 4);
        if (h < 0xC || h > maxSize) return 0;
        cs = rd32(buf + off + 4);
        break;
    default:
        return 0;
    }
    if (cs > maxSize - h) return 0;
    *hdr = h;
    *codeSize = cs;
    return off;
}

/* RiftTransformCliDisasm: rewrite the metadata tokens of every CLI method
 * body through the CLI map.  This is the whole seed transform for CLI
 * files; the disassembly/relocation transforms run for native images. */
static void pa30_transform_cli_disasm(unsigned char *buf, unsigned long len,
                                      const CLIMETA *meta, const CLIMAP *cm)
{
    unsigned long row;
    unsigned methods = 0, tokens = 0, toks = 0, insns = 0;

    if (!meta || meta->empty || meta->rows[6] == 0 ||
        meta->rows[6] > 0x100000UL)
    {
        if (getenv("PA30_DEBUG")) fprintf(stderr,
            "CLITR skip empty=%d rows6=%u\n", meta ? meta->empty : -1,
            meta ? meta->rows[6] : 0);
        return;
    }
    /* The DLL's loop breaks when the next row index reaches rows[6], so the
     * last MethodDef row is never visited.  Match that off-by-one. */
    for (row = 1; row < meta->rows[6]; ++row)
    {
        unsigned long rva = (unsigned long)cli_get_cell(meta, buf, len, 6,
                                                        (unsigned)row, 0) +
                            meta->d5;
        unsigned long hdr = 0, codeSize = 0, off, n, pos;
        unsigned char *p;

        if (!rva) continue;
        off = cli_method_offset(buf, len, rva, &hdr, &codeSize);
        if (!off) continue;
        ++methods;
        p = buf + off + hdr;
        n = codeSize;
        if (off + hdr + n > len) n = len - off - hdr;
        pos = 0;
        while (pos < n)
        {
            unsigned op, plen;
            unsigned long operand;
            unsigned tok, hi, lo;

            if (p[pos] == 0xFE)
            {
                ++pos;
                if (pos >= n) break;
                op = g_cliIlParam2[p[pos]];
            }
            else
                op = g_cliIlParam1[p[pos]];
            plen = g_cliIlParamLen[op];
            if (pos + 1 + plen > n) break;
            operand = pos + 1;
            pos += 1 + plen;
            if (op != 1 && op != 4 && op != 8)
            {
                if (op == 9)
                {
                    unsigned long cnt;
                    if (n - pos < 4) break;
                    cnt = rd32(p + operand);
                    if ((n - pos) >> 2 < cnt) break;
                    pos += 4 * cnt;
                    continue;
                }
                if (op <= 9 || op > 11) continue;
            }
            ++toks; ++insns;
            tok = rd32(p + operand);
            ++toks;
            ++insns;
            hi = tok >> 24;
            lo = tok & 0xFFFFFFUL;
            if (hi >= 0x40)
            {
                if (hi == 0x70)
                {
                    unsigned v = rift_map_value(cm->heap[1], cm->heapN[1], lo);
                    p[operand + 0] = (unsigned char)((v | 0x70000000UL) & 0xFF);
                    p[operand + 1] = (unsigned char)(((v | 0x70000000UL) >> 8) & 0xFF);
                    p[operand + 2] = (unsigned char)(((v | 0x70000000UL) >> 16) & 0xFF);
                    p[operand + 3] = (unsigned char)(((v | 0x70000000UL) >> 24) & 0xFF);
                }
            }
            else
            {
                unsigned v = rift_map_value(cm->tbl[hi], cm->tblN[hi], lo);
                unsigned nv = (hi << 24) | v;
                if (nv != tok) ++tokens;
                p[operand + 0] = (unsigned char)(nv & 0xFF);
                p[operand + 1] = (unsigned char)((nv >> 8) & 0xFF);
                p[operand + 2] = (unsigned char)((nv >> 16) & 0xFF);
                p[operand + 3] = (unsigned char)((nv >> 24) & 0xFF);
            }
        }
    }
    if (getenv("PA30_DEBUG")) fprintf(stderr,
        "CLITR methods=%u tokens=%u toks=%u insns=%u\n",
        methods, tokens, toks, insns);
}

/* CliMap::MapCoded: remap a coded index through its tag table. */
static unsigned cli_map_coded(const CLIMAP *cm, unsigned idx, unsigned v)
{
    unsigned bits, tag, tbl;
    if (idx >= 13) return v;
    bits = g_cliCodedBits[idx];
    tag = v & ((1u << bits) - 1);
    if (tag >= g_cliCodedCount[idx]) return v;
    tbl = g_cliCodedMem[idx][tag];
    if (tbl >= 64 || !cm->tblN[tbl]) return v;
    return tag | (rift_map_value(cm->tbl[tbl], cm->tblN[tbl], v >> bits) << bits);
}

static void cli_put(unsigned char *p, unsigned is4, unsigned v)
{
    if (is4)
    {
        p[0] = (unsigned char)(v & 0xFF);
        p[1] = (unsigned char)((v >> 8) & 0xFF);
        p[2] = (unsigned char)((v >> 16) & 0xFF);
        p[3] = (unsigned char)((v >> 24) & 0xFF);
    }
    else
    {
        p[0] = (unsigned char)(v & 0xFF);
        p[1] = (unsigned char)((v >> 8) & 0xFF);
    }
}

/* ---- Signature blob token remapping (RiftTransformCliMetadata, blob pass) ---- */

typedef struct tagCLIBLOBREF
{
    unsigned off;
    unsigned kind;
} CLIBLOBREF;

typedef struct tagCLIBLOBSET
{
    CLIBLOBREF a[8192];
    unsigned n;
} CLIBLOBSET;

static void cli_blob_collect(CLIBLOBSET *s, unsigned off, unsigned kind)
{
    unsigned i;
    for (i = 0; i < s->n; ++i)
        if (s->a[i].off == off) return;      /* the DLL keeps the first kind */
    if (s->n < 8192)
    {
        s->a[s->n].off = off;
        s->a[s->n].kind = kind;
        ++s->n;
    }
}

/* Read a compressed (ECMA-335) unsigned integer; *pos advances past it. */
static unsigned sig_comp(const unsigned char *p, unsigned long n,
                         unsigned long *pos)
{
    unsigned long i = *pos;
    unsigned v;
    if (i >= n) { *pos = n; return 0; }
    v = p[i];
    if (!(v & 0x80))
    {
        *pos = i + 1;
        return v;
    }
    if (!(v & 0x40))
    {
        if (i + 1 >= n) { *pos = n; return v & 0x3F; }
        *pos = i + 2;
        return ((v & 0x3F) << 8) | p[i + 1];
    }
    if (!(v & 0x20))
    {
        if (i + 3 >= n) { *pos = n; return v & 0x1F; }
        *pos = i + 4;
        return ((v & 0x1F) << 24) | ((unsigned)p[i + 1] << 16) |
               ((unsigned)p[i + 2] << 8) | p[i + 3];
    }
    *pos = n;               /* invalid compressed integer */
    return 0;
}

/* Re-encode a remapped TypeDefOrRef-style token in place, using the same
 * field width the DLL writes (it keeps the original span). */
static void sig_put_comp(unsigned char *p, unsigned long n,
                         unsigned long start, unsigned long end, unsigned v)
{
    unsigned long width = end - start;
    if (v < 0x80)
    {
        if (width >= 1) p[start] = (unsigned char)v;
    }
    else if (v < 0x4000)
    {
        if (width >= 2)
        {
            p[start] = (unsigned char)((v >> 8) | 0x80);
            p[start + 1] = (unsigned char)v;
        }
    }
    else if (v < 0x20000000 && width >= 4)
    {
        p[start] = (unsigned char)((v >> 24) | 0xC0);
        p[start + 1] = (unsigned char)(v >> 16);
        p[start + 2] = (unsigned char)(v >> 8);
        p[start + 3] = (unsigned char)v;
    }
}

static unsigned g_sigRows[64];          /* source metadata row counts */

/* The DLL remaps tag 0 and 1 through the TypeDef map and tag 2 through the
 * TypeSpec map (msdelta.dll.c:39479-39500, 39560-39574).  Out-of-range rows
 * are left alone. */
static unsigned sig_map_token(const CLIMAP *cm, unsigned v)
{
    unsigned tag = v & 3;
    unsigned row = v >> 2;
    unsigned tbl = (tag == 2) ? 27 : 2;

    /* RiftTable::Map does not range-check the row against the table's row
     * count: values past the last entry use that entry's rift.  Rejecting
     * out-of-range rows here silently skips tokens the DLL does remap. */
    (void)g_sigRows;
    return (rift_map_value(cm->tbl[tbl], cm->tblN[tbl], row) << 2) | tag;
}

static void cli_sig_type(const CLIMAP *cm, unsigned char *p, unsigned long n,
                         unsigned long *pos, unsigned depth, int doMap);

static void cli_sig_ret_and_params(const CLIMAP *cm, unsigned char *p,
                                   unsigned long n, unsigned long *pos,
                                   unsigned params, unsigned depth)
{
    if (depth > 8) return;
    /* The DLL's hand-written signature walker takes a different branch
     * when the return type is ELEMENT_TYPE_END / VOID / TYPEDBYREF: it
     * skips the type list entirely and leaves every token untouched. */
    {
        unsigned ret = (*pos < n) ? p[*pos] : 0;
        int noMap = (ret == 0x00 || ret == 0x01 || ret == 0x16);
        cli_sig_type(cm, p, n, pos, depth + 1, !noMap);
        while (params-- && *pos < n)
            cli_sig_type(cm, p, n, pos, depth + 1, !noMap);
    }
}

static void cli_sig_method(const CLIMAP *cm, unsigned char *p,
                           unsigned long n, unsigned long *pos,
                           unsigned depth)
{
    unsigned cc, gen = 0, params;
    if (*pos >= n) return;
    cc = p[(*pos)++];
    if (cc & 0x10)
        gen = sig_comp(p, n, pos);
    params = sig_comp(p, n, pos);
    (void)gen;
    cli_sig_ret_and_params(cm, p, n, pos, params, depth + 1);
}

static void cli_sig_type(const CLIMAP *cm, unsigned char *p, unsigned long n,
                         unsigned long *pos, unsigned depth, int doMap)
{
    unsigned et, start;
    unsigned long tokStart, tokEnd;
    unsigned v;

    if (depth > 12 || *pos >= n) return;
    start = (*pos)++;
    et = p[start];
    switch (et)
    {
    case 0x11:                  /* ELEMENT_TYPE_VALUETYPE */
    case 0x12:                  /* ELEMENT_TYPE_CLASS */
    case 0x1F:                  /* ELEMENT_TYPE_CMOD_REQD */
    case 0x20:                  /* ELEMENT_TYPE_CMOD_OPT */
        tokStart = *pos;
        v = sig_comp(p, n, pos);
        tokEnd = *pos;
        if (doMap)
            sig_put_comp(p, n, tokStart, tokEnd, sig_map_token(cm, v));
        if (et == 0x1F || et == 0x20)
            cli_sig_type(cm, p, n, pos, depth + 1, doMap);
        break;
    case 0x0F:                  /* PTR */
    case 0x10:                  /* BYREF */
    case 0x1D:                  /* SZARRAY */
        cli_sig_type(cm, p, n, pos, depth + 1, doMap);
        break;
    case 0x13:                  /* VAR */
    case 0x1E:                  /* MVAR */
        sig_comp(p, n, pos);
        break;
    case 0x14:                  /* ARRAY */
        {
            unsigned rank, ns, nb, i;
            cli_sig_type(cm, p, n, pos, depth + 1, doMap);
            rank = sig_comp(p, n, pos);
            ns = sig_comp(p, n, pos);
            for (i = 0; i < ns && *pos < n; ++i) sig_comp(p, n, pos);
            nb = sig_comp(p, n, pos);
            for (i = 0; i < nb && *pos < n; ++i) sig_comp(p, n, pos);
            (void)rank;
        }
        break;
    case 0x15:                  /* GENERICINST: CLASS/VALUETYPE + argc + args */
        cli_sig_type(cm, p, n, pos, depth + 1, doMap);
        {
            unsigned argc = sig_comp(p, n, pos), i;
            for (i = 0; i < argc && *pos < n; ++i)
                cli_sig_type(cm, p, n, pos, depth + 1, doMap);
        }
        break;
    case 0x1B:                  /* FNPTR */
        cli_sig_method(cm, p, n, pos, depth + 1);
        break;
    case 0x41:                  /* SENTINEL */
    case 0x45:                  /* PINNED */
        cli_sig_type(cm, p, n, pos, depth + 1, doMap);
        break;
    default:
        break;                  /* void, primitives, string, object, typedbyref */
    }
}

/* Rewrite the TypeDefOrRef tokens inside signature blobs. */
static void pa30_transform_cli_blobs(unsigned char *buf, unsigned long len,
                                     const CLIMETA *src, const CLIMAP *cm,
                                     const CLIBLOBSET *blobs)
{
    unsigned i;
    unsigned long base = src->blobOff;
    unsigned long heapLen = src->blobLen;

    if (!base || !heapLen || base + heapLen > len) return;
    memcpy(g_sigRows, src->rows, sizeof(g_sigRows));
    for (i = 0; i < blobs->n; ++i)
    {
        unsigned long off = blobs->a[i].off;
        unsigned kind = blobs->a[i].kind;
        unsigned long pos, blen, start, end;
        unsigned char *p;

        if (off >= heapLen) continue;
        pos = base + off;
        blen = sig_comp(buf, base + heapLen, &pos);
        start = pos;
        end = base + off + heapLen;      /* overwritten below */
        {
            unsigned long heapEnd = base + heapLen;
            unsigned long q = pos;
            /* the length prefix we just read gives the blob size */
            (void)blen;
            {
                unsigned long lenStart = base + off;
                unsigned long lpos = lenStart;
                unsigned l = sig_comp(buf, heapEnd, &lpos);
                end = lpos + l;
                if (end > heapEnd) end = heapEnd;
            }
            if (end <= start || end > heapEnd) continue;
            p = buf;
        }
        if ((kind == 0 || kind == 2) && start < end && p[start] == 0x06)
            kind = 3;                  /* FieldSig referenced via kind 0/2 */
        if (kind >= 1 && kind <= 5)
        {
            unsigned long q = start;
            if (kind == 5)
                cli_sig_type(cm, p, end, &q, 0, 1);
            else if (kind == 3)
            {
                if (q < end) ++q;        /* ELEMENT_TYPE_FIELD (0x06) */
                cli_sig_type(cm, p, end, &q, 0, 1);
            }
            else if (kind == 4)
            {
                unsigned params;
                if (q < end) ++q;        /* ELEMENT_TYPE_PROPERTY (0x08) */
                params = sig_comp(p, end, &q);
                cli_sig_ret_and_params(cm, p, end, &q, params, 0);
            }
            else
                cli_sig_method(cm, p, end, &q, 0);   /* 1 = MethodDef, 2 = MemberRef */
        }
        else if (kind == 9)
        {
            unsigned long q = start;
            unsigned cc = (q < end) ? p[q++] : 0;
            if ((cc & 0x0F) == 0x07)     /* LOCAL_SIG: count + types */
            {
                unsigned cnt = sig_comp(p, end, &q), i;
                for (i = 0; i < cnt && q < end; ++i)
                    cli_sig_type(cm, p, end, &q, 0, i == 0);
            }
            else
                cli_sig_method(cm, p, end, &q, 0);
        }
    }
}

/* RiftTransformCliMetadata: rewrite every heap index, table index, coded
 * index and method RVA of the CLI metadata through the CLI map, so the seed
 * lines up row-for-row with the target's metadata. */
static void pa30_transform_cli_metadata(unsigned char *buf, unsigned long len,
                                        const CLIMETA *src, const CLIMETA *tgt,
                                        const CLIMAP *cm, const RIFTENTRY *rt,
                                        unsigned rn, CLIBLOBSET *blobs)
{
    unsigned t, c, row;
    int rvaWrite = 1;

    if (!src || src->empty) return;
    if (getenv("PA30_CLIRVA")) rvaWrite = atoi(getenv("PA30_CLIRVA"));
    for (t = 0; t < 64; ++t)
    {
        unsigned ncols, stride, toff, n;
        if (!src->rows[t]) continue;
        ncols = g_cliNCols[t];
        stride = src->stride[t];
        toff = src->toff[t];
        n = src->rows[t];
        for (c = 0; c < ncols; ++c)
        {
            unsigned ty = g_cliColType[t][c];
            unsigned idx = g_cliColIdx[t][c];
            unsigned coff = src->coff[t][c];
            unsigned is4 = src->is4[t][c];
            unsigned wide = is4 ? 4 : 2;

            if (ty == 0 || ty == 1)
                continue;                   /* plain constant */
            if (ty == 3 && !cm->heapN[0]) continue;
            if (ty == 4 && !cm->heapN[2]) continue;
            if (ty == 5 && !cm->heapN[3]) continue;
            if (ty == 6 && (idx >= 64 || !cm->tblN[idx])) continue;
            for (row = 1; row <= n; ++row)
            {
                unsigned long o = (unsigned long)toff +
                                  (unsigned long)(row - 1) * stride + coff;
                unsigned v, nv;
                if (o + wide > len) break;
                v = is4 ? rd32(buf + o) : rd16(buf + o);
                nv = v;
                switch (ty)
                {
                case 2:
                    nv = rvaWrite
                        ? (unsigned)((long)pa30_map_rva(rt, rn,
                                        (unsigned long)src->d5 + v) -
                                     (long)tgt->d5)
                        : 0;
                    break;
                case 3:
                    nv = rift_map_value(cm->heap[0], cm->heapN[0], v);
                    break;
                case 4:
                    cli_blob_collect(blobs, v, idx);
                    nv = rift_map_value(cm->heap[2], cm->heapN[2], v);
                    break;
                case 5:
                    nv = rift_map_value(cm->heap[3], cm->heapN[3], v);
                    break;
                case 6:
                    nv = rift_map_value(cm->tbl[idx], cm->tblN[idx], v);
                    break;
                case 7:
                    nv = cli_map_coded(cm, idx, v);
                    break;
                default:
                    break;
                }
                if (nv != v)
                    cli_put(buf + o, is4, nv);
            }
        }
    }
}

/* Build the CLI contribution to the compression rift. */
static int cli_compression_rift(RIFTENTRY **out, unsigned *outn,
                                const CLIMETA *src, const CLIMETA *tgt,
                                const CLIMAP *cm)
{
    RIFTBUF o;
    unsigned t;

    *out = NULL;
    *outn = 0;
    memset(&o, 0, sizeof(o));
    if (src->empty || tgt->empty)
        return 0;
    /* The DLL skips CompressionRiftTableFromCliMap entirely when the CliMap
     * is empty (BitReadCliMap's presence bit was clear).  Adding identity
     * entries for every metadata table in that case blows the offset rift up
     * from a handful of entries to tens of thousands and corrupts RIFT
     * matches. */
    {
        unsigned q, any = 0;
        for (q = 0; q < 4; ++q)
            if (cm->heapN[q]) any = 1;
        for (q = 0; q < 64; ++q)
            if (cm->tblN[q]) any = 1;
        if (!any) return 0;
    }
    cli_add_heap(&o, (__int64)src->stringsOff, (__int64)tgt->stringsOff,
                 cm->heap[0], cm->heapN[0]);
    cli_add_heap(&o, (__int64)src->usOff, (__int64)tgt->usOff,
                 cm->heap[1], cm->heapN[1]);
    cli_add_heap(&o, (__int64)src->blobOff, (__int64)tgt->blobOff,
                 cm->heap[2], cm->heapN[2]);
    cli_add_table_sparse(&o, (__int64)src->guidOff, (__int64)tgt->guidOff,
                         16, cm->heap[3], cm->heapN[3]);
    for (t = 0; t < 64; ++t)
    {
        unsigned c, same;
        if (!src->rows[t] || !tgt->rows[t] ||
            src->rows[t] > 0x100000UL || tgt->rows[t] > 0x100000UL)
            continue;
        same = (src->stride[t] == tgt->stride[t]);
        for (c = 0; same && c < g_cliNCols[t]; ++c)
            if (src->is4[t][c] != tgt->is4[t][c]) same = 0;
        if (same)
            cli_add_table_sparse(&o, (__int64)src->toff[t],
                                 (__int64)tgt->toff[t],
                                 (__int64)src->stride[t],
                                 cm->tbl[t], cm->tblN[t]);
        else
            cli_add_table_full(&o, src, tgt, t, cm->tbl[t], cm->tblN[t]);
    }
    *out = o.a;
    *outn = o.n;
    return 0;
}

static void cli_map_free(CLIMAP *cm)
{
    unsigned i;
    for (i = 0; i < 4; ++i) { free(cm->heap[i]); cm->heap[i] = NULL; cm->heapN[i] = 0; }
    for (i = 0; i < 64; ++i) { free(cm->tbl[i]); cm->tbl[i] = NULL; cm->tblN[i] = 0; }
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
    if (!PA30_MAGIC_OK(rd16(buf + opt)) || opt + 0x90 > len) return;
    rrva = rd32(buf + PA30_DD(buf, opt) + 5 * 8);
    rsize = rd32(buf + PA30_DD(buf, opt) + 5 * 8 + 4);
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

}

/* Mirrors compo::MarkNonExeComponent::Transform (msdelta.dll.c:42457):
 * every byte of a non-executable section and the PE headers are marked as
 * handled, so the relative-call/jump passes leave rewrite targets that
 * live there alone.  The DLL also marks each data directory by RVA, but
 * doing so regresses several real deltas, so that part is deliberately
 * left out. */
static void pa30_mark_nonexe(const unsigned char *buf, unsigned long len,
                             unsigned char *mask)
{
    unsigned long pe, opt, nsec, sh, s, k;
    if (len < 0x40) return;
    pe = rd32(buf + 0x3C);
    if (pe + 24 > len || memcmp(buf + pe, "PE\0\0", 4)) return;
    opt = pe + 24;
    if (!PA30_MAGIC_OK(rd16(buf + opt)) || opt + 0x90 > len) return;
    nsec = rd16(buf + pe + 6);
    sh = opt + rd16(buf + pe + 20);
    for (s = 0; s < nsec && sh + 40 * s + 40 <= len; ++s)
    {
        unsigned long o = sh + 40 * s;
        unsigned long chars = rd32(buf + o + 36);
        unsigned long raw = rd32(buf + o + 20);
        unsigned long rs = rd32(buf + o + 16);
        if (chars & 0x20000000UL) continue;      /* executable: leave alone */
        if (raw >= len) continue;
        if (rs > len - raw) rs = len - raw;
        for (k = 0; k < rs; ++k)
            mask[raw + k] |= 0x01U;
    }
    /* SizeOfHeaders is memset to 3 by the DLL. */
    {
        unsigned long hdr = rd32(buf + opt + 0x3C);
        if (hdr > len) hdr = len;
        for (k = 0; k < hdr; ++k)
            mask[k] |= 0x03U;
    }
}

/* Mirrors the DLL's RiftTransformRelocationsI386Component::
 * TransformInferredRelocations: scan from SizeOfHeaders, rewriting any
 * aligned dword that is a VA inside the old image to
 * MapRva(va - oldBase) + newBase.  A packed hint array prevents overlapping
 * hits from being rewritten twice. */
static void pa30_transform_pointers(unsigned char *buf, unsigned long len,
                                    const RIFTENTRY *rt, unsigned rn,
                                    unsigned __int64 oldBase,
                                    unsigned __int64 newBase,
                                    unsigned long sizeOfImage,
                                    unsigned long sizeOfHeaders,
                                    const unsigned char *relocMask)
{
    unsigned char *hint;
    unsigned long pos;
    unsigned long end = len >= 4 ? len - 4 : 0;
    int skipImm = getenv("PA30_SKIPIMM") != NULL;

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
        if (pos && skipImm &&
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
            unsigned __int64 nv;
            if (((hint[pos] | hint[pos + 1] | hint[pos + 2] | hint[pos + 3])
                 & 0x02) == 0)
            {
                nv = (unsigned __int64)pa30_map_rva(rt, rn,
                        (unsigned long)(v - oldBase)) + newBase;
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

/* RiftTransformDisasmAmd64: rewrite RIP-relative displacements in x64 code
 * so they still point at the same section after the rebase.  We recognise
 * the common ModRM=00/rm=101 encodings instead of running a full decoder. */
static int pa30_x64_decode(const unsigned char *start,
                           const unsigned char *end, int *ripOff)
{
    /* ripOff is also used for a rel32 branch operand (E8/E9/0F8x). */
    const unsigned char *p = start;
    int opsz16 = 0, rexw = 0;
    int hasModrm = 0, imm = 0;
    unsigned op;

    *ripOff = -1;
    for (;;)
    {
        unsigned c;
        if (p >= end) return 0;
        c = *p;
        if (c == 0x66) { opsz16 = 1; ++p; continue; }
        if (c == 0x67 || c == 0xF0 || c == 0xF2 || c == 0xF3 ||
            c == 0x2E || c == 0x36 || c == 0x3E || c == 0x26 ||
            c == 0x64 || c == 0x65) { ++p; continue; }
        break;
    }
    /* The DLL's table only knows 48-4F as a REX prefix; 40-47 are plain
     * one-byte opcodes to it. */
    /* In 64-bit mode 0x40-0x4F are always REX prefixes (the INC/DEC opcodes
     * were repurposed); a legacy prefix such as 0x66 may precede them. */
    if (p < end && *p >= 0x40 && *p <= 0x4F)
    {
        rexw = (*p & 0x08) != 0;
        ++p;
    }
    if (p >= end) return 0;
    op = *p++;

    if (op == 0x0F)
    {
        unsigned op2;
        if (p >= end) return 0;
        op2 = *p++;
        /* The DLL's table gives the multi-byte NOP a length of two bytes
         * (0F and 1F), leaving the displacement bytes to be decoded as
         * fresh instructions. */
        if (op2 == 0x1F)
            return (int)(p - start);
        if (op2 >= 0x80 && op2 <= 0x8F)
        {
            *ripOff = (int)(p - start);
            imm = opsz16 ? 2 : 4;
        }
        else if (op2 == 0x38 || op2 == 0x3A)
        {
            /* Three-byte opcode maps: 0F 38 <op> /r, 0F 3A <op> /r ib. */
            if (p >= end) return 0;
            ++p;
            hasModrm = 1;
            if (op2 == 0x3A) imm = 1;
        }
        else if (op2 == 0x0F)
        {
            /* 3DNow!: 0F 0F /r ib */
            hasModrm = 1;
            imm = 1;
        }
        else
        {
            switch (op2)
            {
            case 0x05: case 0x06: case 0x07: case 0x08: case 0x09:
            case 0x0B: case 0x0E: case 0x30: case 0x31: case 0x32:
            case 0x33: case 0x34: case 0x35: case 0x37: case 0x77:
            case 0xA0: case 0xA1: case 0xA2: case 0xA8: case 0xA9:
            case 0xAA: case 0xC8: case 0xC9: case 0xCA: case 0xCB:
            case 0xCC: case 0xCD: case 0xCE: case 0xCF: case 0xFF:
                break;
            default:
                hasModrm = 1;
                switch (op2)
                {
                case 0x70: case 0x71: case 0x72: case 0x73:
                case 0xA4: case 0xAC: case 0xBA: case 0xC2:
                case 0xC4: case 0xC5: case 0xC6:
                    imm = 1;
                    break;
                }
                break;
            }
        }
    }
    else
    {
        switch (op)
        {
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x18: case 0x19: case 0x1A: case 0x1B:
        case 0x20: case 0x21: case 0x22: case 0x23:
        case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x38: case 0x39: case 0x3A: case 0x3B:
        case 0x62: case 0x63:
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E: case 0x8F:
        case 0xD0: case 0xD1: case 0xD2: case 0xD3:
        case 0xD8: case 0xD9: case 0xDA: case 0xDB:
        case 0xDC: case 0xDD: case 0xDE: case 0xDF:
        case 0xFE: case 0xFF:
            hasModrm = 1;
            break;
        case 0x69: case 0x6B:
            hasModrm = 1; imm = (op == 0x6B) ? 1 : (opsz16 ? 2 : 4);
            break;
        case 0x80: case 0x82: case 0x83:
            hasModrm = 1; imm = 1;
            break;
        case 0x81:
            hasModrm = 1; imm = opsz16 ? 2 : 4;
            break;
        case 0xC0: case 0xC1: case 0xC6:
            hasModrm = 1; imm = 1;
            break;
        case 0xC7:
            hasModrm = 1; imm = opsz16 ? 2 : 4;
            break;
        case 0xF6: case 0xF7:
            hasModrm = 2;               /* imm depends on the reg field */
            break;
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        case 0xE0: case 0xE1: case 0xE2: case 0xE3:
        case 0xEB:
            imm = 1;
            break;
        case 0x04: case 0x0C: case 0x14: case 0x1C:
        case 0x24: case 0x2C: case 0x34: case 0x3C:
        case 0x6A: case 0xA8: case 0xCD:
        case 0xE4: case 0xE5: case 0xE6: case 0xE7:
        case 0xD4: case 0xD5:
            imm = 1;
            break;
        case 0x05: case 0x0D: case 0x15: case 0x1D:
        case 0x25: case 0x2D: case 0x35: case 0x3D:
        case 0x68: case 0xA9:
            imm = opsz16 ? 2 : 4;
            break;
        case 0xE8: case 0xE9:
            *ripOff = (int)(p - start);
            imm = opsz16 ? 2 : 4;
            break;
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            imm = 1;
            break;
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            imm = rexw ? 8 : (opsz16 ? 2 : 4);
            break;
        case 0xC2: case 0xCA:
            imm = 2;
            break;
        case 0xC8:
            imm = 3;
            break;
        case 0xA0: case 0xA1: case 0xA2: case 0xA3:
            imm = rexw ? 8 : 4;
            break;
        default:
            break;
        }
    }

    if (hasModrm)
    {
        unsigned modrm, mod, rm;
        if (p >= end) return 0;
        modrm = *p++;
        mod = modrm >> 6;
        rm = modrm & 7;
        if (mod != 3)
        {
            if (rm == 4)
            {
                unsigned sib;
                if (p >= end) return 0;
                sib = *p++;
                if (mod == 0 && (sib & 7) == 5) p += 4;
            }
            else if (mod == 0 && rm == 5)
            {
                *ripOff = (int)(p - start);
                p += 4;
            }
            if (mod == 1) p += 1;
            else if (mod == 2) p += 4;
        }
        if (hasModrm == 2)
            imm = ((modrm >> 3) & 7) <= 1 ? ((op == 0xF7) ? (opsz16 ? 2 : 4) : 1)
                                          : 0;
    }
    p += imm;
    if (p > end) return 0;
    return (int)(p - start);
}

static void pa30_transform_amd64_rip(unsigned char *buf, unsigned long len,
                                     const RIFTENTRY *rt, unsigned rn,
                                     unsigned long sizeOfImage,
                                     const unsigned char *hint)
{
    unsigned long pe, opt, dd, er, es, n, entry;
    if (len < 0x40) return;
    pe = rd32(buf + 0x3C);
    if (pe + 24 > len || memcmp(buf + pe, "PE\0\0", 4)) return;
    opt = pe + 24;
    if (rd16(buf + opt) != 0x20B) return;   /* x64 only */
    dd = PA30_DD(buf, opt);
    if (dd + 4 * 8 > len) return;
    er = rd32(buf + dd + 3 * 8);            /* Exception Table (.pdata) */
    es = rd32(buf + dd + 3 * 8 + 4);
    if (!er || es < 12) return;

    /* The DLL walks each RUNTIME_FUNCTION range rather than sweeping .text,
     * so dead code and embedded data are never decoded. */
    n = es / 12;
    for (entry = 0; entry < n; ++entry)
    {
        unsigned long eoff = pa30_rva_off(buf, len, er + entry * 12);
        unsigned long begin, end, start, limit, p;
        if (eoff == 0xFFFFFFFFUL || eoff + 12 > len) continue;
        begin = rd32(buf + eoff);
        end = rd32(buf + eoff + 4);
        if (!begin || end <= begin) continue;
        start = pa30_rva_off(buf, len, begin);
        if (start == 0xFFFFFFFFUL || start >= len) continue;
        limit = start + (end - begin);
        if (limit > len) limit = len;
        p = start;
        while (p < limit)
        {
            int rip = -1;
            int step;
            if (hint && (hint[p] & 0x01))
            { ++p; continue; }
            step = pa30_x64_decode(buf + p, buf + limit, &rip);
            if (step <= 0) { ++p; continue; }
            if (rip >= 0 && p + (unsigned long)rip + 4 <= limit)
            {
                unsigned long f = p + (unsigned long)rip;
                long rel, siteRVA, targetRVA, mappedSite, mappedTarget, newrel;
                unsigned long to;
                rel = (long)rd32(buf + f);
                siteRVA = (long)(begin + (f - start) + 4);
                targetRVA = siteRVA + rel;
                /* The DLL does not range-check the target: MapRva is applied
                 * to whatever value the operand holds. */
                if (!(hint && (hint[f] | hint[f + 1] |
                               hint[f + 2] | hint[f + 3]) & 0x01))
                {
                    mappedSite = (long)pa30_map_rva(rt, rn,
                                                    (unsigned long)siteRVA);
                    mappedTarget = (long)pa30_map_rva(rt, rn,
                                               (unsigned long)targetRVA);
                    newrel = mappedTarget - mappedSite;
                    if (newrel != rel)
                    {
                        pa30_set_u32(buf, f, (unsigned long)newrel);
                        if (hint)
                            memset((void *)(hint + f), 0x01, 4);
                    }
                }
            }
            p += (unsigned long)step;
        }
    }
}

/* RiftTransformPdataAmd64: .pdata holds 12-byte RUNTIME_FUNCTION records
 * whose three dwords are RVAs into the image. */
static void pa30_transform_pdata_amd64(unsigned char *buf, unsigned long len,
                                       const RIFTENTRY *rt, unsigned rn,
                                       unsigned long sizeOfImage)
{
    unsigned long pe, opt, dd, er, es, off, end;
    if (len < 0x40) return;
    pe = rd32(buf + 0x3C);
    if (pe + 24 > len || memcmp(buf + pe, "PE\0\0", 4)) return;
    opt = pe + 24;
    if (rd16(buf + opt) != 0x20B) return;
    dd = PA30_DD(buf, opt);
    if (dd + 4 * 8 > len) return;
    er = rd32(buf + dd + 3 * 8);        /* Exception Table */
    es = rd32(buf + dd + 3 * 8 + 4);
    if (!er || es < 12) return;
    off = pa30_rva_off(buf, len, er);
    if (off == 0xFFFFFFFFUL || es > len - off) return;
    end = off + es - 12;
    for (; off <= end; off += 12)
    {
        unsigned k, uwOrig;
        uwOrig = rd32(buf + off + 8);
        for (k = 0; k < 3; ++k)
        {
            unsigned long v = rd32(buf + off + 4 * k);
            if (!v || v >= sizeOfImage) continue;
            pa30_set_u32(buf, off + 4 * k,
                         (unsigned long)pa30_map_rva(rt, rn, (long)v));
        }
        /* RiftTransformPdataAmd64 also remaps the exception-handler RVA that
         * follows the unwind codes when the UNWIND_INFO has an EH flag.  The
         * DLL locates UNWIND_INFO with the original, not yet mapped, RVA. */
        {
            unsigned long uw = uwOrig;
            if (uw && uw < sizeOfImage)
            {
                unsigned long uo = pa30_rva_off(buf, len, uw);
                if (uo != 0xFFFFFFFFUL && uo + 4 <= len &&
                    (buf[uo] & 0x38) != 0)
                {
                    unsigned long codes = buf[uo + 2];
                    unsigned long hop = 4 * ((codes + 1) >> 1) + 4;
                    if (uo + hop + 4 <= len)
                    {
                        unsigned long v = rd32(buf + uo + hop);
                        pa30_set_u32(buf, uo + hop,
                                     (unsigned long)pa30_map_rva(rt, rn,
                                                                 (long)v));
                    }
                }
            }
        }
    }
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
    if (!PA30_MAGIC_OK(rd16(buf + opt)) || opt + 0x50 > len) return;
    imp = rd32(buf + PA30_DD(buf, opt) + 8);   /* Import Table RVA (data dir 1) */
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
            if (rd16(buf + opt) != 0x20B)
            {
                /* UnbindPortableExecutable makes a section literally named
                 * ".idata" writable, but for a native CLR image whose imports
                 * live at the end of .text the DLL removes the upstream
                 * write bit instead. */
                int idata =
                    (buf[o] | 0x20) == '.' &&
                    (buf[o + 1] | 0x20) == 'i' &&
                    (buf[o + 2] | 0x20) == 'd' &&
                    (buf[o + 3] | 0x20) == 'a' &&
                    (buf[o + 4] | 0x20) == 't' &&
                    (buf[o + 5] | 0x20) == 'a' &&
                    (buf[o + 6] == 0 || buf[o + 6] == ' ') &&
                    (buf[o + 7] == 0 || buf[o + 7] == ' ');
                if (idata && !(ch & 0x80000000UL))
                    ch |= 0x80000000UL;
                else if (!idata && (ch & 0x80000000UL))
                    ch &= ~0x80000000UL;
            }
            buf[o + 36] = (unsigned char)(ch & 0xFF);
                buf[o + 37] = (unsigned char)((ch >> 8) & 0xFF);
                buf[o + 38] = (unsigned char)((ch >> 16) & 0xFF);
                buf[o + 39] = (unsigned char)((ch >> 24) & 0xFF);
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
    if (!PA30_MAGIC_OK(rd16(buf + opt)) || opt + 0x70 > len) return;
    imp = rd32(buf + PA30_DD(buf, opt) + 8);
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
            unsigned long width = (rd16(buf + opt) == 0x20B) ? 8 : 4;
            unsigned i;
            if (to == 0xFFFFFFFFUL) continue;
            for (i = 0; i < 4096 && to + width * (i + 1) <= len; ++i)
            {
                unsigned long at = to + width * i;
                unsigned long v = rd32(buf + at);
                unsigned long hi = (width == 8) ? rd32(buf + at + 4) : 0;
                if (!v && !hi) break;
                if (hi & 0x80000000UL) continue;    /* ordinal import */
                if (v && !(v & 0x80000000UL))
                    pa30_set_u32(buf, at,
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
                imp = rd32(buf + PA30_DD(buf, opt) + 8);
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
    if (!PA30_MAGIC_OK(rd16(buf + opt))) return;
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
    if (!PA30_MAGIC_OK(rd16(buf + opt)) || opt + 0x90 > len) return;
    er = rd32(buf + PA30_DD(buf, opt));
    es = rd32(buf + PA30_DD(buf, opt) + 4);
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
                                   unsigned long sizeOfImage,
                                   const unsigned char *orig)
{
    unsigned long pe, opt, sh, nsec, s;
    if (len < 0x40) return;
    pe = rd32(buf + 0x3C);
    if (pe + 24 > len || memcmp(buf + pe, "PE\0\0", 4)) return;
    opt = pe + 24;
    if (!PA30_MAGIC_OK(rd16(buf + opt))) return;
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
            if (buf[p] == 0x0F && p + 6 <= span &&
                (buf[p + 1] & 0xF0) == 0x80)
            {
                opLen = 6; hintAt = p + 1;
            }
            else if (buf[p] != 0xE9)
                continue;
            /* Do not treat an E9 / 0F8x byte that appeared inside a rewritten
             * E8 call's rel32 as an opcode: it was not a jump in the source
             * image, unlike a genuine jump at the same file offset. */
            if (buf[p] == 0xE9)
            {
                if (orig[p] != 0xE9) continue;
            }
            else if (orig[p] != 0x0F || (orig[p + 1] & 0xF0) != 0x80)
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
            if (to == 0xFFFFFFFFUL || to >= len) continue;
            mappedSite = (long)pa30_map_rva(rt, rn, (unsigned long)siteRVA);
            mappedTarget = (long)pa30_map_rva(rt, rn,
                                              (unsigned long)targetRVA);
            newrel = mappedTarget - mappedSite;
            if (newrel > 127 || newrel < -128)
            {
                /* Far jump: the DLL honours the target's hint bit. */
                if (hint && (hint[to] & 0x01)) continue;
                if (newrel != rel)
                    pa30_set_u32(buf, hintAt + 1, (unsigned long)newrel);
            }
            else if (newrel != rel)
            {
                /* RiftTransformRelativeJmpsI386 folds a jump whose mapped
                 * displacement fits in rel8 into a short jump (EB rel8 or
                 * 7x rel8), leaving the rest of the old 6-byte instruction
                 * untouched. */
                if (buf[p] == 0xE9)
                {
                    buf[p] = 0xEB;
                    buf[p + 1] = (unsigned char)newrel;
                }
                else
                {
                    unsigned char op2 = buf[hintAt];
                    buf[p] = (unsigned char)(0x70 | (op2 & 0x0F));
                    buf[hintAt] = (unsigned char)newrel;
                }
            }
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
    if (!PA30_MAGIC_OK(rd16(buf + opt)) || opt + 0x90 > len) return;
    rrva = rd32(buf + PA30_DD(buf, opt) + 2 * 8);      /* Resource directory */
    rsize = rd32(buf + PA30_DD(buf, opt) + 2 * 8 + 4);
    if (!rrva || !rsize) return;
    off = pa30_rva_off(buf, len, rrva);
    if (off == 0xFFFFFFFFUL || off + rsize > len) return;
    pa30_res_walk(buf, off, rsize, rrva, rt, rn, 0, 0);
}

static void pa30_transform_relocs(unsigned char *buf, unsigned long len,
                                  const RIFTENTRY *rt, unsigned rn,
                                  unsigned __int64 oldBase,
                                  unsigned __int64 newBase,
                                  unsigned long sizeOfImage)
{
    unsigned long pe, opt, rrva, rsize, off, end, n = 0, i, w, cap = 0;
    RELOC *rel;

    if (len < 0x40) return;
    pe = rd32(buf + 0x3C);
    if (pe + 24 > len || memcmp(buf + pe, "PE\0\0", 4)) return;
    opt = pe + 24;
    if (!PA30_MAGIC_OK(rd16(buf + opt)) || opt + 0x90 > len) return;
    rrva = rd32(buf + PA30_DD(buf, opt) + 5 * 8);      /* Base Relocation Table */
    rsize = rd32(buf + PA30_DD(buf, opt) + 5 * 8 + 4);
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
                unsigned long width = (type == 10) ? 8 : 4;
                if (fo != 0xFFFFFFFFUL && fo + width <= len)
                {
                    unsigned __int64 v = (type == 10) ? rd64(buf + fo) :
                                                       rd32(buf + fo);
                    if (v >= oldBase && v < oldBase + sizeOfImage)
                    {
                        unsigned __int64 nv =
                            (unsigned __int64)pa30_map_rva(rt, rn,
                                (unsigned long)(v - oldBase)) + newBase;
                        if (type == 10)
                        {
                            unsigned k;
                            for (k = 0; k < 8; ++k)
                                buf[fo + k] = (unsigned char)(nv >> (8 * k));
                        }
                        else
                            pa30_set_u32(buf, fo, (unsigned long)nv);
                    }
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

/* Index of the last entry with left <= x, or ~0u if there is none.  The
 * decompressor's rift lookup used to scan the whole table for every match;
 * CLI deltas grow that table from a handful of entries to nearly a thousand,
 * so use a binary search (the DLL's OffsetRiftTable does the same). */
static unsigned rift_find_index(const RIFTENTRY *rift, unsigned n, __int64 x)
{
    unsigned lo, hi, mid;
    if (!n || rift[0].left > x) return 0xFFFFFFFFU;
    lo = 0;
    hi = n - 1;
    while (lo < hi)
    {
        mid = (lo + hi + 1) >> 1;
        if (rift[mid].left <= x) lo = mid;
        else hi = mid - 1;
    }
    return lo;
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
    const char *symDbg = getenv("PA30_SYMDBG");
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


        if (symDbg && pos >= symLo && pos < symHi)
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
            unsigned ri, riFound;
            /* The DLL's OffsetRiftTable is keyed by the COMBINED position
             * (srcLen + output position), mapping it to a combined source
             * position.  Pick the entry with the largest left <= cpos. */
            cpos = (long)pos + (long)srcLen;
            /* An empty table means the implicit identity rift: the combined
             * position maps back to the output position (off = -srcLen). */
            riFound = rift_find_index(rift, riftN, cpos);
            ri = (riFound == 0xFFFFFFFFU) ? 0 : riFound + 1;
            riftOff = (riFound == 0xFFFFFFFFU)
                        ? -(long)srcLen
                        : (long)(rift[riFound].right - rift[riFound].left);
            if (sym.value == 0x54000UL && ri < riftN)
                riftLimit = (long)(rift[ri].left - cpos);

            if (sym.value == 0x54000UL)
            {
                unsigned long done = 0;
                unsigned curi, ci;
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

                    ci = rift_find_index(rift, riftN, cpos2);
                    curi = (ci == 0xFFFFFFFFU) ? 0 : ci + 1;
                    curOff = (ci == 0xFFFFFFFFU)
                            ? -(long)srcLen
                            : (long)(rift[ci].right - rift[ci].left);
                    limit = (curi < riftN) ? rift[curi].left - cpos2 : -1;
                    if (limit > 0 && limit < (long)chunk)
                        chunk = (unsigned long)limit;
                    sp = cpos2 + curOff;

                    if (symDbg && pos >= symLo && pos < symHi)
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
                if (symDbg && pos < 512)
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
                if (symDbg && (pos == 83697 || pos == 86119))
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

static unsigned __int64 rd64(const unsigned char *p)
{
    return (unsigned __int64)rd32(p) | ((unsigned __int64)rd32(p + 4) << 32);
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
    double tPhase = 0, tStart = 0;
    int doPhase = getenv("PA30_PHASE") != NULL;
    if (doPhase) tStart = (double)clock() / CLOCKS_PER_SEC;
#define PHASE(tag) if (doPhase) { double t = (double)clock()/CLOCKS_PER_SEC; \
    fprintf(stderr, "PHASE %s %.3f\n", tag, t - tPhase); fflush(stderr); tPhase = t; }

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
        CLIMETA cliSrc;
        CLIMETA cliTgt;
        CLIMAP cliMap;
        int cliMapOk = 0;

        memset(&cliSrc, 0, sizeof(cliSrc));
        memset(&cliTgt, 0, sizeof(cliTgt));
        memset(&cliMap, 0, sizeof(cliMap));
        cliSrc.empty = 1;
        cliTgt.empty = 1;

        /* The pre blob is bit-packed with the same 3-bit leader.  It holds
         * the target PE info, its RVA map, optional CLI metadata, the used
         * rift table, the CLI map, and the compression RIFT table used by
         * 0x54000 matches. */
        if (preLen > 16)
        {
            BITR pb;
            br_init(&pb, pre, preLen);
            {
                BITR ti = pb;
                unsigned long gp;
                peImageBase = br_read64(&ti);
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
                if (getenv("PA30_DEBUG")) fprintf(stderr,
                    "PRE rift1 n=%u at bit %lu\n", tmpN, pb.bitpos);
                cli_meta_from_bits(&cliTgt, &pb);
                if (getenv("PA30_DEBUG")) fprintf(stderr,
                    "PRE cli=%d at bit %lu\n", !cliTgt.empty, pb.bitpos);
                if (rift_read(&pb, &rt, &rn) == 0)
                {
                    if (getenv("PA30_DEBUG"))
                    {
                        unsigned qi;
                        fprintf(stderr, "PRE rift2(compression) n=%u at bit %lu\n",
                                rn, pb.bitpos);
                        for (qi = 0; qi < rn; ++qi)
                            fprintf(stderr, "  rt[%u] left=%I64d right=%I64d rift=%I64d\n",
                                    qi, rt[qi].left, rt[qi].right,
                                    rt[qi].right - rt[qi].left);
                    }
                    if (cli_map_read(&cliMap, &pb) == 0)
                        cliMapOk = 1;
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
            if (n0)
            {
                RIFTENTRY sh;
                unsigned k, w;

                /* Build this even for empty rifts: rift_multiply treats a
                 * missing table as identity, so the source PE section map
                 * alone still yields the DLL's offset rift (needed by
                 * deltas such as globalinstallorder.xml). */
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
                /* The DLL only reduces the *final* Sum table; dropping
                 * repeated rifts here is wrong because the CLI entries
                 * merged below can separate two same-rift entries. */
                w = 0;
                for (k = 0; k < n3; ++k)
                {
                    if (t3[k].left <= 0) continue;
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

        PHASE("pre");
        /* CLI work is only needed when the target pre blob actually carries
         * CLI metadata; skip the PE metadata parse and derivation otherwise. */
        if (!cliTgt.empty)
        {
            cli_meta_from_pe(&cliSrc, source, sourceLen);
            cli_meta_derive(&cliSrc);
            cli_meta_derive(&cliTgt);
        }

        PHASE("derive");
        /* Fold in the rift the CLI map induces.  The DLL builds
         * compressionRiftTable3 = Sum(compressionRiftTable2, cliMapCompression)
         * before the decompressor consumes it; the CLI entries are the finer
         * grained mapping of the metadata heaps and tables. */
        if (cliMapOk)
        {
            RIFTENTRY *cr = NULL;
            unsigned crn = 0;
            if (cli_compression_rift(&cr, &crn, &cliSrc, &cliTgt, &cliMap) == 0 &&
                crn)
            {
                unsigned total = oriftN + crn;
                RIFTENTRY *comb = (RIFTENTRY *)malloc(
                    (size_t)(total ? total : 1) * sizeof(*comb));
                RIFTENTRY *sortTmp = (RIFTENTRY *)malloc(
                    (size_t)(total ? total : 1) * sizeof(*sortTmp));
                if (comb && sortTmp)
                {
                    unsigned j, w, k;
                    /* Concatenate and sort stably by left, exactly like the
                     * DLL's Sum followed by its radix Sort.  On equal lefts
                     * the CLI entry comes later and wins the reduction. */
                    if (oriftN)
                        memcpy(comb, orift, (size_t)oriftN * sizeof(*comb));
                    for (j = 0; j < crn; ++j)
                    {
                        comb[oriftN + j].left = (__int64)sourceLen + cr[j].left;
                        comb[oriftN + j].right = cr[j].right;
                    }
                    rift_stable_sort(comb, total, sortTmp);
                    for (k = 0, w = 0; k < total; ++k)
                    {
                        if (comb[k].left <= 0) continue;
                        if (w && comb[w - 1].left == comb[k].left)
                        {
                            comb[w - 1] = comb[k];
                            continue;
                        }
                        if (w && (comb[w - 1].right - comb[w - 1].left) ==
                                 (comb[k].right - comb[k].left)) continue;
                        comb[w++] = comb[k];
                    }
                    free(sortTmp);
                    free(orift);
                    orift = comb;
                    oriftN = w;
                    if (getenv("PA30_DEBUG")) fprintf(stderr,
                        "CLIRIFT n=%u merged ORIFT n=%u\n", crn, oriftN);
                    if (getenv("PA30_ORMAP"))
                    {
                        unsigned q;
                        for (q = 0; q < oriftN; ++q)
                            fprintf(stderr, "  mo[%u] %I64d -> %I64d (rift %I64d)\n",
                                    q, orift[q].left, orift[q].right,
                                    orift[q].right - orift[q].left);
                    }
                }
            }
            free(cr);
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
        PHASE("orift");
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
                    /* Rebase the source PE to the target image.  PE32 stores
                     * a 32-bit ImageBase at +0x1C, PE32+ a 64-bit one at +0x18. */
                    {
                        unsigned short magic = rd16(prepared + lfa + 24);
                        unsigned __int64 oldBase;
                        unsigned long sizeOfImage, sizeOfHeaders;
                        if ((magic != 0x10B && magic != 0x20B) ||
                            lfa + 24 + 0x40 > sourceLen)
                            goto skip_transforms;
                        if (magic == 0x10B)
                            oldBase = rd32(prepared + lfa + 24 + 0x1C);
                        else
                            oldBase = rd64(prepared + lfa + 24 + 0x18);
                        sizeOfImage = rd32(prepared + lfa + 24 + 0x38);
                        sizeOfHeaders = rd32(prepared + lfa + 24 + 0x3C);
                        if (magic == 0x10B)
                        {
                            prepared[lfa + 24 + 0x1C] = (unsigned char)(peImageBase & 0xFF);
                            prepared[lfa + 24 + 0x1D] = (unsigned char)((peImageBase >> 8) & 0xFF);
                            prepared[lfa + 24 + 0x1E] = (unsigned char)((peImageBase >> 16) & 0xFF);
                            prepared[lfa + 24 + 0x1F] = (unsigned char)((peImageBase >> 24) & 0xFF);
                        }
                        else
                        {
                            unsigned k;
                            for (k = 0; k < 8; ++k)
                                prepared[lfa + 24 + 0x18 + k] =
                                    (unsigned char)(peImageBase >> (8 * k));
                        }
                        /* NormalizeCoffImage zeroes the PE checksum. */
                        memset(prepared + lfa + 24 + 0x40, 0, 4);
                        {
                            unsigned char *hintBuf =
                                (unsigned char *)malloc(sourceLen);
                            if (hintBuf)
                            {
                                memset(hintBuf, 0x02, sourceLen);
                                pa30_reloc_mask(prepared, sourceLen, hintBuf);
                                pa30_mark_nonexe(prepared, sourceLen, hintBuf);
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
                            /* CLI assemblies take the CLI transform only;
                             * native images get the disassembly/relocation
                             * pipeline.  The delta's file-type mnemonic picks
                             * between them. */
                            if (!cliSrc.empty)
                            {
                                CLIBLOBSET blobs;
                                memset(&blobs, 0, sizeof(blobs));
                                if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED cli shared\n");
                                PHASE("cli-pre-start");
                                pa30_transform_relocs(prepared, sourceLen, rt, rn,
                                    oldBase, peImageBase, sizeOfImage);
                                PHASE("cli-relocs");
                                pa30_transform_resources(prepared, sourceLen, rt, rn);
                                PHASE("cli-resources");
                                if (getenv("PA30_BLIND"))
                                    pa30_transform_rvas(prepared, sourceLen, rt, rn,
                                        sizeOfImage, sizeOfHeaders);
                                else
                                    pa30_rewrite_imports(prepared, sourceLen, rt, rn);
                                pa30_transform_exports(prepared, sourceLen, rt, rn);
                                PHASE("cli-imports-exports");
                                if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED cli disasm\n");
                                pa30_transform_cli_disasm(prepared, sourceLen,
                                                          &cliSrc, &cliMap);
                                PHASE("cli-disasm");
                                if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED cli metadata\n");
                                pa30_transform_cli_metadata(prepared, sourceLen,
                                                            &cliSrc, &cliTgt,
                                                            &cliMap, rt, rn,
                                                            &blobs);
                                pa30_transform_cli_blobs(prepared, sourceLen,
                                                         &cliSrc, &cliMap,
                                                         &blobs);
                                PHASE("cli-blobs");
                            }
                            else
                            {
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED pointers\n");
                            PHASE("nat-start");
                            pa30_transform_pointers(prepared, sourceLen, rt, rn,
                                oldBase, peImageBase,
                                sizeOfImage, sizeOfHeaders, hintBuf);
                            PHASE("nat-pointers");
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED amd64 rip\n");
                            pa30_transform_amd64_rip(prepared, sourceLen, rt, rn,
                                                     sizeOfImage, hintBuf);
                            PHASE("nat-amd64rip");
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED pdata\n");
                            pa30_transform_pdata_amd64(prepared, sourceLen, rt, rn,
                                                       sizeOfImage);
                            /* Even when the delta's target has no CLI
                             * metadata, a managed source image still needs
                             * its MethodDef RVA cells remapped; run the CLI
                             * metadata pass with the empty target/map. */
                            if (h.code == 2 && !(h.flags & 0x1))
                            {
                                CLIMETA nc;
                                CLIBLOBSET nb;
                                memset(&nc, 0, sizeof(nc));
                                memset(&nb, 0, sizeof(nb));
                                cli_meta_from_pe(&nc, source, sourceLen);
                                cli_meta_derive(&nc);
                                if (!nc.empty)
                                    pa30_transform_cli_metadata(prepared,
                                        sourceLen, &nc, &cliTgt, &cliMap,
                                        rt, rn, &nb);
                            }
                            PHASE("nat-pdata");
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED relocs\n");
                            pa30_transform_relocs(prepared, sourceLen, rt, rn,
                                oldBase, peImageBase,
                                sizeOfImage);
                            PHASE("nat-relocs");
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED resources\n");
                            pa30_transform_resources(prepared, sourceLen,
                                                     rt, rn);
                            PHASE("nat-resources");
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED markimports\n");
                            pa30_mark_import_section(prepared, sourceLen);
                            PHASE("nat-markimports");
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED imports\n");
                            if (getenv("PA30_BLIND"))
                                pa30_transform_rvas(prepared, sourceLen, rt, rn,
                                    sizeOfImage, sizeOfHeaders);
                            else
                                pa30_rewrite_imports(prepared, sourceLen,
                                                     rt, rn);
                            PHASE("nat-imports");
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED relcalls\n");
                            if (rd16(prepared + lfa + 24) == 0x10B)
                            pa30_transform_relcalls(prepared, sourceLen, rt,
                                                    rn, hintBuf, sizeOfImage);
                            PHASE("nat-relcalls");
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED reljmps\n");
                            if (rd16(prepared + lfa + 24) == 0x10B)
                            pa30_transform_reljmps(prepared, sourceLen, rt,
                                                   rn, hintBuf, sizeOfImage,
                                                   source);
                            PHASE("nat-reljmps");
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED exports\n");
                            pa30_transform_exports(prepared, sourceLen,
                                                   rt, rn);
                            }
                            if (getenv("PA30_DEBUG")) fprintf(stderr, "SEED done\n");
                            free(hintBuf);
                        }
                    }
                skip_transforms: ;
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
        PHASE("seed");
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
        PHASE("decomp");
        if (decompressSrc != source) free((void *)decompressSrc);
        cli_map_free(&cliMap);
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




