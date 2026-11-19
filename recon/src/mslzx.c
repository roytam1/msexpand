/*
 * mslzx.c -- C89 port of the patch engine's LZXD decoder.
 *
 * The 32-bit bit cache physically holds two live words of stream data,
 * Huffman lookups peek the top bits with NO pre-fill, and fillbuf() refills
 * only AFTER consuming a codeword when bitcount <= 0.  This is the bit-cache
 * contract both _sfx_.dll and mspatcha.dll implement; it differs from the
 * earlier wimlib-derived port, which prefilled before every symbol read.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "MsLzx.h"

typedef unsigned char  u8;
typedef signed char    s8;
typedef unsigned short u16;
typedef signed short   s16;
typedef unsigned int   u32;
typedef int            s32;

#define NUM_CHARS              256
#define NUM_PRIMARY_LENGTHS    7
#define NUM_LENGTHS            8
#define NL_SHIFT               3
#define MIN_MATCH              2
#define MAX_MATCH              257
#define NUM_SECONDARY_LENGTHS  249
#define ALIGNED_NUM_ELEMENTS   8
#define MAIN_TABLE_BITS        10
#define LEN_TABLE_BITS         8
#define ALIGNED_TABLE_BITS     7
#define DS_TABLE_BITS          8
#define NUM_DECODE_SMALL       20
#define TREE_ENC_REP_MIN                 4
#define TREE_ENC_REPZ_FIRST_EXTRA_BITS   4
#define TREE_ENC_REPZ_SECOND_EXTRA_BITS  5
#define TREE_ENC_REP_SAME_EXTRA_BITS     1
#define MAX_POS_SLOTS          290
#define MAX_MAIN_SYMS          (NUM_CHARS + MAX_POS_SLOTS * NUM_LENGTHS)
#define BLOCKTYPE_VERBATIM     1
#define BLOCKTYPE_ALIGNED      2
#define BLOCKTYPE_UNCOMPRESSED 3

/* ---------------------------- bit stream -------------------------------- */
struct bitstream {
    u32 bitbuf;          /* 32-bit window: consumed bits at top, live below */
    s32 bitcount;        /* number of consumable bits at the top */
    const u8 *next;
    const u8 *end;
    int error;
};

static u16 rd_le16(const u8 *p) { return (u16)(p[0] | ((u16)p[1] << 8)); }

static void bit_init(struct bitstream *b, const u8 *buf, unsigned long size)
{
    b->next = buf;
    b->end = buf + size;
    b->bitbuf = 0;
    b->bitcount = 0;
    b->error = 0;
}

/* Preload TWO words into the bit cache, count only the first as valid. */
static void bit_reinit(struct bitstream *b)
{
    const u8 *p;
    if (b->end - b->next < 4) return;
    p = b->next;
    b->bitbuf = (u32)p[2] | ((u32)p[3] << 8) |
                (((u32)p[0] | ((u32)p[1] << 8)) << 16);
    b->bitcount = 16;
    b->next += 4;
}

static void fillbuf(struct bitstream *b, int n)
{
    b->bitbuf <<= n;
    b->bitcount -= n;
    if (b->bitcount <= 0) {
        if (b->end - b->next < 2) { b->error = 1; return; }
        b->bitbuf |= (u32)rd_le16(b->next) << (-b->bitcount);
        b->next += 2;
        b->bitcount += 16;
        if (b->bitcount <= 0) {
            if (b->end - b->next < 2) { b->error = 1; return; }
            b->bitbuf |= (u32)rd_le16(b->next) << (-b->bitcount);
            b->next += 2;
            b->bitcount += 16;
        }
    }
}

static u32 getbits(struct bitstream *b, int n)
{
    u32 v;
    if (n == 0) return 0;
    v = b->bitbuf >> (32 - n);
    fillbuf(b, n);
    return v;
}

/* ---------------------- Huffman table construction ---------------------- */
/* Canonical-code table builder: short primary table with negative
 * subtable references into leftright[].  Returns 1 on success. */
static int make_table(int nchar, const u8 *bitlen, int tablebits,
                      s16 *table, s16 *leftright)
{
    unsigned count[17], weight[17], start[18];
    int avail, ch;
    unsigned i, nextcode, k;
    u8 len, jutbits;

    for (i = 1; i <= 16; ++i) count[i] = 0;
    for (i = 0; i < (unsigned)nchar; ++i) ++count[bitlen[i]];
    start[1] = 0;
    for (i = 1; i <= 16; ++i)
        start[i + 1] = start[i] + (count[i] << (16 - i));
    if (start[17] != 65536) {
        if (start[17] == 0) {
            memset(table, 0, (size_t)2 << tablebits);
            return 1;
        }
        return 0;
    }
    jutbits = (u8)(16 - tablebits);
    for (i = 1; i <= (unsigned)tablebits; ++i) {
        start[i] >>= jutbits;
        weight[i] = 1U << (tablebits - i);
    }
    while (i <= 16) { weight[i] = 1U << (16 - i); ++i; }
    i = start[tablebits + 1] >> jutbits;
    if (i != 65536)
        memset(&table[i], 0, (size_t)2 * ((1U << tablebits) - i));
    avail = nchar;
    for (ch = 0; ch < nchar; ++ch) {
        s16 *p;
        if (!(len = bitlen[ch])) continue;
        nextcode = start[len] + weight[len];
        if (len <= tablebits) {
            if (nextcode > (1U << tablebits)) return 0;
            for (i = start[len]; i < nextcode; ++i) table[i] = (s16)ch;
            start[len] = nextcode;
        } else {
            int bi;
            k = start[len];
            start[len] = nextcode;
            p = &table[k >> jutbits];
            bi = len - tablebits;
            k <<= tablebits;
            do {
                if (*p == 0) {
                    leftright[avail * 2] = leftright[avail * 2 + 1] = 0;
                    *p = (s16)-avail;
                    ++avail;
                }
                if ((s16)k < 0) p = &leftright[-(*p) * 2 + 1];
                else            p = &leftright[-(*p) * 2];
                k <<= 1;
                --bi;
            } while (bi);
            *p = (s16)ch;
        }
    }
    return 1;
}

/* Specialised builder for the 7-bit aligned-symbol byte table. */
static int make_table_8bit(const u8 *bitlen, u8 *table)
{
    u16 count[17], weight[17], start[18];
    u16 i, nextcode;
    u8 len, ch;
    for (i = 1; i <= 16; ++i) count[i] = 0;
    for (i = 0; i < 8; ++i) ++count[bitlen[i]];
    start[1] = 0;
    for (i = 1; i <= 16; ++i)
        start[i + 1] = start[i] + (count[i] << (16 - i));
    if (start[17] != 0) return 0;
    for (i = 1; i <= 7; ++i) {
        start[i] >>= 9;
        weight[i] = 1U << (7 - i);
    }
    while (i <= 16) { weight[i] = 1U << (16 - i); ++i; }
    memset(table, 0, 1 << 7);
    for (ch = 0; ch < 8; ++ch) {
        if (!(len = bitlen[ch])) continue;
        nextcode = start[len] + weight[len];
        if (nextcode > (1 << 7)) return 0;
        for (i = start[len]; i < nextcode; ++i) table[i] = ch;
        start[len] = nextcode;
    }
    return 1;
}

/* Huffman lookup: peek top tablebits, walk subtable, then fillbuf(len). */
static int decode_huff(struct bitstream *b, const s16 *table, const s16 *lr,
                       const u8 *lens, int tablebits)
{
    int j = table[b->bitbuf >> (32 - tablebits)];
    if (j < 0) {
        u32 mask = 1UL << (31 - tablebits);
        do {
            j = -j;
            if (b->bitbuf & mask) j = lr[2 * j + 1];
            else                  j = lr[2 * j];
            mask >>= 1;
        } while (j < 0);
    }
    fillbuf(b, lens[j]);
    return j;
}

/* --------------------------- decoder state ------------------------------ */
struct state {
    struct bitstream bs;
    u8  main_len[MAX_MAIN_SYMS];
    u8  main_prev[MAX_MAIN_SYMS];
    s16 main_table[1 << MAIN_TABLE_BITS];
    s16 main_lr[2 * (2 * MAX_MAIN_SYMS - 1)];
    u8  len_len[NUM_SECONDARY_LENGTHS];
    u8  len_prev[NUM_SECONDARY_LENGTHS];
    s16 len_table[1 << LEN_TABLE_BITS];
    s16 len_lr[2 * (2 * NUM_SECONDARY_LENGTHS - 1)];
    u8  aligned_table[1 << ALIGNED_TABLE_BITS];
    u8  aligned_len[ALIGNED_NUM_ELEMENTS];
    u32 slot_base[MAX_POS_SLOTS + 1];
    u8  extra_bits[MAX_POS_SLOTS];
    u32 reps[3];                 /* LRU repeated offsets, persist across blocks */
    int window_bits;
    u32 window_size;
    u32 window_mask;
};

static void make_slot_tables(struct state *st)
{
    u32 base = 0;
    int i;
    static const u8 eb[MAX_POS_SLOTS] = {
        0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,
        9,9,10,10,11,11,12,12,13,13,14,14,15,15,16,16
        /* remainder filled below */
    };
    for (i = 0; i < MAX_POS_SLOTS; ++i)
        st->extra_bits[i] = (u8)((i >= 36) ? 17 : eb[i]);
    for (i = 0; i <= MAX_POS_SLOTS; ++i) {
        st->slot_base[i] = base;
        if (i < 4) base += 1;
        else if (i < 36) base += 1U << (i / 2 - 1);
        else base += 1U << 17;
    }
}

static int num_main_syms(struct state *st)
{
    u32 maxoff = st->window_size - MIN_MATCH - 1;
    int n = 30;
    while (maxoff >= st->slot_base[n] && n < MAX_POS_SLOTS) ++n;
    return NUM_CHARS + n * NUM_LENGTHS;
}

/* -------------------------- ReadRepTree --------------------------------- */
static int read_rep_tree(struct bitstream *b, int num_elements,
                         const u8 *lastlen, u8 *len)
{
    u8 small_bitlen[NUM_DECODE_SMALL];
    s16 small_table[1 << DS_TABLE_BITS];
    s16 leftright_s[2 * (2 * NUM_DECODE_SMALL - 1)];
    static const u8 mod17[34] = {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
    };
    int i, consecutive, temp;
    u8 value;

    for (i = 0; i < NUM_DECODE_SMALL; ++i)
        small_bitlen[i] = (u8)getbits(b, 4);
    if (b->error) return 0;
    if (!make_table(NUM_DECODE_SMALL, small_bitlen, DS_TABLE_BITS,
                    small_table, leftright_s)) return 0;

    for (i = 0; i < num_elements; ++i) {
        temp = decode_huff(b, small_table, leftright_s, small_bitlen,
                           DS_TABLE_BITS);
        if (b->error) return 0;
        if (temp == 17) {
            consecutive = (u8)getbits(b, TREE_ENC_REPZ_FIRST_EXTRA_BITS);
            consecutive += TREE_ENC_REP_MIN;
            if (i + consecutive >= num_elements) consecutive = num_elements - i;
            while (consecutive-- > 0) len[i++] = 0;
            --i;
        } else if (temp == 18) {
            consecutive = (u8)getbits(b, TREE_ENC_REPZ_SECOND_EXTRA_BITS);
            consecutive += TREE_ENC_REP_MIN + 16;
            if (i + consecutive >= num_elements) consecutive = num_elements - i;
            while (consecutive-- > 0) len[i++] = 0;
            --i;
        } else if (temp == 19) {
            consecutive = (u8)getbits(b, TREE_ENC_REP_SAME_EXTRA_BITS);
            consecutive += TREE_ENC_REP_MIN;
            if (i + consecutive >= num_elements) consecutive = num_elements - i;
            temp = decode_huff(b, small_table, leftright_s, small_bitlen,
                               DS_TABLE_BITS);
            value = mod17[(lastlen[i] - temp) + 17];
            while (consecutive-- > 0) len[i++] = value;
            --i;
        } else {
            len[i] = mod17[(lastlen[i] - temp) + 17];
        }
    }
    return !b->error;
}

static int read_trees(struct state *st)
{
    int nmain, i;
    struct bitstream *b = &st->bs;
    nmain = num_main_syms(st);
    if (!read_rep_tree(b, NUM_CHARS, st->main_prev, st->main_len)) return 0;
    for (i = NUM_CHARS; i < nmain; ++i) st->main_prev[i] = 0;
    if (!read_rep_tree(b, nmain - NUM_CHARS, st->main_prev + NUM_CHARS,
                       st->main_len + NUM_CHARS)) return 0;
    if (!make_table(nmain, st->main_len, MAIN_TABLE_BITS,
                    st->main_table, st->main_lr)) return 0;
    if (!read_rep_tree(b, NUM_SECONDARY_LENGTHS, st->len_prev,
                       st->len_len)) return 0;
    if (!make_table(NUM_SECONDARY_LENGTHS, st->len_len, LEN_TABLE_BITS,
                    st->len_table, st->len_lr)) return 0;
    return 1;
}

static int read_aligned_tree(struct state *st)
{
    int i;
    for (i = 0; i < 8; ++i)
        st->aligned_len[i] = (u8)getbits(&st->bs, 3);
    return st->bs.error ? 0 : make_table_8bit(st->aligned_len, st->aligned_table);
}

/* --------------------- block decoding (verbatim/aligned) ---------------- */
static int decode_block(struct state *st, int block_type, u8 *window,
                        u32 bufpos, u32 amount, u32 e8base, int e8present)
{
    struct bitstream *b = &st->bs;
    u32 end = bufpos + amount;
    u32 *reps = st->reps;        /* persist across blocks and chunks */
    (void)e8base;
    (void)e8present;

    while (bufpos < end) {
        int c, match_length, m;
        u32 match_pos, temp_pos;

        c = decode_huff(b, st->main_table, st->main_lr, st->main_len,
                        MAIN_TABLE_BITS);
        if ((c -= NUM_CHARS) < 0) {
            window[bufpos & st->window_mask] = (u8)c;
            window[(bufpos + st->window_size) & st->window_mask] = (u8)c;
            ++bufpos;
            continue;
        }
        match_length = c & NUM_PRIMARY_LENGTHS;
        if (match_length == NUM_PRIMARY_LENGTHS)
            match_length += decode_huff(b, st->len_table, st->len_lr,
                                        st->len_len, LEN_TABLE_BITS);
        m = c >> NL_SHIFT;

        if (m > 2) {
            if (block_type == BLOCKTYPE_ALIGNED) {
                if (st->extra_bits[m] >= 3) {
                    if (st->extra_bits[m] - 3)
                        temp_pos = getbits(b, st->extra_bits[m] - 3);
                    else
                        temp_pos = 0;
                    match_pos = st->slot_base[m] - 2 + (temp_pos << 3);
                    temp_pos = st->aligned_table[b->bitbuf >> (32 - ALIGNED_TABLE_BITS)];
                    fillbuf(b, st->aligned_len[temp_pos]);
                    match_pos += temp_pos;
                } else {
                    if (st->extra_bits[m])
                        match_pos = getbits(b, st->extra_bits[m]) + st->slot_base[m] - 2;
                    else
                        match_pos = 1;
                }
            } else {
                /* verbatim: full extra bits, no aligned symbol */
                if (m > 3)
                    match_pos = getbits(b, st->extra_bits[m]) + st->slot_base[m] - 2;
                else
                    match_pos = 1;
            }
            reps[2] = reps[1]; reps[1] = reps[0]; reps[0] = match_pos;
        } else {
            match_pos = reps[m];
            if (m) { reps[m] = reps[0]; reps[0] = match_pos; }
        }
        match_length += MIN_MATCH;
        if (match_length == MAX_MATCH) {
            u32 x = getbits(b, 9);
            if (!(x & 0x100)) match_length += x;
            else if (!(x & 0x80)) match_length += ((x & 0x7F) << 3) + getbits(b, 3) + 256;
            else if (x & 0x40) match_length += (((x & 0x3F) << 9) | getbits(b, 9));
            else match_length += (((x & 0x3F) << 6) | getbits(b, 6)) + 1280;
        }
        do {
            window[bufpos & st->window_mask] =
                window[(bufpos - match_pos) & st->window_mask];
            window[(bufpos + st->window_size) & st->window_mask] =
                window[bufpos & st->window_mask];
            ++bufpos;
        } while (--match_length > 0);
    }
    return (int)(bufpos - (end - amount));
}

/* --------------------------- top level ---------------------------------- */
int MsLzxDecompressSeededMulti(const unsigned char *const *chunks,
                               const unsigned long *sizes, unsigned long nchunks,
                               unsigned char *out, unsigned long outLen,
                               int windowBits, const unsigned char *seed,
                               unsigned long seedLen)
{
    struct state *st;
    u8 *window;
    unsigned long ci;
    u32 produced = 0;
    int block_type = 0;
    u32 block_remaining = 0;
    int need_header = 1;
    int e8present = 0;
    u32 e8base = 0;
    int result = -1;
    u32 first_chunk = 1;

    if (!chunks || !sizes || !out || !outLen || !nchunks) return -1;
    if (windowBits < 15 || windowBits > 25) return -1;
    if (seedLen > (1UL << windowBits)) return -1;

    st = (struct state *)calloc(1, sizeof(*st));
    window = (u8 *)calloc((size_t)1 << windowBits, 1);
    if (!st || !window) { free(st); free(window); return -1; }
    if (seed && seedLen)
        memcpy(window + ((size_t)1 << windowBits) - seedLen, seed, seedLen);

    st->window_bits = windowBits;
    st->window_size = 1UL << windowBits;
    st->window_mask = st->window_size - 1;
    st->reps[0] = st->reps[1] = st->reps[2] = 1;
    make_slot_tables(st);

    for (ci = 0; ci < nchunks && produced < outLen; ++ci) {
        u32 request = outLen - produced;
        u32 chunk_end;
        if (request > 0x8000) request = 0x8000;
        chunk_end = produced + request;
        bit_init(&st->bs, chunks[ci], sizes[ci]);
        bit_reinit(&st->bs);

        if (first_chunk) {
            first_chunk = 0;
            e8present = (int)getbits(&st->bs, 1);
            if (e8present) {
                u32 lo = getbits(&st->bs, 16);
                u32 hi = getbits(&st->bs, 16);
                e8base = (hi << 16) | lo;
            }
        }

        while (produced < chunk_end) {
            if (need_header) {
                block_type = (int)getbits(&st->bs, 3);
                block_remaining = (getbits(&st->bs, 8) << 16) |
                                  (getbits(&st->bs, 8) << 8) |
                                   getbits(&st->bs, 8);
                if (block_remaining == 0) goto done;
                if (block_type == BLOCKTYPE_ALIGNED) {
                    if (!read_aligned_tree(st)) goto done;
                }
                if (block_type == BLOCKTYPE_VERBATIM ||
                    block_type == BLOCKTYPE_ALIGNED) {
                    if (!read_trees(st)) goto done;
                } else if (block_type == BLOCKTYPE_UNCOMPRESSED) {
                    goto done;
                } else goto done;
                need_header = 0;
            }
            {
                u32 n = block_remaining;
                u32 made;
                if (n > chunk_end - produced) n = chunk_end - produced;
                made = (u32)decode_block(st, block_type, window, produced, n,
                                         e8base, e8present);
                if (made == 0) goto done;
                produced += made;
                block_remaining -= made;
                if (block_remaining == 0) need_header = 1;
            }
        }
    }
    if (produced < outLen) goto done;

    /* E8 x86 call-target translation */
    if (e8present && outLen > 10) {
        u32 limit = outLen;
        u32 i = 0;
        while (i < limit) {
            u32 end = i + 32768 - 10;
            if (end > limit) end = limit;
            for (; i < end; ++i) {
                if (window[i] == 0xE8) {
                    u32 v = window[i+1] | ((u32)window[i+2] << 8) |
                            ((u32)window[i+3] << 16) | ((u32)window[i+4] << 24);
                    if ((s32)v >= -(s32)i && v < e8base) {
                        u32 d = (v >= i) ? v - i : v + e8base;
                        window[i+1] = (u8)d;
                        window[i+2] = (u8)(d >> 8);
                        window[i+3] = (u8)(d >> 16);
                        window[i+4] = (u8)(d >> 24);
                    }
                    i += 4;
                }
            }
            i += 10;
        }
    }
    memcpy(out, window, (size_t)outLen);
    result = 0;
done:
    free(st);
    free(window);
    return result;
}

int MsLzxRawDecompress(const unsigned char *in, unsigned long inLen,
                       unsigned char *out, unsigned long outLen, int windowBits)
{
    return -1;  /* not needed for this experiment */
}

int MsLzxDecompressSeeded(const unsigned char *in, unsigned long inLen,
                          unsigned char *out, unsigned long outLen,
                          int windowBits, const unsigned char *seed,
                          unsigned long seedLen)
{
    return -1;  /* not needed for this experiment */
}
