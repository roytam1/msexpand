/*
 * MsLzx.c -- C89/MSVC6 port of the MsLzx raw decompressor from wimlib 1.14.5.
 *
 * Reference: wimlib-1.14.5/src/MSLZX_decompress.c (LGPL-2.1+),
 *            wimlib-1.14.5/src/MSLZX_common.c    (LGPL-2.1+),
 *            wimlib-1.14.5/src/decompress_common.c (MIT, Huffman helpers).
 *
 * Ported for the standalone expand.exe reconstruction.  No wimlib headers
 * or runtime dependencies are needed; only <string.h>/<stdlib.h> are used.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "MsLzx.h"

typedef unsigned char       u8;
typedef signed char         s8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef int                 s32;

/* ------------------------------ constants ------------------------------ */
#define MSLZX_NUM_CHARS                  256
#define MSLZX_MIN_MATCH_LEN              2
#define MSLZX_NUM_PRIMARY_LENS           7
#define MSLZX_NUM_LEN_HEADERS            (MSLZX_NUM_PRIMARY_LENS + 1)
#define MSLZX_LENCODE_NUM_SYMBOLS        249

#define MSLZX_BLOCKTYPE_VERBATIM         1
#define MSLZX_BLOCKTYPE_ALIGNED          2
#define MSLZX_BLOCKTYPE_UNCOMPRESSED     3

#define MSLZX_MIN_WINDOW_ORDER           15
#define MSLZX_MAX_WINDOW_ORDER           25
#define MSLZX_MAX_OFFSET_SLOTS           290
#define MSLZX_MAINCODE_MAX_NUM_SYMBOLS   (MSLZX_NUM_CHARS + MSLZX_MAX_OFFSET_SLOTS * MSLZX_NUM_LEN_HEADERS)
#define MSLZX_PRECODE_NUM_SYMBOLS        20
#define MSLZX_PRECODE_ELEMENT_SIZE       4
#define MSLZX_NUM_ALIGNED_OFFSET_BITS    3
#define MSLZX_ALIGNEDCODE_NUM_SYMBOLS    (1 << MSLZX_NUM_ALIGNED_OFFSET_BITS)
#define MSLZX_ALIGNEDCODE_ELEMENT_SIZE   3
#define MSLZX_MIN_ALIGNED_OFFSET_SLOT    8

#define MSLZX_MAX_MAIN_CODEWORD_LEN      16
#define MSLZX_MAX_LEN_CODEWORD_LEN       16
#define MSLZX_MAX_PRE_CODEWORD_LEN       ((1 << MSLZX_PRECODE_ELEMENT_SIZE) - 1)
#define MSLZX_MAX_ALIGNED_CODEWORD_LEN   ((1 << MSLZX_ALIGNEDCODE_ELEMENT_SIZE) - 1)

#define MSLZX_DEFAULT_BLOCK_SIZE         32768
#define MSLZX_NUM_RECENT_OFFSETS         3
#define MSLZX_READ_LENS_MAX_OVERRUN      50

#define MSLZX_MAINCODE_TABLEBITS         11
#define MSLZX_LENCODE_TABLEBITS          9
#define MSLZX_PRECODE_TABLEBITS          6
#define MSLZX_ALIGNEDCODE_TABLEBITS      7

/* Decode table capacities (zlib 'enough' values from wimlib). */
#define SZ_MAIN     16384  /* up to 2576 syms, 11 table bits, max len 16 */
#define SZ_LEN       878   /* 249 syms,  9 table bits, max len 16 */
#define SZ_PRE       582   /*  20 syms,  6 table bits, max len 15 */
#define SZ_ALIGNED   128   /*   8 syms,  7 table bits, max len  7 */
#define SZ_WORKING   2620  /* 2*(16+1) + 2576 */

/* --------------------------- decode table entry ------------------------- */
#define DECODE_TABLE_SYMBOL_SHIFT      4
#define DECODE_TABLE_LENGTH_MASK       0xF
#define MAKE_DECODE_TABLE_ENTRY(sym, len) \
    (((unsigned)(sym) << DECODE_TABLE_SYMBOL_SHIFT) | (unsigned)(len))

/* --------------------------- offset slot tables ------------------------- */
/* offset slot => first match offset using that slot (includes extra entry). */
/* mspatcha's position bases (MP_POS_minus2 + 2): generated at startup.
 * base[0..3] = 0,1,2,3; base[4..35] advance by 1<<(i/2-1);
 * base[36..] advance by 1<<17. */
static u32 MSLZX_offset_slot_base[MSLZX_MAX_OFFSET_SLOTS + 1];
static int MSLZX_slot_base_ready = 0;
static unsigned MSLZX_window_order_g = 15;
static u8 *out_end_global;
static const u8 *multi_chunk_limit;   /* non-NULL while decoding one LZXD chunk */
static u32 last_produced;             /* bytes written by last block call */

static void MSLZX_make_slot_bases(void)
{
    u32 base = 0;
    int i;
    if (MSLZX_slot_base_ready)
        return;
    for (i = 0; i <= MSLZX_MAX_OFFSET_SLOTS; ++i)
    {
        MSLZX_offset_slot_base[i] = base;
        if (i < 4)
            base += 1;
        else if (i < 36)
            base += 1UL << (i / 2 - 1);
        else
            base += 1UL << 17;
    }
    MSLZX_slot_base_ready = 1;
}

/* offset slot => number of extra bits (verbatim/compressed blocks). */
static const u8 MSLZX_extra_offset_bits[MSLZX_MAX_OFFSET_SLOTS] = {
     0,  0,  0,  0,  1,  1,  2,  2,  3,  3, 
     4,  4,  5,  5,  6,  6,  7,  7,  8,  8, 
     9,  9, 10, 10, 11, 11, 12, 12, 13, 13, 
    14, 14, 15, 15, 16, 16, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 
};

/* --------------------------- little-endian helpers ---------------------- */
static u16 rd_le16(const u8 *p)
{
    return (u16)(p[0] | ((u16)p[1] << 8));
}

static u32 rd_le32(const u8 *p)
{
    return (u32)p[0] | ((u32)p[1] << 8) |
           ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static void wr_le32(u8 *p, u32 v)
{
    p[0] = (u8)v;
    p[1] = (u8)(v >> 8);
    p[2] = (u8)(v >> 16);
    p[3] = (u8)(v >> 24);
}

/* --------------------------- input bitstream ---------------------------- */
/* Bits are stored little-endian 16-bit units, MSB of each unit first.
 * The next bit is always bit 31 of bitbuf. */
struct input_bitstream {
    u32 bitbuf;
    u32 bitsleft;
    const u8 *next;
    const u8 *end;
    int exhausted;              /* set when no whole input words remain */
};

static void init_input_bitstream(struct input_bitstream *is,
                                 const u8 *buffer, unsigned long size)
{
    is->bitbuf = 0;
    is->bitsleft = 0;
    is->next = buffer;
    is->end = buffer + size;
    is->exhausted = 0;
}

static void bitstream_ensure_bits(struct input_bitstream *is, unsigned num_bits)
{
    if (is->bitsleft >= num_bits)
        return;
    if (is->end - is->next < 2) {
        is->bitsleft = 32;
        is->exhausted = 1;
        return;
    }
    is->bitbuf |= (u32)rd_le16(is->next) << (16 - is->bitsleft);
    is->next += 2;
    is->bitsleft += 16;
    if (num_bits == 17 && is->bitsleft == 16) {
        if (is->end - is->next < 2) {
            is->bitsleft = 32;
            is->exhausted = 1;
            return;
        }
        is->bitbuf |= (u32)rd_le16(is->next);
        is->next += 2;
        is->bitsleft = 32;
    }
}

static u32 bitstream_peek_bits(const struct input_bitstream *is,
                               unsigned num_bits)
{
    return (is->bitbuf >> 1) >> (sizeof(is->bitbuf) * 8 - num_bits - 1);
}

static void bitstream_remove_bits(struct input_bitstream *is, unsigned num_bits)
{
    is->bitbuf <<= num_bits;
    is->bitsleft -= num_bits;
}

static u32 bitstream_pop_bits(struct input_bitstream *is, unsigned num_bits)
{
    u32 bits = bitstream_peek_bits(is, num_bits);
    bitstream_remove_bits(is, num_bits);
    return bits;
}

static u32 bitstream_read_bits(struct input_bitstream *is, unsigned num_bits)
{
    bitstream_ensure_bits(is, num_bits);
    return bitstream_pop_bits(is, num_bits);
}

static u8 bitstream_read_byte(struct input_bitstream *is)
{
    if (is->end == is->next)
        return 0;
    return *is->next++;
}

static u32 bitstream_read_u32(struct input_bitstream *is)
{
    u32 v;
    if (is->end - is->next < 4)
        return 0;
    v = rd_le32(is->next);
    is->next += 4;
    return v;
}

static int bitstream_read_bytes(struct input_bitstream *is, void *dst,
                                unsigned long count)
{
    if ((unsigned long)(is->end - is->next) < count)
        return -1;
    memcpy(dst, is->next, (size_t)count);
    is->next += count;
    return 0;
}

static void bitstream_align(struct input_bitstream *is)
{
    is->bitsleft = 0;
    is->bitbuf = 0;
}

/* --------------------------- Huffman decode table ----------------------- */
/* Build a canonical-Huffman decode table from the codeword lengths in lens.
 * Returns 0 on success, -1 if the lengths are invalid. */
static int make_huffman_decode_table(u16 *decode_table, unsigned num_syms,
                                     unsigned table_bits, const u8 *lens,
                                     unsigned max_codeword_len,
                                     u16 *working_space)
{
    u16 *len_counts = &working_space[0];
    u16 *offsets = &working_space[1 * (max_codeword_len + 1)];
    u16 *sorted_syms = &working_space[2 * (max_codeword_len + 1)];
    s32 remainder = 1;
    unsigned char *entry_ptr = (unsigned char *)decode_table;
    unsigned codeword_len = 1;
    unsigned sym_idx, codeword, subtable_pos, subtable_bits, subtable_prefix;
    unsigned len, sym;

    for (len = 0; len <= max_codeword_len; ++len)
        len_counts[len] = 0;
    for (sym = 0; sym < num_syms; ++sym)
        ++len_counts[lens[sym]];
    for (len = 1; len <= max_codeword_len; ++len) {
        remainder = (remainder << 1) - len_counts[len];
        if (remainder < 0)
            return -1;
    }
    if (remainder != 0) {
        if (remainder != (s32)(1U << max_codeword_len))
            return -1;
        memset(decode_table, 0, (size_t)2 << table_bits);
        return 0;
    }

    offsets[0] = 0;
    for (len = 0; len < max_codeword_len; ++len)
        offsets[len + 1] = offsets[len] + len_counts[len];
    for (sym = 0; sym < num_syms; ++sym)
        sorted_syms[offsets[lens[sym]]++] = (u16)sym;

    sym_idx = offsets[0];
    {
        unsigned stores_per_loop = 1U << (table_bits - codeword_len);
        while (stores_per_loop != 0) {
            unsigned end_sym_idx = sym_idx + len_counts[codeword_len];
            for (; sym_idx < end_sym_idx; ++sym_idx) {
                u16 v = (u16)MAKE_DECODE_TABLE_ENTRY(sorted_syms[sym_idx],
                                                     codeword_len);
                unsigned n = stores_per_loop;
                do {
                    *(u16 *)entry_ptr = v;
                    entry_ptr += sizeof(v);
                } while (--n);
            }
            ++codeword_len;
            stores_per_loop >>= 1;
        }
    }

    if (sym_idx == num_syms)
        return 0;

    codeword = ((u16 *)entry_ptr - decode_table) << 1;
    subtable_pos = 1U << table_bits;
    subtable_bits = table_bits;
    subtable_prefix = (unsigned)-1;
    do {
        while (len_counts[codeword_len] == 0) {
            ++codeword_len;
            codeword <<= 1;
        }
        {
            unsigned prefix = codeword >> (codeword_len - table_bits);
            if (prefix != subtable_prefix) {
                subtable_prefix = prefix;
                subtable_bits = codeword_len - table_bits;
                remainder = (s32)1 << subtable_bits;
                for (;;) {
                    remainder -= len_counts[table_bits + subtable_bits];
                    if (remainder <= 0)
                        break;
                    ++subtable_bits;
                    remainder <<= 1;
                }
                decode_table[subtable_prefix] = (u16)MAKE_DECODE_TABLE_ENTRY(
                    subtable_pos, subtable_bits);
            }
            {
                u16 v = (u16)MAKE_DECODE_TABLE_ENTRY(
                    sorted_syms[sym_idx], codeword_len - table_bits);
                unsigned n = 1U << (subtable_bits -
                                    (codeword_len - table_bits));
                do { decode_table[subtable_pos++] = v; } while (--n);
            }
            --len_counts[codeword_len];
            ++codeword;
        }
    } while (++sym_idx < num_syms);
    return 0;
}

/* Read one Huffman symbol from the bitstream using the given table. */
static unsigned read_huffsym(struct input_bitstream *is, const u16 *decode_table,
                             unsigned table_bits, unsigned max_codeword_len)
{
    unsigned entry, symbol, length;

    bitstream_ensure_bits(is, max_codeword_len);
    entry = decode_table[bitstream_peek_bits(is, table_bits)];
    symbol = entry >> DECODE_TABLE_SYMBOL_SHIFT;
    length = entry & DECODE_TABLE_LENGTH_MASK;
    if (max_codeword_len > table_bits &&
        entry >= (1U << (table_bits + DECODE_TABLE_SYMBOL_SHIFT)))
    {
        bitstream_remove_bits(is, table_bits);
        entry = decode_table[symbol + bitstream_peek_bits(is, length)];
        symbol = entry >> DECODE_TABLE_SYMBOL_SHIFT;
        length = entry & DECODE_TABLE_LENGTH_MASK;
    }
    bitstream_remove_bits(is, length);
    return symbol;
}

/* --------------------------- decompressor state ------------------------- */
struct MSLZX_decompressor {
    u16 maincode_decode_table[SZ_MAIN];
    u8 maincode_lens[MSLZX_MAINCODE_MAX_NUM_SYMBOLS + MSLZX_READ_LENS_MAX_OVERRUN];

    u16 lencode_decode_table[SZ_LEN];
    u8 lencode_lens[MSLZX_LENCODE_NUM_SYMBOLS + MSLZX_READ_LENS_MAX_OVERRUN];

    u16 alignedcode_decode_table[SZ_ALIGNED];
    u8 alignedcode_lens[MSLZX_ALIGNEDCODE_NUM_SYMBOLS];

    u16 precode_decode_table[SZ_PRE];
    u8 precode_lens[MSLZX_PRECODE_NUM_SYMBOLS];

    u8 extra_offset_bits[MSLZX_MAX_OFFSET_SLOTS];
    u8 extra_offset_bits_minus_aligned[MSLZX_MAX_OFFSET_SLOTS];

    u16 working[SZ_WORKING];

    unsigned window_order;
    u32 e8_base;
    unsigned block_count;
    unsigned num_main_syms;
};

static unsigned read_presym(const struct MSLZX_decompressor *d,
                            struct input_bitstream *is)
{
    return read_huffsym(is, d->precode_decode_table,
                        MSLZX_PRECODE_TABLEBITS, MSLZX_MAX_PRE_CODEWORD_LEN);
}

static unsigned read_mainsym(const struct MSLZX_decompressor *d,
                             struct input_bitstream *is)
{
    return read_huffsym(is, d->maincode_decode_table,
                        MSLZX_MAINCODE_TABLEBITS, MSLZX_MAX_MAIN_CODEWORD_LEN);
}

static unsigned read_lensym(const struct MSLZX_decompressor *d,
                            struct input_bitstream *is)
{
    return read_huffsym(is, d->lencode_decode_table,
                        MSLZX_LENCODE_TABLEBITS, MSLZX_MAX_LEN_CODEWORD_LEN);
}

static unsigned read_alignedsym(const struct MSLZX_decompressor *d,
                                struct input_bitstream *is)
{
    return read_huffsym(is, d->alignedcode_decode_table,
                        MSLZX_ALIGNEDCODE_TABLEBITS, MSLZX_MAX_ALIGNED_CODEWORD_LEN);
}

/* Read a precode, then decode num_lens delta-encoded codeword lengths. */
static int MSLZX_read_codeword_lens(struct MSLZX_decompressor *d,
                                  struct input_bitstream *is,
                                  u8 *lens, unsigned num_lens)
{
    u8 *len_ptr = lens;
    u8 *lens_end = lens + num_lens;
    unsigned i;

    for (i = 0; i < MSLZX_PRECODE_NUM_SYMBOLS; ++i)
        d->precode_lens[i] =
            (u8)bitstream_read_bits(is, MSLZX_PRECODE_ELEMENT_SIZE);

    if (make_huffman_decode_table(d->precode_decode_table,
                                  MSLZX_PRECODE_NUM_SYMBOLS,
                                  MSLZX_PRECODE_TABLEBITS,
                                  d->precode_lens,
                                  MSLZX_MAX_PRE_CODEWORD_LEN,
                                  d->working))
        return -1;

    do {
        unsigned presym;
        u8 len;

        presym = read_presym(d, is);
        if (presym < 17) {
            len = (u8)(*len_ptr - presym);
            if ((s8)len < 0)
                len = (u8)(len + 17);
            *len_ptr++ = len;
        } else {
            unsigned run_len;

            if (presym == 17) {
                run_len = 4 + bitstream_read_bits(is, 4);
                len = 0;
            } else if (presym == 18) {
                run_len = 20 + bitstream_read_bits(is, 5);
                len = 0;
            } else {
                run_len = 4 + bitstream_read_bits(is, 1);
                presym = read_presym(d, is);
                if (presym > 17)
                    return -1;
                len = (u8)(*len_ptr - presym);
                if ((s8)len < 0)
                    len = (u8)(len + 17);
            }
            do {
                *len_ptr++ = len;
            } while (--run_len);
        }
    } while (len_ptr < lens_end);

    return 0;
}

/* Read the header of an MsLzx block. */
static int MSLZX_read_block_header(struct MSLZX_decompressor *d,
                                 struct input_bitstream *is,
                                 u32 recent_offsets[], int *block_type_ret,
                                 u32 *block_size_ret)
{
    int block_type;
    u32 block_size;
    unsigned i;

    /* mspatcha: 3-bit type followed by an unconditional 24-bit size. */
    bitstream_ensure_bits(is, 4);
    block_type = (int)bitstream_pop_bits(is, 3);
    block_size = (bitstream_read_bits(is, 8) << 16) |
                 (bitstream_read_bits(is, 8) << 8) |
                 bitstream_read_bits(is, 8);

    switch (block_type) {
    case MSLZX_BLOCKTYPE_ALIGNED:
        for (i = 0; i < MSLZX_ALIGNEDCODE_NUM_SYMBOLS; ++i)
            d->alignedcode_lens[i] =
                (u8)bitstream_read_bits(is, MSLZX_ALIGNEDCODE_ELEMENT_SIZE);
        /* fall through */

    case MSLZX_BLOCKTYPE_VERBATIM:
        if (MSLZX_read_codeword_lens(d, is, d->maincode_lens, MSLZX_NUM_CHARS))
            return -1;
        if (MSLZX_read_codeword_lens(d, is, d->maincode_lens + MSLZX_NUM_CHARS,
                                   d->num_main_syms - MSLZX_NUM_CHARS))
            return -1;
        if (MSLZX_read_codeword_lens(d, is, d->lencode_lens,
                                   MSLZX_LENCODE_NUM_SYMBOLS))
            return -1;
        break;

    case MSLZX_BLOCKTYPE_UNCOMPRESSED:
        bitstream_ensure_bits(is, 1);
        bitstream_align(is);
        recent_offsets[0] = bitstream_read_u32(is);
        recent_offsets[1] = bitstream_read_u32(is);
        recent_offsets[2] = bitstream_read_u32(is);
        if (recent_offsets[0] == 0 || recent_offsets[1] == 0 ||
            recent_offsets[2] == 0)
            return -1;
        break;

    default:
        return -1;
    }

    *block_type_ret = block_type;
    *block_size_ret = block_size;
    return 0;
}

/* Validate and copy an LZ77 match.  Source and destination may overlap. */
static int lz_copy(u32 length, u32 offset, u8 *out_begin, u8 *out_next,
                   u8 *out_end)
{
    u8 *end;
    unsigned long produced = (unsigned long)(out_next - out_begin);
    unsigned long window_size = (unsigned long)1 << MSLZX_window_order_g;

    if (offset == 0 || offset > window_size)
        return -1;
    end = out_next + length;
    /* mspatcha wraps match sources around the circular LZX window.  A source
     * position beyond the current output wraps to the end of the window,
     * where the caller placed the seeded dictionary. */
    while (out_next != end)
    {
        unsigned long srcpos;
        if (produced >= offset)
            srcpos = produced - offset;
        else
            srcpos = window_size - (offset - produced);
        *out_next++ = out_begin[srcpos];
        ++produced;
    }
    return 0;
}

/* Decode the literals and matches of one compressed block. */
static int MSLZX_decompress_block(struct MSLZX_decompressor *d,
                                struct input_bitstream *_is, int block_type,
                                u32 block_size, u8 *out_begin, u8 *out_next,
                                u32 recent_offsets[])
{
    struct input_bitstream is_onstack = *_is;
    struct input_bitstream *is = &is_onstack;
    u8 *block_start = out_next;
    u8 *block_end = out_next + block_size;
    unsigned min_aligned_offset_slot;
    static int symcount = 0;
    if (block_end > out_end_global)
        block_end = out_end_global;

    if (make_huffman_decode_table(d->maincode_decode_table,
                                  d->num_main_syms,
                                  MSLZX_MAINCODE_TABLEBITS,
                                  d->maincode_lens,
                                  MSLZX_MAX_MAIN_CODEWORD_LEN,
                                  d->working))
        return -1;

    if (make_huffman_decode_table(d->lencode_decode_table,
                                  MSLZX_LENCODE_NUM_SYMBOLS,
                                  MSLZX_LENCODE_TABLEBITS,
                                  d->lencode_lens,
                                  MSLZX_MAX_LEN_CODEWORD_LEN,
                                  d->working))
        return -1;

    if (block_type == MSLZX_BLOCKTYPE_ALIGNED) {
        if (make_huffman_decode_table(d->alignedcode_decode_table,
                                      MSLZX_ALIGNEDCODE_NUM_SYMBOLS,
                                      MSLZX_ALIGNEDCODE_TABLEBITS,
                                      d->alignedcode_lens,
                                      MSLZX_MAX_ALIGNED_CODEWORD_LEN,
                                      d->working))
            return -1;
        min_aligned_offset_slot = MSLZX_MIN_ALIGNED_OFFSET_SLOT;
        memcpy(d->extra_offset_bits, d->extra_offset_bits_minus_aligned,
               sizeof(d->extra_offset_bits));
    } else {
        min_aligned_offset_slot = MSLZX_MAX_OFFSET_SLOTS;
        memcpy(d->extra_offset_bits, MSLZX_extra_offset_bits,
               sizeof(d->extra_offset_bits));
    }

    do {
        unsigned mainsym;
        unsigned length;
        u32 offset;
        unsigned offset_slot;

        if (multi_chunk_limit && is->exhausted)
            break;
        mainsym = read_mainsym(d, is);
        if (mainsym < MSLZX_NUM_CHARS) {
            *out_next++ = (u8)mainsym;
            continue;
        }

        length = mainsym % MSLZX_NUM_LEN_HEADERS;
        offset_slot = (mainsym - MSLZX_NUM_CHARS) / MSLZX_NUM_LEN_HEADERS;

        if (length == MSLZX_NUM_PRIMARY_LENS)
            length += read_lensym(d, is);
        length += MSLZX_MIN_MATCH_LEN;

        /* mspatcha reads the distance extra bits BEFORE the long-match
         * length extension.  Reversing them shifts the bitstream: the
         * 9-bit length read steals the leading distance bits and the
         * 12-bit distance read gets the length bits instead. */
        if (block_type == MSLZX_BLOCKTYPE_VERBATIM && offset_slot == 3)
        {
            offset = 1;
            recent_offsets[2] = recent_offsets[1];
            recent_offsets[1] = recent_offsets[0];
        }
        else if (offset_slot < MSLZX_NUM_RECENT_OFFSETS) {
            offset = recent_offsets[offset_slot];
            recent_offsets[offset_slot] = recent_offsets[0];
        } else {
            offset = bitstream_read_bits(is, d->extra_offset_bits[offset_slot]);
            if (offset_slot >= min_aligned_offset_slot)
                offset = (offset << MSLZX_NUM_ALIGNED_OFFSET_BITS) |
                         read_alignedsym(d, is);
            /* mspatcha's MP_POS_minus2 table is position_base - 2. */
            offset += (u32)MSLZX_offset_slot_base[offset_slot] - 2;
            recent_offsets[2] = recent_offsets[1];
            recent_offsets[1] = recent_offsets[0];
        }

        /* mspatcha's long-match extension for length 257. */
        if (length == 257)
        {
            unsigned x = bitstream_read_bits(is, 9);
            if (!(x & 0x100))
                length = x + 257;
            else if (!(x & 0x80))
                length = (((x & 0x7F) << 3) | bitstream_read_bits(is, 3)) + 513;
            else if (x & 0x40)
                length = (((x & 0x3F) << 9) | bitstream_read_bits(is, 9)) + 257;
            else
                length = (((x & 0x3F) << 6) | bitstream_read_bits(is, 6)) + 1537;
        }
        recent_offsets[0] = offset;
        if (length > (u32)(block_end - out_next))
            length = (u32)(block_end - out_next);
        if (lz_copy(length, offset, out_begin, out_next, block_end))
            return -1;
        out_next += length;
    } while (out_next != block_end);

    *_is = is_onstack;
    last_produced = (u32)(out_next - block_start);
    return 0;
}

/* --------------------------- E8 x86 translation filter ------------------ */
/* Undo MsLzx's E8 preprocessing of x86 CALL targets.
 *
 * wimlib uses a fixed "magic" filesize of 12000000 for WIM resources.  For
 * cabinet files the correct filesize is the (uncompressed) data size, so we
 * pass that in as 'filesize'.  The bit-twiddling algorithm is identical to
 * wimlib's undo_translate_target()/MSLZX_postprocess().
 */
static void undo_translate_target(u8 *target, s32 input_pos, s32 filesize)
{
    s32 abs_offset = (s32)rd_le32(target);
    s32 rel_offset;

    if (abs_offset >= 0) {
        if (abs_offset < filesize) {
            rel_offset = abs_offset - input_pos;
            wr_le32(target, (u32)rel_offset);
        }
    } else {
        if (abs_offset >= -input_pos) {
            rel_offset = abs_offset + filesize;
            wr_le32(target, (u32)rel_offset);
        }
    }
}

static void MSLZX_postprocess(u8 *data, u32 size, u32 e8base)
{
    u8 *tail, *p, saved_bytes[6];
    s32 filesize = (s32)e8base;

    if (size <= 10)
        return;

    /* Trap: overwrite the tail with E8 bytes so the loop always terminates
     * before the end of the buffer (see wimlib MSLZX_common.c). */
    tail = data + size - 6;
    memcpy(saved_bytes, tail, 6);
    memset(tail, 0xE8, 6);

    p = data;
    for (;;) {
        while (*p != 0xE8)
            ++p;
        if (p >= tail)
            break;
        undo_translate_target(p + 1, (s32)(p - data), filesize);
        p += 5;
    }
    memcpy(tail, saved_bytes, 6);
}

/* --------------------------- top level --------------------------------- */
static unsigned MSLZX_get_num_main_syms(unsigned window_order)
{
    u32 window_size = (u32)1 << window_order;
    u32 max_offset = window_size - MSLZX_MIN_MATCH_LEN - 1;
    unsigned num_offset_slots = 30;

    while (max_offset >= (u32)MSLZX_offset_slot_base[num_offset_slots])
        ++num_offset_slots;
    return MSLZX_NUM_CHARS + (num_offset_slots * MSLZX_NUM_LEN_HEADERS);
}

static int MSLZX_decompress(struct MSLZX_decompressor *d,
                          const u8 *compressed_data, unsigned long compressed_size,
                          u8 *uncompressed_data, unsigned long uncompressed_size,
                          unsigned long seedLen)
{
    u8 *out_begin = uncompressed_data;
    u8 *out_next = out_begin + seedLen;
    u8 *out_end = out_next + uncompressed_size;
    struct input_bitstream is;
    u32 recent_offsets[MSLZX_NUM_RECENT_OFFSETS];
    unsigned may_have_e8_byte = 0;
    unsigned e8_present = 0;
    unsigned i;

    recent_offsets[0] = 1;
    recent_offsets[1] = 1;
    recent_offsets[2] = 1;

    init_input_bitstream(&is, compressed_data, compressed_size);

    /* mspatcha reads a per-group E8 translation header before block data. */
    bitstream_ensure_bits(&is, 1);
    d->e8_base = 0;
    {
        unsigned lo, hi;
        e8_present = bitstream_pop_bits(&is, 1);
        if (e8_present) {
            lo = bitstream_read_bits(&is, 16);
            hi = bitstream_read_bits(&is, 16);
            d->e8_base = (u32)((hi << 16) | lo);
        }
    }
    d->block_count = 0;

    /* Codeword lengths begin as all 0s for delta encoding purposes. */
    memset(d->maincode_lens, 0, d->num_main_syms);
    memset(d->lencode_lens, 0, MSLZX_LENCODE_NUM_SYMBOLS);

    /* Prepare the 'extra bits minus aligned' table. */
    memcpy(d->extra_offset_bits_minus_aligned, MSLZX_extra_offset_bits,
           sizeof(d->extra_offset_bits_minus_aligned));
    for (i = MSLZX_MIN_ALIGNED_OFFSET_SLOT; i < MSLZX_MAX_OFFSET_SLOTS; ++i)
        d->extra_offset_bits_minus_aligned[i] -= MSLZX_NUM_ALIGNED_OFFSET_BITS;

    while (out_next < out_end) {
        int block_type;
        u32 block_size;

        if (MSLZX_read_block_header(d, &is, recent_offsets,
                                  &block_type, &block_size))
            return -1;

        if (block_size < 1 || block_size > (u32)(out_end - out_next))
            return -1;

        if (block_type != MSLZX_BLOCKTYPE_UNCOMPRESSED) {
            if (MSLZX_decompress_block(d, &is, block_type, block_size,
                                     out_begin, out_next, recent_offsets))
                return -1;
            may_have_e8_byte |= d->maincode_lens[0xE8];
        } else {
            if (bitstream_read_bytes(&is, out_next, block_size))
                return -1;
            if (block_size & 1)
                bitstream_read_byte(&is);
            may_have_e8_byte = 1;
        }
        out_next += block_size;
    }

    (void)may_have_e8_byte;
    if (e8_present && d->block_count < 0x8000)
        MSLZX_postprocess(out_begin + seedLen, (u32)uncompressed_size,
                          d->e8_base ? d->e8_base : (u32)uncompressed_size);

    return 0;
}

/* Decode a multi-chunk stream while keeping decoder state across chunks. */
int MsLzxDecompressSeededMulti(const unsigned char *const *chunks,
                               const unsigned long *sizes, unsigned long nchunks,
                               unsigned char *out, unsigned long outLen,
                               int windowBits, const unsigned char *seed,
                               unsigned long seedLen)
{
    struct MSLZX_decompressor *d;
    unsigned char *window;
    struct input_bitstream is;
    u32 recent_offsets[MSLZX_NUM_RECENT_OFFSETS];
    unsigned long ci, i;
    unsigned may_have_e8_byte = 0;
    unsigned e8_present = 0;
    u8 *out_next, *out_end;
    int need_header = 1;
    u32 block_remaining = 0;
    int block_type = 0;
    int result = -1;

    if (!chunks || !sizes || !out || !outLen || !nchunks)
        return -1;
    if (windowBits < MSLZX_MIN_WINDOW_ORDER || windowBits > MSLZX_MAX_WINDOW_ORDER)
        return -1;
    if (seedLen > ((unsigned long)1 << windowBits))
        return -1;

    MSLZX_make_slot_bases();
    d = (struct MSLZX_decompressor *)calloc(1, sizeof(*d));
    window = (unsigned char *)calloc((size_t)1 << windowBits, 1);
    if (!d || !window) { free(d); free(window); return -1; }
    if (seed && seedLen)
        memcpy(window + ((size_t)1 << windowBits) - seedLen, seed, (size_t)seedLen);

    d->window_order = (unsigned)windowBits;
    MSLZX_window_order_g = d->window_order;
    d->num_main_syms = MSLZX_get_num_main_syms(d->window_order);
    d->block_count = 0;
    d->e8_base = 0;
    recent_offsets[0] = recent_offsets[1] = recent_offsets[2] = 1;
    memset(d->maincode_lens, 0, d->num_main_syms);
    memset(d->lencode_lens, 0, MSLZX_LENCODE_NUM_SYMBOLS);
    memcpy(d->extra_offset_bits_minus_aligned, MSLZX_extra_offset_bits,
           sizeof(d->extra_offset_bits_minus_aligned));
    for (i = MSLZX_MIN_ALIGNED_OFFSET_SLOT; i < MSLZX_MAX_OFFSET_SLOTS; ++i)
        d->extra_offset_bits_minus_aligned[i] -= MSLZX_NUM_ALIGNED_OFFSET_BITS;

    out_next = window;
    out_end = window + outLen;

    for (ci = 0; ci < nchunks; ++ci) {
        init_input_bitstream(&is, chunks[ci], sizes[ci]);
        if (ci == 0) {
            unsigned lo, hi;
            bitstream_ensure_bits(&is, 1);
            e8_present = bitstream_pop_bits(&is, 1);
            if (e8_present) {
                lo = bitstream_read_bits(&is, 16);
                hi = bitstream_read_bits(&is, 16);
                d->e8_base = (u32)((hi << 16) | lo);
            }
        }
        while (out_next < out_end) {
            u32 block_size;
            u8 *chunk_end;
            u8 *start = out_next;

            if (need_header) {
                if (MSLZX_read_block_header(d, &is, recent_offsets,
                                            &block_type, &block_size))
                    goto done;
                if (block_size < 1)
                    goto done;
                block_remaining = block_size;
                need_header = 0;
                d->block_count++;
            }

            chunk_end = out_next + block_remaining;
            if (chunk_end > out_end) chunk_end = out_end;
            out_end_global = chunk_end;

            if (block_type == MSLZX_BLOCKTYPE_UNCOMPRESSED) {
                u32 n = (u32)(chunk_end - out_next);
                if (bitstream_read_bytes(&is, out_next, n))
                    goto done;
                if (n & 1) bitstream_read_byte(&is);
                may_have_e8_byte = 1;
                out_next += n;
            } else {
                multi_chunk_limit = is.end;
                if (MSLZX_decompress_block(d, &is, block_type, block_remaining,
                                           window, out_next, recent_offsets))
                {
                    multi_chunk_limit = NULL;
                    goto done;
                }
                multi_chunk_limit = NULL;
                out_next += last_produced;
                may_have_e8_byte |= d->maincode_lens[0xE8];
            }
            block_remaining -= (u32)(out_next - start);
            if (block_remaining == 0)
                need_header = 1;

            /* No more input words in this chunk: move to next chunk. */
            if (is.exhausted)
                break;
            if (out_next == start)
                goto done;
        }
    }
    if (out_next != out_end)
        goto done;

    (void)may_have_e8_byte;
    if (e8_present && d->block_count < 0x8000)
        MSLZX_postprocess(window, (u32)outLen,
                          d->e8_base ? d->e8_base : (u32)outLen);
    memcpy(out, window, (size_t)outLen);
    result = 0;

done:
    free(d);
    free(window);
    return result;
}

int MsLzxRawDecompress(const unsigned char *in, unsigned long inLen,
                     unsigned char *out, unsigned long outLen, int windowBits)
{
    struct MSLZX_decompressor *d;
    int result;

    if (!in || !out || inLen == 0 || outLen == 0)
        return -1;
    if (windowBits < MSLZX_MIN_WINDOW_ORDER || windowBits > MSLZX_MAX_WINDOW_ORDER)
        return -1;
    if (outLen > 0xFFFFFFFFUL)
        return -1;

    MSLZX_make_slot_bases();
    d = (struct MSLZX_decompressor *)calloc(1, sizeof(*d));
    if (!d)
        return -1;

    d->window_order = (unsigned)windowBits;
    d->num_main_syms = MSLZX_get_num_main_syms(d->window_order);

    result = MSLZX_decompress(d, in, inLen, out, outLen, 0);
    free(d);
    return result;
}

int MsLzxDecompressSeeded(const unsigned char *in, unsigned long inLen,
                        unsigned char *out, unsigned long outLen, int windowBits,
                        const unsigned char *seed, unsigned long seedLen)
{
    struct MSLZX_decompressor *d;
    unsigned char *window;
    int result;

    if (!in || !out || inLen == 0 || outLen == 0)
        return -1;
    if (windowBits < MSLZX_MIN_WINDOW_ORDER || windowBits > MSLZX_MAX_WINDOW_ORDER)
        return -1;
    if (outLen > 0xFFFFFFFFUL || seedLen > 0xFFFFFFFFUL)
        return -1;
    if (seedLen > ((unsigned long)1 << windowBits))
        return -1;

    MSLZX_make_slot_bases();
    d = (struct MSLZX_decompressor *)calloc(1, sizeof(*d));
    window = (unsigned char *)calloc((size_t)1 << windowBits, 1);
    if (!d || !window)
    {
        free(d);
        free(window);
        return -1;
    }
    /* mspatcha seeds the END of the LZX window; output starts at offset 0. */
    if (seed && seedLen)
    {
        unsigned long avail = seedLen;

        memcpy(window + ((size_t)1 << windowBits) - seedLen,
               seed, (size_t)avail);
    }
    d->window_order = (unsigned)windowBits;
    MSLZX_window_order_g = d->window_order;
    d->num_main_syms = MSLZX_get_num_main_syms(d->window_order);
    out_end_global = window + outLen;
    result = MSLZX_decompress(d, in, inLen, window, outLen, 0);

    if (result == 0)
        memcpy(out, window, (size_t)outLen);
    free(d);
    free(window);
    return result;
}









