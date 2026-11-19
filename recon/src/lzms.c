/*
 * lzms.c -- C89 port of the LZMS raw decompressor from wimlib 1.14.5.
 *
 * Copyright (C) 2013-2016 Eric Biggers (LZMS codec, LGPL-2.1+)
 * Copyright 2022 Eric Biggers (Huffman helpers, MIT)
 *
 * Ported to C89 / MSVC6 for the standalone expand.exe reconstruction.
 * Requires the uncompressed size up front; decompresses a single raw block.
 */
#include "expand.h"
#include "lzms.h"

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned __int64 u64;
typedef int            s32;
typedef int            bool;
#define true  1
#define false 0

#define LZMS_MIN_MATCH_LENGTH          1
#define LZMS_MAX_BUFFER_SIZE           1073741824UL
#define LZMS_NUM_LZ_REPS               3
#define LZMS_NUM_DELTA_REPS            3
#define LZMS_NUM_LZ_REP_DECISIONS      (LZMS_NUM_LZ_REPS - 1)
#define LZMS_NUM_DELTA_REP_DECISIONS   (LZMS_NUM_DELTA_REPS - 1)
#define LZMS_NUM_MAIN_PROBS            16
#define LZMS_NUM_MATCH_PROBS           32
#define LZMS_NUM_LZ_PROBS              64
#define LZMS_NUM_LZ_REP_PROBS          64
#define LZMS_NUM_DELTA_PROBS           64
#define LZMS_NUM_DELTA_REP_PROBS       64
#define LZMS_PROBABILITY_BITS          6
#define LZMS_PROBABILITY_DENOMINATOR   64
#define LZMS_INITIAL_PROBABILITY       48
#define LZMS_INITIAL_RECENT_BITS       ((u64)0x55555555UL)
#define LZMS_NUM_LITERAL_SYMS          256
#define LZMS_NUM_LENGTH_SYMS           54
#define LZMS_NUM_DELTA_POWER_SYMS      8
#define LZMS_MAX_NUM_OFFSET_SYMS       799
#define LZMS_MAX_NUM_SYMS              799
#define LZMS_LITERAL_CODE_REBUILD_FREQ    1024
#define LZMS_LZ_OFFSET_CODE_REBUILD_FREQ  1024
#define LZMS_LENGTH_CODE_REBUILD_FREQ     512
#define LZMS_DELTA_OFFSET_CODE_REBUILD_FREQ 1024
#define LZMS_DELTA_POWER_CODE_REBUILD_FREQ  512
#define LZMS_MAX_CODEWORD_LENGTH       15
#define LZMS_X86_ID_WINDOW_SIZE        65535
#define LZMS_X86_MAX_TRANSLATION_OFFSET 1023

#define LZMS_LITERAL_TABLEBITS     10
#define LZMS_LENGTH_TABLEBITS      9
#define LZMS_LZ_OFFSET_TABLEBITS   11
#define LZMS_DELTA_OFFSET_TABLEBITS 11
#define LZMS_DELTA_POWER_TABLEBITS 7

/* Decode-table entry layout (from wimlib decompress_common.h). */
#define DECODE_TABLE_SYMBOL_SHIFT   4
#define DECODE_TABLE_LENGTH_MASK    0xF
#define MAKE_DECODE_TABLE_ENTRY(sym, len) \
    (((unsigned)(sym) << DECODE_TABLE_SYMBOL_SHIFT) | (unsigned)(len))

/* Table sizes (zlib 'enough' precomputed by wimlib for these combinations). */
#define SZ_LITERAL    1302
#define SZ_LENGTH     618
#define SZ_OFFSET     2854
#define SZ_DELTA_POWER 128
#define SZ_WORKING    (2 * (LZMS_MAX_CODEWORD_LENGTH + 1) + LZMS_MAX_NUM_SYMS)

/* ==================== offset / length tables (from lzms_common.c) ======== */
/* TABLES_GO_HERE */
/* Table: offset slot => offset slot base value  */
const u32 lzms_offset_slot_base[LZMS_MAX_NUM_OFFSET_SYMS + 1] = {
	0x00000001, 0x00000002, 0x00000003, 0x00000004,
	0x00000005, 0x00000006, 0x00000007, 0x00000008,
	0x00000009, 0x0000000d, 0x00000011, 0x00000015,
	0x00000019, 0x0000001d, 0x00000021, 0x00000025,
	0x00000029, 0x0000002d, 0x00000035, 0x0000003d,
	0x00000045, 0x0000004d, 0x00000055, 0x0000005d,
	0x00000065, 0x00000075, 0x00000085, 0x00000095,
	0x000000a5, 0x000000b5, 0x000000c5, 0x000000d5,
	0x000000e5, 0x000000f5, 0x00000105, 0x00000125,
	0x00000145, 0x00000165, 0x00000185, 0x000001a5,
	0x000001c5, 0x000001e5, 0x00000205, 0x00000225,
	0x00000245, 0x00000265, 0x00000285, 0x000002a5,
	0x000002c5, 0x000002e5, 0x00000325, 0x00000365,
	0x000003a5, 0x000003e5, 0x00000425, 0x00000465,
	0x000004a5, 0x000004e5, 0x00000525, 0x00000565,
	0x000005a5, 0x000005e5, 0x00000625, 0x00000665,
	0x000006a5, 0x00000725, 0x000007a5, 0x00000825,
	0x000008a5, 0x00000925, 0x000009a5, 0x00000a25,
	0x00000aa5, 0x00000b25, 0x00000ba5, 0x00000c25,
	0x00000ca5, 0x00000d25, 0x00000da5, 0x00000e25,
	0x00000ea5, 0x00000f25, 0x00000fa5, 0x00001025,
	0x000010a5, 0x000011a5, 0x000012a5, 0x000013a5,
	0x000014a5, 0x000015a5, 0x000016a5, 0x000017a5,
	0x000018a5, 0x000019a5, 0x00001aa5, 0x00001ba5,
	0x00001ca5, 0x00001da5, 0x00001ea5, 0x00001fa5,
	0x000020a5, 0x000021a5, 0x000022a5, 0x000023a5,
	0x000024a5, 0x000026a5, 0x000028a5, 0x00002aa5,
	0x00002ca5, 0x00002ea5, 0x000030a5, 0x000032a5,
	0x000034a5, 0x000036a5, 0x000038a5, 0x00003aa5,
	0x00003ca5, 0x00003ea5, 0x000040a5, 0x000042a5,
	0x000044a5, 0x000046a5, 0x000048a5, 0x00004aa5,
	0x00004ca5, 0x00004ea5, 0x000050a5, 0x000052a5,
	0x000054a5, 0x000056a5, 0x000058a5, 0x00005aa5,
	0x00005ca5, 0x00005ea5, 0x000060a5, 0x000064a5,
	0x000068a5, 0x00006ca5, 0x000070a5, 0x000074a5,
	0x000078a5, 0x00007ca5, 0x000080a5, 0x000084a5,
	0x000088a5, 0x00008ca5, 0x000090a5, 0x000094a5,
	0x000098a5, 0x00009ca5, 0x0000a0a5, 0x0000a4a5,
	0x0000a8a5, 0x0000aca5, 0x0000b0a5, 0x0000b4a5,
	0x0000b8a5, 0x0000bca5, 0x0000c0a5, 0x0000c4a5,
	0x0000c8a5, 0x0000cca5, 0x0000d0a5, 0x0000d4a5,
	0x0000d8a5, 0x0000dca5, 0x0000e0a5, 0x0000e4a5,
	0x0000eca5, 0x0000f4a5, 0x0000fca5, 0x000104a5,
	0x00010ca5, 0x000114a5, 0x00011ca5, 0x000124a5,
	0x00012ca5, 0x000134a5, 0x00013ca5, 0x000144a5,
	0x00014ca5, 0x000154a5, 0x00015ca5, 0x000164a5,
	0x00016ca5, 0x000174a5, 0x00017ca5, 0x000184a5,
	0x00018ca5, 0x000194a5, 0x00019ca5, 0x0001a4a5,
	0x0001aca5, 0x0001b4a5, 0x0001bca5, 0x0001c4a5,
	0x0001cca5, 0x0001d4a5, 0x0001dca5, 0x0001e4a5,
	0x0001eca5, 0x0001f4a5, 0x0001fca5, 0x000204a5,
	0x00020ca5, 0x000214a5, 0x00021ca5, 0x000224a5,
	0x000234a5, 0x000244a5, 0x000254a5, 0x000264a5,
	0x000274a5, 0x000284a5, 0x000294a5, 0x0002a4a5,
	0x0002b4a5, 0x0002c4a5, 0x0002d4a5, 0x0002e4a5,
	0x0002f4a5, 0x000304a5, 0x000314a5, 0x000324a5,
	0x000334a5, 0x000344a5, 0x000354a5, 0x000364a5,
	0x000374a5, 0x000384a5, 0x000394a5, 0x0003a4a5,
	0x0003b4a5, 0x0003c4a5, 0x0003d4a5, 0x0003e4a5,
	0x0003f4a5, 0x000404a5, 0x000414a5, 0x000424a5,
	0x000434a5, 0x000444a5, 0x000454a5, 0x000464a5,
	0x000474a5, 0x000484a5, 0x000494a5, 0x0004a4a5,
	0x0004b4a5, 0x0004c4a5, 0x0004e4a5, 0x000504a5,
	0x000524a5, 0x000544a5, 0x000564a5, 0x000584a5,
	0x0005a4a5, 0x0005c4a5, 0x0005e4a5, 0x000604a5,
	0x000624a5, 0x000644a5, 0x000664a5, 0x000684a5,
	0x0006a4a5, 0x0006c4a5, 0x0006e4a5, 0x000704a5,
	0x000724a5, 0x000744a5, 0x000764a5, 0x000784a5,
	0x0007a4a5, 0x0007c4a5, 0x0007e4a5, 0x000804a5,
	0x000824a5, 0x000844a5, 0x000864a5, 0x000884a5,
	0x0008a4a5, 0x0008c4a5, 0x0008e4a5, 0x000904a5,
	0x000924a5, 0x000944a5, 0x000964a5, 0x000984a5,
	0x0009a4a5, 0x0009c4a5, 0x0009e4a5, 0x000a04a5,
	0x000a24a5, 0x000a44a5, 0x000a64a5, 0x000aa4a5,
	0x000ae4a5, 0x000b24a5, 0x000b64a5, 0x000ba4a5,
	0x000be4a5, 0x000c24a5, 0x000c64a5, 0x000ca4a5,
	0x000ce4a5, 0x000d24a5, 0x000d64a5, 0x000da4a5,
	0x000de4a5, 0x000e24a5, 0x000e64a5, 0x000ea4a5,
	0x000ee4a5, 0x000f24a5, 0x000f64a5, 0x000fa4a5,
	0x000fe4a5, 0x001024a5, 0x001064a5, 0x0010a4a5,
	0x0010e4a5, 0x001124a5, 0x001164a5, 0x0011a4a5,
	0x0011e4a5, 0x001224a5, 0x001264a5, 0x0012a4a5,
	0x0012e4a5, 0x001324a5, 0x001364a5, 0x0013a4a5,
	0x0013e4a5, 0x001424a5, 0x001464a5, 0x0014a4a5,
	0x0014e4a5, 0x001524a5, 0x001564a5, 0x0015a4a5,
	0x0015e4a5, 0x001624a5, 0x001664a5, 0x0016a4a5,
	0x0016e4a5, 0x001724a5, 0x001764a5, 0x0017a4a5,
	0x0017e4a5, 0x001824a5, 0x001864a5, 0x0018a4a5,
	0x0018e4a5, 0x001924a5, 0x001964a5, 0x0019e4a5,
	0x001a64a5, 0x001ae4a5, 0x001b64a5, 0x001be4a5,
	0x001c64a5, 0x001ce4a5, 0x001d64a5, 0x001de4a5,
	0x001e64a5, 0x001ee4a5, 0x001f64a5, 0x001fe4a5,
	0x002064a5, 0x0020e4a5, 0x002164a5, 0x0021e4a5,
	0x002264a5, 0x0022e4a5, 0x002364a5, 0x0023e4a5,
	0x002464a5, 0x0024e4a5, 0x002564a5, 0x0025e4a5,
	0x002664a5, 0x0026e4a5, 0x002764a5, 0x0027e4a5,
	0x002864a5, 0x0028e4a5, 0x002964a5, 0x0029e4a5,
	0x002a64a5, 0x002ae4a5, 0x002b64a5, 0x002be4a5,
	0x002c64a5, 0x002ce4a5, 0x002d64a5, 0x002de4a5,
	0x002e64a5, 0x002ee4a5, 0x002f64a5, 0x002fe4a5,
	0x003064a5, 0x0030e4a5, 0x003164a5, 0x0031e4a5,
	0x003264a5, 0x0032e4a5, 0x003364a5, 0x0033e4a5,
	0x003464a5, 0x0034e4a5, 0x003564a5, 0x0035e4a5,
	0x003664a5, 0x0036e4a5, 0x003764a5, 0x0037e4a5,
	0x003864a5, 0x0038e4a5, 0x003964a5, 0x0039e4a5,
	0x003a64a5, 0x003ae4a5, 0x003b64a5, 0x003be4a5,
	0x003c64a5, 0x003ce4a5, 0x003d64a5, 0x003de4a5,
	0x003ee4a5, 0x003fe4a5, 0x0040e4a5, 0x0041e4a5,
	0x0042e4a5, 0x0043e4a5, 0x0044e4a5, 0x0045e4a5,
	0x0046e4a5, 0x0047e4a5, 0x0048e4a5, 0x0049e4a5,
	0x004ae4a5, 0x004be4a5, 0x004ce4a5, 0x004de4a5,
	0x004ee4a5, 0x004fe4a5, 0x0050e4a5, 0x0051e4a5,
	0x0052e4a5, 0x0053e4a5, 0x0054e4a5, 0x0055e4a5,
	0x0056e4a5, 0x0057e4a5, 0x0058e4a5, 0x0059e4a5,
	0x005ae4a5, 0x005be4a5, 0x005ce4a5, 0x005de4a5,
	0x005ee4a5, 0x005fe4a5, 0x0060e4a5, 0x0061e4a5,
	0x0062e4a5, 0x0063e4a5, 0x0064e4a5, 0x0065e4a5,
	0x0066e4a5, 0x0067e4a5, 0x0068e4a5, 0x0069e4a5,
	0x006ae4a5, 0x006be4a5, 0x006ce4a5, 0x006de4a5,
	0x006ee4a5, 0x006fe4a5, 0x0070e4a5, 0x0071e4a5,
	0x0072e4a5, 0x0073e4a5, 0x0074e4a5, 0x0075e4a5,
	0x0076e4a5, 0x0077e4a5, 0x0078e4a5, 0x0079e4a5,
	0x007ae4a5, 0x007be4a5, 0x007ce4a5, 0x007de4a5,
	0x007ee4a5, 0x007fe4a5, 0x0080e4a5, 0x0081e4a5,
	0x0082e4a5, 0x0083e4a5, 0x0084e4a5, 0x0085e4a5,
	0x0086e4a5, 0x0087e4a5, 0x0088e4a5, 0x0089e4a5,
	0x008ae4a5, 0x008be4a5, 0x008ce4a5, 0x008de4a5,
	0x008fe4a5, 0x0091e4a5, 0x0093e4a5, 0x0095e4a5,
	0x0097e4a5, 0x0099e4a5, 0x009be4a5, 0x009de4a5,
	0x009fe4a5, 0x00a1e4a5, 0x00a3e4a5, 0x00a5e4a5,
	0x00a7e4a5, 0x00a9e4a5, 0x00abe4a5, 0x00ade4a5,
	0x00afe4a5, 0x00b1e4a5, 0x00b3e4a5, 0x00b5e4a5,
	0x00b7e4a5, 0x00b9e4a5, 0x00bbe4a5, 0x00bde4a5,
	0x00bfe4a5, 0x00c1e4a5, 0x00c3e4a5, 0x00c5e4a5,
	0x00c7e4a5, 0x00c9e4a5, 0x00cbe4a5, 0x00cde4a5,
	0x00cfe4a5, 0x00d1e4a5, 0x00d3e4a5, 0x00d5e4a5,
	0x00d7e4a5, 0x00d9e4a5, 0x00dbe4a5, 0x00dde4a5,
	0x00dfe4a5, 0x00e1e4a5, 0x00e3e4a5, 0x00e5e4a5,
	0x00e7e4a5, 0x00e9e4a5, 0x00ebe4a5, 0x00ede4a5,
	0x00efe4a5, 0x00f1e4a5, 0x00f3e4a5, 0x00f5e4a5,
	0x00f7e4a5, 0x00f9e4a5, 0x00fbe4a5, 0x00fde4a5,
	0x00ffe4a5, 0x0101e4a5, 0x0103e4a5, 0x0105e4a5,
	0x0107e4a5, 0x0109e4a5, 0x010be4a5, 0x010de4a5,
	0x010fe4a5, 0x0111e4a5, 0x0113e4a5, 0x0115e4a5,
	0x0117e4a5, 0x0119e4a5, 0x011be4a5, 0x011de4a5,
	0x011fe4a5, 0x0121e4a5, 0x0123e4a5, 0x0125e4a5,
	0x0127e4a5, 0x0129e4a5, 0x012be4a5, 0x012de4a5,
	0x012fe4a5, 0x0131e4a5, 0x0133e4a5, 0x0135e4a5,
	0x0137e4a5, 0x013be4a5, 0x013fe4a5, 0x0143e4a5,
	0x0147e4a5, 0x014be4a5, 0x014fe4a5, 0x0153e4a5,
	0x0157e4a5, 0x015be4a5, 0x015fe4a5, 0x0163e4a5,
	0x0167e4a5, 0x016be4a5, 0x016fe4a5, 0x0173e4a5,
	0x0177e4a5, 0x017be4a5, 0x017fe4a5, 0x0183e4a5,
	0x0187e4a5, 0x018be4a5, 0x018fe4a5, 0x0193e4a5,
	0x0197e4a5, 0x019be4a5, 0x019fe4a5, 0x01a3e4a5,
	0x01a7e4a5, 0x01abe4a5, 0x01afe4a5, 0x01b3e4a5,
	0x01b7e4a5, 0x01bbe4a5, 0x01bfe4a5, 0x01c3e4a5,
	0x01c7e4a5, 0x01cbe4a5, 0x01cfe4a5, 0x01d3e4a5,
	0x01d7e4a5, 0x01dbe4a5, 0x01dfe4a5, 0x01e3e4a5,
	0x01e7e4a5, 0x01ebe4a5, 0x01efe4a5, 0x01f3e4a5,
	0x01f7e4a5, 0x01fbe4a5, 0x01ffe4a5, 0x0203e4a5,
	0x0207e4a5, 0x020be4a5, 0x020fe4a5, 0x0213e4a5,
	0x0217e4a5, 0x021be4a5, 0x021fe4a5, 0x0223e4a5,
	0x0227e4a5, 0x022be4a5, 0x022fe4a5, 0x0233e4a5,
	0x0237e4a5, 0x023be4a5, 0x023fe4a5, 0x0243e4a5,
	0x0247e4a5, 0x024be4a5, 0x024fe4a5, 0x0253e4a5,
	0x0257e4a5, 0x025be4a5, 0x025fe4a5, 0x0263e4a5,
	0x0267e4a5, 0x026be4a5, 0x026fe4a5, 0x0273e4a5,
	0x0277e4a5, 0x027be4a5, 0x027fe4a5, 0x0283e4a5,
	0x0287e4a5, 0x028be4a5, 0x028fe4a5, 0x0293e4a5,
	0x0297e4a5, 0x029be4a5, 0x029fe4a5, 0x02a3e4a5,
	0x02a7e4a5, 0x02abe4a5, 0x02afe4a5, 0x02b3e4a5,
	0x02bbe4a5, 0x02c3e4a5, 0x02cbe4a5, 0x02d3e4a5,
	0x02dbe4a5, 0x02e3e4a5, 0x02ebe4a5, 0x02f3e4a5,
	0x02fbe4a5, 0x0303e4a5, 0x030be4a5, 0x0313e4a5,
	0x031be4a5, 0x0323e4a5, 0x032be4a5, 0x0333e4a5,
	0x033be4a5, 0x0343e4a5, 0x034be4a5, 0x0353e4a5,
	0x035be4a5, 0x0363e4a5, 0x036be4a5, 0x0373e4a5,
	0x037be4a5, 0x0383e4a5, 0x038be4a5, 0x0393e4a5,
	0x039be4a5, 0x03a3e4a5, 0x03abe4a5, 0x03b3e4a5,
	0x03bbe4a5, 0x03c3e4a5, 0x03cbe4a5, 0x03d3e4a5,
	0x03dbe4a5, 0x03e3e4a5, 0x03ebe4a5, 0x03f3e4a5,
	0x03fbe4a5, 0x0403e4a5, 0x040be4a5, 0x0413e4a5,
	0x041be4a5, 0x0423e4a5, 0x042be4a5, 0x0433e4a5,
	0x043be4a5, 0x0443e4a5, 0x044be4a5, 0x0453e4a5,
	0x045be4a5, 0x0463e4a5, 0x046be4a5, 0x0473e4a5,
	0x047be4a5, 0x0483e4a5, 0x048be4a5, 0x0493e4a5,
	0x049be4a5, 0x04a3e4a5, 0x04abe4a5, 0x04b3e4a5,
	0x04bbe4a5, 0x04c3e4a5, 0x04cbe4a5, 0x04d3e4a5,
	0x04dbe4a5, 0x04e3e4a5, 0x04ebe4a5, 0x04f3e4a5,
	0x04fbe4a5, 0x0503e4a5, 0x050be4a5, 0x0513e4a5,
	0x051be4a5, 0x0523e4a5, 0x052be4a5, 0x0533e4a5,
	0x053be4a5, 0x0543e4a5, 0x054be4a5, 0x0553e4a5,
	0x055be4a5, 0x0563e4a5, 0x056be4a5, 0x0573e4a5,
	0x057be4a5, 0x0583e4a5, 0x058be4a5, 0x0593e4a5,
	0x059be4a5, 0x05a3e4a5, 0x05abe4a5, 0x05b3e4a5,
	0x05bbe4a5, 0x05c3e4a5, 0x05cbe4a5, 0x05d3e4a5,
	0x05dbe4a5, 0x05e3e4a5, 0x05ebe4a5, 0x05f3e4a5,
	0x05fbe4a5, 0x060be4a5, 0x061be4a5, 0x062be4a5,
	0x063be4a5, 0x064be4a5, 0x065be4a5, 0x465be4a5,
	/* The last entry is extra; it is equal to LZMS_MAX_MATCH_OFFSET + 1 and
	 * is here to aid binary search.  */
};

/* Table: offset slot => number of extra offset bits  */
const u8 lzms_extra_offset_bits[LZMS_MAX_NUM_OFFSET_SYMS] = {
	0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2,
	2 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 4 , 4 , 4 , 4 , 4 , 4 , 4 , 4,
	4 , 4 , 5 , 5 , 5 , 5 , 5 , 5 , 5 , 5 , 5 , 5 , 5 , 5 , 5 , 5,
	5 , 6 , 6 , 6 , 6 , 6 , 6 , 6 , 6 , 6 , 6 , 6 , 6 , 6 , 6 , 6,
	7 , 7 , 7 , 7 , 7 , 7 , 7 , 7 , 7 , 7 , 7 , 7 , 7 , 7 , 7 , 7,
	7 , 7 , 7 , 7 , 8 , 8 , 8 , 8 , 8 , 8 , 8 , 8 , 8 , 8 , 8 , 8,
	8 , 8 , 8 , 8 , 8 , 8 , 8 , 8 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9,
	9 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9 , 9,
	9 , 9 , 9 , 9 , 9 , 9 , 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
	10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
	10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11,
	11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
	11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 12,
	12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
	12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
	12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13,
	13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
	13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
	13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
	15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
	15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
	15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
	15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 16, 16, 16, 16, 16,
	16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
	16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
	16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
	16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
	16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17,
	17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
	17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
	17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
	17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
	17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
	18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
	18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
	18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
	18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
	18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
	18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 19,
	19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
	19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
	19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
	19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
	19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
	19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
	19, 19, 19, 19, 19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 30,
};

/* Table: length slot => length slot base value  */
const u32 lzms_length_slot_base[LZMS_NUM_LENGTH_SYMS + 1] = {
	0x00000001, 0x00000002, 0x00000003, 0x00000004,
	0x00000005, 0x00000006, 0x00000007, 0x00000008,
	0x00000009, 0x0000000a, 0x0000000b, 0x0000000c,
	0x0000000d, 0x0000000e, 0x0000000f, 0x00000010,
	0x00000011, 0x00000012, 0x00000013, 0x00000014,
	0x00000015, 0x00000016, 0x00000017, 0x00000018,
	0x00000019, 0x0000001a, 0x0000001b, 0x0000001d,
	0x0000001f, 0x00000021, 0x00000023, 0x00000027,
	0x0000002b, 0x0000002f, 0x00000033, 0x00000037,
	0x0000003b, 0x00000043, 0x0000004b, 0x00000053,
	0x0000005b, 0x0000006b, 0x0000007b, 0x0000008b,
	0x0000009b, 0x000000ab, 0x000000cb, 0x000000eb,
	0x0000012b, 0x000001ab, 0x000002ab, 0x000004ab,
	0x000008ab, 0x000108ab, 0x400108ab,
	/* The last entry is extra; it is equal to LZMS_MAX_MATCH_LENGTH + 1 and
	 * is here to aid binary search.  */
};

/* Table: length slot => number of extra length bits  */
const u8 lzms_extra_length_bits[LZMS_NUM_LENGTH_SYMS] = {
	0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 ,
	0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 ,
	0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 ,
	0 , 0 , 1 , 1 , 1 , 1 , 2 , 2 ,
	2 , 2 , 2 , 2 , 3 , 3 , 3 , 3 ,
	4 , 4 , 4 , 4 , 4 , 5 , 5 , 6 ,
	7 , 8 , 9 , 10, 16, 30,
};
/* ==================== Huffman helpers (MIT, from wimlib) ================ */
#define MAX_NUM_SYMS      799
#define MAX_CODEWORD_LEN  16
#define NUM_SYMBOL_BITS   10
#define SYMBOL_MASK       ((1U << NUM_SYMBOL_BITS) - 1)
#define FREQ_MASK         (~SYMBOL_MASK)

static void heapify_subtree(u32 *A, unsigned length, unsigned subtree_idx)
{
    unsigned parent_idx, child_idx;
    u32 v = A[subtree_idx];
    parent_idx = subtree_idx;
    while ((child_idx = parent_idx * 2) <= length)
    {
        if (child_idx < length && A[child_idx + 1] > A[child_idx])
            ++child_idx;
        if (v >= A[child_idx])
            break;
        A[parent_idx] = A[child_idx];
        parent_idx = child_idx;
    }
    A[parent_idx] = v;
}

static void heapify_array(u32 *A, unsigned length)
{
    unsigned i;
    for (i = length / 2; i >= 1; --i)
        heapify_subtree(A, length, i);
}

static void heap_sort(u32 *A, unsigned length)
{
    u32 *B = A - 1;   /* 1-based */
    heapify_array(B, length);
    while (length >= 2)
    {
        u32 tmp = B[length];
        B[length] = B[1];
        B[1] = tmp;
        --length;
        heapify_subtree(B, length, 1);
    }
}

static unsigned sort_symbols(unsigned num_syms, const u32 *freqs,
                             u8 *lens, u32 *symout)
{
    unsigned counters[MAX_NUM_SYMS];
    unsigned sym, i, num_used_syms, num_counters;

    num_counters = num_syms;
    memset(counters, 0, num_counters * sizeof(counters[0]));
    for (sym = 0; sym < num_syms; ++sym)
    {
        unsigned f = freqs[sym];
        ++counters[f < num_counters - 1 ? f : num_counters - 1];
    }
    num_used_syms = 0;
    for (i = 1; i < num_counters; ++i)
    {
        unsigned count = counters[i];
        counters[i] = num_used_syms;
        num_used_syms += count;
    }
    for (sym = 0; sym < num_syms; ++sym)
    {
        u32 freq = freqs[sym];
        if (freq != 0)
        {
            unsigned idx = freq < num_counters - 1 ? freq : num_counters - 1;
            symout[counters[idx]++] = sym | (freq << NUM_SYMBOL_BITS);
        }
        else
        {
            lens[sym] = 0;
        }
    }
    heap_sort(symout + counters[num_counters - 2],
              counters[num_counters - 1] - counters[num_counters - 2]);
    return num_used_syms;
}

static void build_tree(u32 *A, unsigned sym_count)
{
    const unsigned last_idx = sym_count - 1;
    unsigned i = 0, b = 0, e = 0;
    do
    {
        u32 new_freq;
        if (i + 1 <= last_idx &&
            (b == e || (A[i + 1] & FREQ_MASK) <= (A[b] & FREQ_MASK)))
        {
            new_freq = (A[i] & FREQ_MASK) + (A[i + 1] & FREQ_MASK);
            i += 2;
        }
        else if (b + 2 <= e &&
                 (i > last_idx ||
                  (A[b + 1] & FREQ_MASK) < (A[i] & FREQ_MASK)))
        {
            new_freq = (A[b] & FREQ_MASK) + (A[b + 1] & FREQ_MASK);
            A[b] = (e << NUM_SYMBOL_BITS) | (A[b] & SYMBOL_MASK);
            A[b + 1] = (e << NUM_SYMBOL_BITS) | (A[b + 1] & SYMBOL_MASK);
            b += 2;
        }
        else
        {
            new_freq = (A[i] & FREQ_MASK) + (A[b] & FREQ_MASK);
            A[b] = (e << NUM_SYMBOL_BITS) | (A[b] & SYMBOL_MASK);
            ++i;
            ++b;
        }
        A[e] = new_freq | (A[e] & SYMBOL_MASK);
    } while (++e < last_idx);
}

static void compute_length_counts(u32 *A, unsigned root_idx,
                                  unsigned *len_counts, unsigned max_len)
{
    unsigned len;
    int node;
    for (len = 0; len <= max_len; ++len)
        len_counts[len] = 0;
    len_counts[1] = 2;
    A[root_idx] &= SYMBOL_MASK;
    for (node = (int)root_idx - 1; node >= 0; --node)
    {
        unsigned parent = A[node] >> NUM_SYMBOL_BITS;
        unsigned depth = (A[parent] >> NUM_SYMBOL_BITS) + 1;
        unsigned l = depth;
        A[node] = (A[node] & SYMBOL_MASK) | (depth << NUM_SYMBOL_BITS);
        if (l >= max_len)
        {
            l = max_len;
            do { --l; } while (len_counts[l] == 0);
        }
        --len_counts[l];
        len_counts[l + 1] += 2;
    }
}

static void gen_codewords(u32 *A, u8 *lens, const unsigned *len_counts,
                          unsigned max_len, unsigned num_syms)
{
    unsigned next_codewords[MAX_CODEWORD_LEN + 1];
    unsigned i = 0, len, sym;
    /* Assign lengths in decreasing order to frequency-sorted symbols. */
    for (len = max_len; len >= 1; --len)
    {
        unsigned count = len_counts[len];
        while (count--)
            lens[A[i++] & SYMBOL_MASK] = (u8)len;
    }
    next_codewords[0] = 0;
    next_codewords[1] = 0;
    for (len = 2; len <= max_len; ++len)
        next_codewords[len] =
            (next_codewords[len - 1] + len_counts[len - 1]) << 1;
    for (sym = 0; sym < num_syms; ++sym)
        A[sym] = next_codewords[lens[sym]]++;
}

static void make_canonical_huffman_code(unsigned num_syms,
                                        unsigned max_codeword_len,
                                        const u32 *freqs, u8 *lens,
                                        u32 *codewords)
{
    unsigned num_used_syms = sort_symbols(num_syms, freqs, lens, codewords);
    if (num_used_syms == 0)
        return;
    if (num_used_syms == 1)
    {
        unsigned sym = codewords[0] & SYMBOL_MASK;
        unsigned nonzero_idx = sym ? sym : 1;
        codewords[0] = 0;
        lens[0] = 1;
        codewords[nonzero_idx] = 1;
        lens[nonzero_idx] = 1;
        return;
    }
    build_tree(codewords, num_used_syms);
    {
        unsigned len_counts[MAX_CODEWORD_LEN + 1];
        compute_length_counts(codewords, num_used_syms - 2,
                              len_counts, max_codeword_len);
        gen_codewords(codewords, lens, len_counts, max_codeword_len, num_syms);
    }
}

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
    for (len = 1; len <= max_codeword_len; ++len)
    {
        remainder = (remainder << 1) - len_counts[len];
        if (remainder < 0)
            return -1;
    }
    if (remainder != 0)
    {
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
        while (stores_per_loop != 0)
        {
            unsigned end_sym_idx = sym_idx + len_counts[codeword_len];
            for (; sym_idx < end_sym_idx; ++sym_idx)
            {
                u16 v = (u16)MAKE_DECODE_TABLE_ENTRY(sorted_syms[sym_idx],
                                                     codeword_len);
                unsigned n = stores_per_loop;
                do
                {
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
    do
    {
        while (len_counts[codeword_len] == 0)
        {
            ++codeword_len;
            codeword <<= 1;
        }
        {
            unsigned prefix = codeword >> (codeword_len - table_bits);
            if (prefix != subtable_prefix)
            {
                subtable_prefix = prefix;
                subtable_bits = codeword_len - table_bits;
                remainder = (s32)1 << subtable_bits;
                for (;;)
                {
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

/* ==================== probabilities ===================================== */
struct lzms_probability_entry
{
    u32 num_recent_zero_bits;
    u64 recent_bits;
};

struct lzms_probabilites
{
    struct lzms_probability_entry main[LZMS_NUM_MAIN_PROBS];
    struct lzms_probability_entry match[LZMS_NUM_MATCH_PROBS];
    struct lzms_probability_entry lz[LZMS_NUM_LZ_PROBS];
    struct lzms_probability_entry delta[LZMS_NUM_DELTA_PROBS];
    struct lzms_probability_entry lz_rep[LZMS_NUM_LZ_REP_DECISIONS]
                                        [LZMS_NUM_LZ_REP_PROBS];
    struct lzms_probability_entry delta_rep[LZMS_NUM_DELTA_REP_DECISIONS]
                                            [LZMS_NUM_DELTA_REP_PROBS];
};

static void lzms_init_probabilities(struct lzms_probabilites *probs)
{
    struct lzms_probability_entry *entries =
        (struct lzms_probability_entry *)probs;
    unsigned n = (unsigned)(sizeof(*probs) /
                            sizeof(struct lzms_probability_entry));
    unsigned i;
    for (i = 0; i < n; ++i)
    {
        entries[i].num_recent_zero_bits = LZMS_INITIAL_PROBABILITY;
        entries[i].recent_bits = LZMS_INITIAL_RECENT_BITS;
    }
}

static void lzms_update_probability_entry(struct lzms_probability_entry *e,
                                          int bit)
{
    s32 delta_zero_bits =
        (s32)(e->recent_bits >> (LZMS_PROBABILITY_DENOMINATOR - 1)) - bit;
    e->num_recent_zero_bits = (u32)((s32)e->num_recent_zero_bits +
                                    delta_zero_bits);
    e->recent_bits = (e->recent_bits << 1) | (u64)bit;
}

static u32 lzms_get_probability(const struct lzms_probability_entry *e)
{
    u32 prob = e->num_recent_zero_bits;
    prob += (prob - 1) >> 31;   /* 0/64 -> 1/64 (unsigned shift!) */
    prob -= (prob >> LZMS_PROBABILITY_BITS);
    return prob;
}

static void lzms_init_symbol_frequencies(u32 *freqs, unsigned num_syms)
{
    unsigned i;
    for (i = 0; i < num_syms; ++i)
        freqs[i] = 1;
}

static void lzms_dilute_symbol_frequencies(u32 *freqs, unsigned num_syms)
{
    unsigned i;
    for (i = 0; i < num_syms; ++i)
        freqs[i] = (freqs[i] >> 1) + 1;
}

/* ==================== little-endian helpers ============================= */
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

/* ==================== range decoder ===================================== */
struct lzms_range_decoder
{
    u32 range;
    u32 code;
    const u8 *next;
    const u8 *end;
};

static void lzms_range_decoder_init(struct lzms_range_decoder *rd,
                                    const u8 *in, unsigned long count)
{
    rd->range = 0xFFFFFFFFU;
    rd->code = ((u32)rd_le16(in) << 16) | rd_le16(in + 2);
    rd->next = in + 4;
    rd->end = in + count;
}

static int lzms_decode_bit(struct lzms_range_decoder *rd, u32 *state_p,
                           u32 num_states,
                           struct lzms_probability_entry *probs)
{
    struct lzms_probability_entry *prob_entry = &probs[*state_p];
    u32 prob, bound;
    *state_p = (*state_p << 1) & (num_states - 1);
    prob = lzms_get_probability(prob_entry);
    if (!(rd->range & 0xFFFF0000U))
    {
        rd->range <<= 16;
        rd->code <<= 16;
        if (rd->next != rd->end)
        {
            rd->code |= rd_le16(rd->next);
            rd->next += 2;
        }
    }
    bound = (rd->range >> LZMS_PROBABILITY_BITS) * prob;
    if (rd->code < bound)
    {
        rd->range = bound;
        lzms_update_probability_entry(prob_entry, 0);
        return 0;
    }
    rd->range -= bound;
    rd->code -= bound;
    lzms_update_probability_entry(prob_entry, 1);
    *state_p |= 1;
    return 1;
}

/* ==================== backwards bitstream =============================== */
typedef u64 bitbuf_t;
struct lzms_input_bitstream
{
    bitbuf_t bitbuf;
    unsigned bitsleft;
    const u8 *next;
    const u8 *begin;
};
#define BITBUF_NBITS (8 * sizeof(bitbuf_t))

static void lzms_input_bitstream_init(struct lzms_input_bitstream *is,
                                      const u8 *in, unsigned long count)
{
    is->bitbuf = 0;
    is->bitsleft = 0;
    is->next = in + count;
    is->begin = in;
}

static void lzms_ensure_bits(struct lzms_input_bitstream *is, unsigned num_bits)
{
    unsigned avail;
    if (is->bitsleft >= num_bits)
        return;
    avail = BITBUF_NBITS - is->bitsleft;
    if (is->next != is->begin)
    {
        is->next -= 2;
        is->bitbuf |= (bitbuf_t)rd_le16(is->next) << (avail - 16);
    }
    if (is->next != is->begin)
    {
        is->next -= 2;
        is->bitbuf |= (bitbuf_t)rd_le16(is->next) << (avail - 32);
    }
    is->bitsleft += 32;
}

static bitbuf_t lzms_peek_bits(const struct lzms_input_bitstream *is,
                               unsigned num_bits)
{
    return (is->bitbuf >> 1) >> (BITBUF_NBITS - num_bits - 1);
}
static void lzms_remove_bits(struct lzms_input_bitstream *is, unsigned num_bits)
{
    is->bitbuf <<= num_bits;
    is->bitsleft -= num_bits;
}
static bitbuf_t lzms_read_bits(struct lzms_input_bitstream *is,
                               unsigned num_bits)
{
    bitbuf_t v;
    lzms_ensure_bits(is, num_bits);
    v = lzms_peek_bits(is, num_bits);
    lzms_remove_bits(is, num_bits);
    return v;
}

/* ==================== decompressor state ================================= */
struct lzms_huffman_rebuild_info
{
    unsigned num_syms_until_rebuild;
    unsigned num_syms;
    unsigned rebuild_freq;
    u32 *codewords;
    u32 *freqs;
    u16 *decode_table;
    unsigned table_bits;
};

struct lzms_decompressor
{
    struct lzms_probabilites probs;

    u16 literal_decode_table[SZ_LITERAL];
    u32 literal_freqs[LZMS_NUM_LITERAL_SYMS];
    struct lzms_huffman_rebuild_info literal_rebuild_info;

    u16 lz_offset_decode_table[SZ_OFFSET];
    u32 lz_offset_freqs[LZMS_MAX_NUM_OFFSET_SYMS];
    struct lzms_huffman_rebuild_info lz_offset_rebuild_info;

    u16 length_decode_table[SZ_LENGTH];
    u32 length_freqs[LZMS_NUM_LENGTH_SYMS];
    struct lzms_huffman_rebuild_info length_rebuild_info;

    u16 delta_offset_decode_table[SZ_OFFSET];
    u32 delta_offset_freqs[LZMS_MAX_NUM_OFFSET_SYMS];
    struct lzms_huffman_rebuild_info delta_offset_rebuild_info;

    u16 delta_power_decode_table[SZ_DELTA_POWER];
    u32 delta_power_freqs[LZMS_NUM_DELTA_POWER_SYMS];
    struct lzms_huffman_rebuild_info delta_power_rebuild_info;

    u32 codewords[LZMS_MAX_NUM_SYMS];
    u8 lens[LZMS_MAX_NUM_SYMS];
    u16 working[SZ_WORKING];
    s32 last_target_usages[65536];
};

static void lzms_build_huffman_code(struct lzms_huffman_rebuild_info *ri,
                                    u8 *lens, u16 *working)
{
    int r;
    make_canonical_huffman_code(ri->num_syms, LZMS_MAX_CODEWORD_LENGTH,
                                ri->freqs, lens, ri->codewords);
    r = make_huffman_decode_table(ri->decode_table, ri->num_syms,
                                  ri->table_bits, lens,
                                  LZMS_MAX_CODEWORD_LENGTH, working);
    (void)r;
    ri->num_syms_until_rebuild = ri->rebuild_freq;
}
static void lzms_init_huffman_code(struct lzms_huffman_rebuild_info *ri,
                                   unsigned num_syms, unsigned rebuild_freq,
                                   u32 *codewords, u32 *freqs,
                                   u16 *decode_table, unsigned table_bits,
                                   struct lzms_decompressor *d)
{
    ri->num_syms = num_syms;
    ri->rebuild_freq = rebuild_freq;
    ri->codewords = codewords;
    ri->freqs = freqs;
    ri->decode_table = decode_table;
    ri->table_bits = table_bits;
    lzms_init_symbol_frequencies(freqs, num_syms);
    lzms_build_huffman_code(ri, d->lens, d->working);
}

static void lzms_init_huffman_codes(struct lzms_decompressor *d,
                                    unsigned num_offset_slots)
{
    lzms_init_huffman_code(&d->literal_rebuild_info,
        LZMS_NUM_LITERAL_SYMS, LZMS_LITERAL_CODE_REBUILD_FREQ,
        d->codewords, d->literal_freqs, d->literal_decode_table,
        LZMS_LITERAL_TABLEBITS, d);
    lzms_init_huffman_code(&d->lz_offset_rebuild_info,
        num_offset_slots, LZMS_LZ_OFFSET_CODE_REBUILD_FREQ,
        d->codewords, d->lz_offset_freqs, d->lz_offset_decode_table,
        LZMS_LZ_OFFSET_TABLEBITS, d);
    lzms_init_huffman_code(&d->length_rebuild_info,
        LZMS_NUM_LENGTH_SYMS, LZMS_LENGTH_CODE_REBUILD_FREQ,
        d->codewords, d->length_freqs, d->length_decode_table,
        LZMS_LENGTH_TABLEBITS, d);
    lzms_init_huffman_code(&d->delta_offset_rebuild_info,
        num_offset_slots, LZMS_DELTA_OFFSET_CODE_REBUILD_FREQ,
        d->codewords, d->delta_offset_freqs, d->delta_offset_decode_table,
        LZMS_DELTA_OFFSET_TABLEBITS, d);
    lzms_init_huffman_code(&d->delta_power_rebuild_info,
        LZMS_NUM_DELTA_POWER_SYMS, LZMS_DELTA_POWER_CODE_REBUILD_FREQ,
        d->codewords, d->delta_power_freqs, d->delta_power_decode_table,
        LZMS_DELTA_POWER_TABLEBITS, d);
}

static void lzms_rebuild_huffman_code(struct lzms_huffman_rebuild_info *ri,
                                      struct lzms_decompressor *d)
{
    lzms_build_huffman_code(ri, d->lens, d->working);
    lzms_dilute_symbol_frequencies(ri->freqs, ri->num_syms);
}

static unsigned lzms_decode_huffman_symbol(struct lzms_input_bitstream *is,
                                           u16 *decode_table,
                                           unsigned table_bits,
                                           u32 *freqs,
                                           struct lzms_huffman_rebuild_info *ri,
                                           struct lzms_decompressor *d)
{
    unsigned entry, symbol, length;
    lzms_ensure_bits(is, LZMS_MAX_CODEWORD_LENGTH);
    entry = decode_table[lzms_peek_bits(is, table_bits)];
    symbol = entry >> DECODE_TABLE_SYMBOL_SHIFT;
    length = entry & DECODE_TABLE_LENGTH_MASK;
    if (entry >= (1U << (table_bits + DECODE_TABLE_SYMBOL_SHIFT)))
    {
        lzms_remove_bits(is, table_bits);
        entry = decode_table[symbol + lzms_peek_bits(is, length)];
        symbol = entry >> DECODE_TABLE_SYMBOL_SHIFT;
        length = entry & DECODE_TABLE_LENGTH_MASK;
    }
    lzms_remove_bits(is, length);
    ++freqs[symbol];
    if (--ri->num_syms_until_rebuild == 0)
        lzms_rebuild_huffman_code(ri, d);
    return symbol;
}

static unsigned lzms_decode_literal(struct lzms_decompressor *d,
                                    struct lzms_input_bitstream *is)
{
    return lzms_decode_huffman_symbol(is, d->literal_decode_table,
        LZMS_LITERAL_TABLEBITS, d->literal_freqs,
        &d->literal_rebuild_info, d);
}
static u32 lzms_decode_lz_offset(struct lzms_decompressor *d,
                                 struct lzms_input_bitstream *is)
{
    unsigned slot = lzms_decode_huffman_symbol(is, d->lz_offset_decode_table,
        LZMS_LZ_OFFSET_TABLEBITS, d->lz_offset_freqs,
        &d->lz_offset_rebuild_info, d);
    return lzms_offset_slot_base[slot] +
           (u32)lzms_read_bits(is, lzms_extra_offset_bits[slot]);
}
static u32 lzms_decode_length(struct lzms_decompressor *d,
                              struct lzms_input_bitstream *is)
{
    unsigned slot = lzms_decode_huffman_symbol(is, d->length_decode_table,
        LZMS_LENGTH_TABLEBITS, d->length_freqs,
        &d->length_rebuild_info, d);
    u32 length = lzms_length_slot_base[slot];
    unsigned num_extra_bits = lzms_extra_length_bits[slot];
    if (num_extra_bits)
        length += (u32)lzms_read_bits(is, num_extra_bits);
    return length;
}
static u32 lzms_decode_delta_offset(struct lzms_decompressor *d,
                                    struct lzms_input_bitstream *is)
{
    unsigned slot = lzms_decode_huffman_symbol(is, d->delta_offset_decode_table,
        LZMS_DELTA_OFFSET_TABLEBITS, d->delta_offset_freqs,
        &d->delta_offset_rebuild_info, d);
    return lzms_offset_slot_base[slot] +
           (u32)lzms_read_bits(is, lzms_extra_offset_bits[slot]);
}
static unsigned lzms_decode_delta_power(struct lzms_decompressor *d,
                                        struct lzms_input_bitstream *is)
{
    return lzms_decode_huffman_symbol(is, d->delta_power_decode_table,
        LZMS_DELTA_POWER_TABLEBITS, d->delta_power_freqs,
        &d->delta_power_rebuild_info, d);
}

static unsigned lzms_get_num_offset_slots(unsigned long uncompressed_size)
{
    unsigned l = 0, r = LZMS_MAX_NUM_OFFSET_SYMS - 1;
    unsigned value, slot;
    if (uncompressed_size < 2)
        return 0;
    value = (unsigned)(uncompressed_size - 1);
    for (;;)
    {
        slot = (l + r) / 2;
        if (value >= lzms_offset_slot_base[slot])
        {
            if (value < lzms_offset_slot_base[slot + 1])
                return slot + 1;
            l = slot + 1;
        }
        else
        {
            r = slot - 1;
        }
    }
}

/* ==================== x86 filter ======================================== */
static u8 g_is_potential_opcode[256];
static int g_opcode_ready = 0;

static void init_opcode_table(void)
{
    if (g_opcode_ready)
        return;
    memset(g_is_potential_opcode, 0, sizeof(g_is_potential_opcode));
    g_is_potential_opcode[0x48] = 1;
    g_is_potential_opcode[0x4C] = 1;
    g_is_potential_opcode[0xE8] = 1;
    g_is_potential_opcode[0xE9] = 1;
    g_is_potential_opcode[0xF0] = 1;
    g_is_potential_opcode[0xFF] = 1;
    g_opcode_ready = 1;
}

static u8 *find_next_opcode_default(u8 *p)
{
    for (;;)
    {
        if (g_is_potential_opcode[*p]) break; ++p;
        if (g_is_potential_opcode[*p]) break; ++p;
        if (g_is_potential_opcode[*p]) break; ++p;
        if (g_is_potential_opcode[*p]) break; ++p;
    }
    return p;
}

static u8 *translate_if_needed(u8 *data, u8 *p, s32 *last_x86_pos,
                               s32 *last_target_usages, bool undo)
{
    s32 max_trans_offset = LZMS_X86_MAX_TRANSLATION_OFFSET;
    s32 opcode_nbytes;
    u16 target16;
    s32 i;
    u32 n;

    if (p[0] >= 0xF0)
    {
        if (p[0] & 0x0F)
        {
            if (p[1] == 0x15) { opcode_nbytes = 2; goto have_opcode; }
        }
        else
        {
            if (p[1] == 0x83 && p[2] == 0x05) { opcode_nbytes = 3; goto have_opcode; }
        }
    }
    else if (p[0] <= 0x4C)
    {
        if ((p[2] & 0x07) == 0x05)
        {
            if (p[1] == 0x8D ||
                (p[1] == 0x8B && !(p[0] & 0x04) && !(p[2] & 0xF0)))
            {
                opcode_nbytes = 3;
                goto have_opcode;
            }
        }
    }
    else
    {
        if (p[0] & 0x01)
        {
            p += 4;
        }
        else
        {
            opcode_nbytes = 1;
            max_trans_offset >>= 1;
            goto have_opcode;
        }
    }
    return p + 1;

have_opcode:
    i = (s32)(p - data);
    p += opcode_nbytes;
    if (undo)
    {
        if (i - *last_x86_pos <= max_trans_offset)
        {
            n = rd_le32(p);
            wr_le32(p, n - (u32)i);
        }
        target16 = (u16)(i + rd_le16(p));
    }
    else
    {
        target16 = (u16)(i + rd_le16(p));
        if (i - *last_x86_pos <= max_trans_offset)
        {
            n = rd_le32(p);
            wr_le32(p, n + (u32)i);
        }
    }
    i += opcode_nbytes + 3;
    if (i - last_target_usages[target16] <= LZMS_X86_ID_WINDOW_SIZE)
        *last_x86_pos = i;
    last_target_usages[target16] = i;
    return p + 4;
}

static void lzms_x86_filter(u8 *data, s32 size, s32 *last_target_usages,
                            bool undo)
{
    u8 *p;
    u8 *tail_ptr;
    s32 last_x86_pos = -LZMS_X86_MAX_TRANSLATION_OFFSET - 1;
    s32 i;
    u8 saved;

    if (size <= 17)
        return;
    init_opcode_table();
    for (i = 0; i < 65536; ++i)
        last_target_usages[i] = -LZMS_X86_ID_WINDOW_SIZE - 1;

    p = data + 1;
    tail_ptr = &data[size - 16];
    saved = *(tail_ptr + 8);
    *(tail_ptr + 8) = 0xE8;
    for (;;)
    {
        p = find_next_opcode_default(p);
        if (p >= tail_ptr)
            break;
        p = translate_if_needed(data, p, &last_x86_pos,
                                last_target_usages, undo);
    }
    *(tail_ptr + 8) = saved;
}

/* ==================== main decompressor ================================= */
static int lzms_decompress(const u8 *in, unsigned long in_nbytes,
                           u8 *out, unsigned long out_nbytes,
                           struct lzms_decompressor *d)
{
    u8 *out_next = out;
    u8 *out_end = out + out_nbytes;
    struct lzms_range_decoder rd;
    struct lzms_input_bitstream is;
    u32 recent_lz_offsets[LZMS_NUM_LZ_REPS + 1];
    u64 recent_delta_pairs[LZMS_NUM_DELTA_REPS + 1];
    unsigned prev_item_type = 0;
    u32 main_state = 0, match_state = 0, lz_state = 0, delta_state = 0;
    u32 lz_rep_states[LZMS_NUM_LZ_REP_DECISIONS];
    u32 delta_rep_states[LZMS_NUM_DELTA_REP_DECISIONS];
    unsigned i;
    int rc;

    if ((in_nbytes & 1) || (in_nbytes < 4))
        return -1;

    memset(lz_rep_states, 0, sizeof(lz_rep_states));
    memset(delta_rep_states, 0, sizeof(delta_rep_states));
    lzms_range_decoder_init(&rd, in, in_nbytes);
    lzms_input_bitstream_init(&is, in, in_nbytes);
    lzms_init_probabilities(&d->probs);
    lzms_init_huffman_codes(d, lzms_get_num_offset_slots(out_nbytes));
    for (i = 0; i <= LZMS_NUM_LZ_REPS; ++i)
        recent_lz_offsets[i] = i + 1;
    for (i = 0; i <= LZMS_NUM_DELTA_REPS; ++i)
        recent_delta_pairs[i] = i + 1;

    while (out_next != out_end)
    {
        u32 offset, length, power, raw_offset, span, real_offset;
        const u8 *matchptr;
        u64 pair;

        if (!lzms_decode_bit(&rd, &main_state, LZMS_NUM_MAIN_PROBS,
                             d->probs.main))
        {
            {
                unsigned lit = lzms_decode_literal(d, &is);
                *out_next++ = (u8)lit;
            }
            prev_item_type = 0;
            continue;
        }

        if (!lzms_decode_bit(&rd, &match_state, LZMS_NUM_MATCH_PROBS,
                             d->probs.match))
        {
            /* LZ match */
            if (!lzms_decode_bit(&rd, &lz_state, LZMS_NUM_LZ_PROBS,
                                 d->probs.lz))
            {
                offset = lzms_decode_lz_offset(d, &is);
                recent_lz_offsets[3] = recent_lz_offsets[2];
                recent_lz_offsets[2] = recent_lz_offsets[1];
                recent_lz_offsets[1] = recent_lz_offsets[0];
            }
            else
            {
                if (!lzms_decode_bit(&rd, &lz_rep_states[0],
                                     LZMS_NUM_LZ_REP_PROBS, d->probs.lz_rep[0]))
                {
                    offset = recent_lz_offsets[0 + (prev_item_type & 1)];
                    recent_lz_offsets[0 + (prev_item_type & 1)] =
                        recent_lz_offsets[0];
                }
                else if (!lzms_decode_bit(&rd, &lz_rep_states[1],
                                          LZMS_NUM_LZ_REP_PROBS,
                                          d->probs.lz_rep[1]))
                {
                    offset = recent_lz_offsets[1 + (prev_item_type & 1)];
                    recent_lz_offsets[1 + (prev_item_type & 1)] =
                        recent_lz_offsets[1];
                    recent_lz_offsets[1] = recent_lz_offsets[0];
                }
                else
                {
                    offset = recent_lz_offsets[2 + (prev_item_type & 1)];
                    recent_lz_offsets[2 + (prev_item_type & 1)] =
                        recent_lz_offsets[2];
                    recent_lz_offsets[2] = recent_lz_offsets[1];
                    recent_lz_offsets[1] = recent_lz_offsets[0];
                }
            }
            recent_lz_offsets[0] = offset;
            prev_item_type = 1;
            length = lzms_decode_length(d, &is);

            if (offset > (u32)(out_next - out))
                return -1;
            matchptr = out_next - offset;
            if (length > (u32)(out_end - out_next))
                return -1;
            while (length--)
                *out_next++ = *matchptr++;
            continue;
        }

        /* Delta match */
        if (!lzms_decode_bit(&rd, &delta_state, LZMS_NUM_DELTA_PROBS,
                             d->probs.delta))
        {
            power = lzms_decode_delta_power(d, &is);
            raw_offset = lzms_decode_delta_offset(d, &is);
            pair = ((u64)power << 32) | raw_offset;
            recent_delta_pairs[3] = recent_delta_pairs[2];
            recent_delta_pairs[2] = recent_delta_pairs[1];
            recent_delta_pairs[1] = recent_delta_pairs[0];
        }
        else
        {
            if (!lzms_decode_bit(&rd, &delta_rep_states[0],
                                 LZMS_NUM_DELTA_REP_PROBS,
                                 d->probs.delta_rep[0]))
            {
                pair = recent_delta_pairs[0 + (prev_item_type >> 1)];
                recent_delta_pairs[0 + (prev_item_type >> 1)] =
                    recent_delta_pairs[0];
            }
            else if (!lzms_decode_bit(&rd, &delta_rep_states[1],
                                      LZMS_NUM_DELTA_REP_PROBS,
                                      d->probs.delta_rep[1]))
            {
                pair = recent_delta_pairs[1 + (prev_item_type >> 1)];
                recent_delta_pairs[1 + (prev_item_type >> 1)] =
                    recent_delta_pairs[1];
                recent_delta_pairs[1] = recent_delta_pairs[0];
            }
            else
            {
                pair = recent_delta_pairs[2 + (prev_item_type >> 1)];
                recent_delta_pairs[2 + (prev_item_type >> 1)] =
                    recent_delta_pairs[2];
                recent_delta_pairs[2] = recent_delta_pairs[1];
                recent_delta_pairs[1] = recent_delta_pairs[0];
            }
            power = (u32)(pair >> 32);
            raw_offset = (u32)pair;
        }
        recent_delta_pairs[0] = pair;
        prev_item_type = 2;
        length = lzms_decode_length(d, &is);

        span = 1U << power;
        real_offset = raw_offset << power;
        if ((real_offset >> power) != raw_offset)
            return -1;
        if (real_offset + span < real_offset)
            return -1;
        if (real_offset + span > (u32)(out_next - out))
            return -1;
        if (length > (u32)(out_end - out_next))
            return -1;
        matchptr = out_next - real_offset;
        do
        {
            *out_next = (u8)(*matchptr + *(out_next - span) -
                             *(matchptr - span));
            ++out_next;
            ++matchptr;
        } while (--length);
    }

    lzms_x86_filter(out, (s32)out_nbytes, d->last_target_usages, true);
    rc = 0;
    return rc;
}

int LzmsRawDecompress(const unsigned char *in, unsigned long inLen,
                      unsigned char *out, unsigned long outLen)
{
    struct lzms_decompressor *d;
    int result;

    if (!in || !out || inLen < 4 || (inLen & 1) ||
        outLen > LZMS_MAX_BUFFER_SIZE)
        return -1;
    d = (struct lzms_decompressor *)calloc(1, sizeof(*d));
    if (!d)
        return -1;
    result = lzms_decompress(in, inLen, out, outLen, d);
    if (result != 0 && inLen == outLen)
    {
        /* Windows stores incompressible LZMS blocks verbatim. */
        memcpy(out, in, (size_t)outLen);
        result = 0;
    }
    free(d);
    return result;
}

/* dpx wraps LZMS blocks in a stream beginning with 0x01584344.  Each
 * chunk has a 16-byte header: [compressedSize, 0, uncompressedSize, 0]. */
int LzmsDecompressData(const unsigned char *in, unsigned long inLen,
                       unsigned char *out, unsigned long outLen)
{
    unsigned long pos;
    unsigned long outPos;

    if (!in || !out)
        return -1;
    if (inLen < 4 ||
        (in[0] | (in[1] << 8) | (in[2] << 16) | ((unsigned long)in[3] << 24))
            != 0x01584344UL)
        return LzmsRawDecompress(in, inLen, out, outLen);

    pos = 4;
    outPos = 0;
    while (pos + 16 <= inLen)
    {
        unsigned long compSize = (unsigned long)in[pos] |
            ((unsigned long)in[pos + 1] << 8) |
            ((unsigned long)in[pos + 2] << 16) |
            ((unsigned long)in[pos + 3] << 24);
        unsigned long rawSize = (unsigned long)in[pos + 8] |
            ((unsigned long)in[pos + 9] << 8) |
            ((unsigned long)in[pos + 10] << 16) |
            ((unsigned long)in[pos + 11] << 24);
        if (compSize > inLen - pos - 16 || rawSize > outLen - outPos)
            return -1;
        if (LzmsRawDecompress(in + pos + 16, compSize,
                              out + outPos, rawSize) != 0)
            return -1;
        pos += 16 + compSize;
        outPos += rawSize;
    }
    return (outPos == outLen) ? 0 : -1;
}
