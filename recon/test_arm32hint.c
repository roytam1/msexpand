/* Unit check for the ARM32 hint mask built before RiftTransformDisasmARM.
 *
 * The reference (msdelta.dll.c MarkNonExeCli4 + imports/exports/relocs)
 * produces: ordinary executable bytes 0, non-executable section bytes 1,
 * PE headers and data-directory ranges 3, import/export text 3, and
 * supported relocation sites 1 (bit 0 only, so the disassembler still
 * rewrites an instruction that merely starts at a relocation site but
 * stops at any interior byte marked 2). */
#include <stdio.h>
#include <string.h>
#include "delta.c"

static void w16(unsigned char *b, unsigned long o, unsigned v)
{
    b[o] = (unsigned char)v;
    b[o + 1] = (unsigned char)(v >> 8);
}

static void w32(unsigned char *b, unsigned long o, unsigned long v)
{
    w16(b, o, (unsigned)v);
    w16(b, o + 2, (unsigned)(v >> 16));
}

int main(void)
{
    unsigned char image[0x800];
    unsigned char hint[0x800];
    const unsigned long opt = 0x98;
    const unsigned long sh = opt + 0xE0;
    const unsigned long dd = opt + 0x60;
    const unsigned long ed = 0x380;   /* export directory, RVA 0x1180 */

    memset(image, 0, sizeof(image));
    memset(hint, 0, sizeof(hint));

    /* PE32 ARMNT image: .text at RVA 0x1000/raw 0x200, .pdata at
     * RVA 0x2000/raw 0x400. */
    image[0] = 'M';
    image[1] = 'Z';
    w32(image, 0x3C, 0x80);
    memcpy(image + 0x80, "PE\0\0", 4);
    w16(image, 0x84, 0x1C4);
    w16(image, 0x86, 2);
    w16(image, 0x94, 0xE0);
    w16(image, opt, 0x10B);
    w32(image, opt + 0x38, 0x5000);
    w32(image, opt + 0x3C, 0x200);

    memcpy(image + sh, ".text", 5);
    w32(image, sh + 8, 0x200);
    w32(image, sh + 12, 0x1000);
    w32(image, sh + 16, 0x200);
    w32(image, sh + 20, 0x200);
    w32(image, sh + 36, 0x60000020UL);

    memcpy(image + sh + 40, ".pdata", 6);
    w32(image, sh + 48, 0x200);
    w32(image, sh + 52, 0x2000);
    w32(image, sh + 56, 0x200);
    w32(image, sh + 60, 0x400);
    w32(image, sh + 76, 0x40000040UL);

    /* Data directories: export at RVA 0x1180/0x28, import at
     * RVA 0x1100/0x28, base relocations at RVA 0x2100/0x0C. */
    w32(image, dd, 0x1180);
    w32(image, dd + 4, 0x28);
    w32(image, dd + 8, 0x1100);
    w32(image, dd + 12, 0x28);
    w32(image, dd + 40, 0x2100);
    w32(image, dd + 44, 0x0C);

    /* Export directory: file table at RVA 0x11C0 (2 dwords), name table
     * at RVA 0x11D0 (2 dwords), ordinal table at RVA 0x11E8 (2 words). */
    w32(image, ed + 12, 0x11E0);
    w32(image, ed + 16, 1);
    w32(image, ed + 20, 2);
    w32(image, ed + 24, 2);
    w32(image, ed + 28, 0x11C0);
    w32(image, ed + 32, 0x11D0);
    w32(image, ed + 36, 0x11E8);

    /* Import descriptor at RVA 0x1100. */
    w32(image, 0x300, 0x1300);
    w32(image, 0x310, 0x1300);

    /* One type-3 relocation for RVA 0x1020 (raw 0x220). */
    w32(image, 0x500, 0x1000);
    w32(image, 0x504, 0x0C);
    w16(image, 0x508, 0x3020);

    pa30_mark_arm32_hint(image, sizeof(image), hint);
    printf("hint: hdr=%u text=%u reloc=%u nonexec=%u import=%u export=%u\n",
           hint[0], hint[0x210], hint[0x220], hint[0x410],
           hint[0x300], hint[ed]);

    if (hint[0] != 3) {                       /* PE headers              */
        fprintf(stderr, "header mark %u != 3\n", hint[0]);
        return 1;
    }
    if (hint[0x210] != 0) {                   /* plain .text byte        */
        fprintf(stderr, "text mark %u != 0\n", hint[0x210]);
        return 1;
    }
    if (hint[0x220] != 1 || hint[0x223] != 1) {   /* HIGHLOW site        */
        fprintf(stderr, "relocation mark %u/%u != 1\n", hint[0x220], hint[0x223]);
        return 1;
    }
    if (hint[0x410] != 1) {                   /* non-executable section  */
        fprintf(stderr, "nonexe mark %u != 1\n", hint[0x410]);
        return 1;
    }
    if (hint[0x300] != 3 || hint[0x313] != 3) {   /* import descriptor   */
        fprintf(stderr, "import mark %u/%u != 3\n", hint[0x300], hint[0x313]);
        return 1;
    }
    if (hint[ed] != 3 || hint[ed + 39] != 3) {    /* export directory    */
        fprintf(stderr, "export mark %u/%u != 3\n", hint[ed], hint[ed + 39]);
        return 1;
    }
    if (hint[0x3C0] != 3 || hint[0x3C4] != 3 ||    /* EAT                 */
        hint[0x3D0] != 3 || hint[0x3D4] != 3 ||    /* name table          */
        hint[0x3E8] != 3 || hint[0x3E9] != 3) {    /* ordinal table       */
        fprintf(stderr, "export array marks %u/%u/%u/%u/%u/%u != 3\n",
                hint[0x3C0], hint[0x3C4], hint[0x3D0], hint[0x3D4],
                hint[0x3E8], hint[0x3E9]);
        return 1;
    }
    printf("ARM32 hint mask: PASS\n");
    return 0;
}
