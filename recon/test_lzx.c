/* test_lzx.c -- differential/validation driver for lzx.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lzx.h"

static unsigned char *read_file(const char *path, unsigned long *len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    long n;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET)) {
        fclose(f); return NULL;
    }
    buf = (unsigned char *)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    *len = (unsigned long)n;
    return buf;
}

int main(int argc, char **argv)
{
    unsigned char *comp, *expected, *out;
    unsigned long compLen, expLen, i;
    int windowBits, rc, bad = 0;

    if (argc < 5) {
        fprintf(stderr, "usage: %s <vector.bin> <expected.bin> <outlen> <windowBits>\n", argv[0]);
        return 2;
    }
    windowBits = atoi(argv[4]);
    comp = read_file(argv[1], &compLen);
    expected = read_file(argv[2], &expLen);
    if (!comp || !expected) { fprintf(stderr, "read failed\n"); return 2; }

    out = (unsigned char *)malloc((size_t)expLen + 1);
    if (!out) return 2;
    memset(out, 0xCC, (size_t)expLen + 1);

    rc = LzxRawDecompress(comp, compLen, out, expLen, windowBits);
    printf("LzxRawDecompress: in=%lu out=%lu wb=%d rc=%d\n",
           compLen, expLen, windowBits, rc);

    if (rc != 0) {
        printf("RESULT: DECOMPRESS FAILED\n");
        bad = 1;
    } else {
        for (i = 0; i < expLen; ++i) {
            if (out[i] != expected[i]) {
                printf("MISMATCH at %lu: got %02X expected %02X\n",
                       i, out[i], expected[i]);
                bad = 1;
                break;
            }
        }
        if (!bad) {
            printf("first16:");
            for (i = 0; i < expLen && i < 16; ++i) printf(" %02X", out[i]);
            printf("\nRESULT: %s\n", "PASS");
        }
    }
    free(comp); free(expected); free(out);
    return bad;
}
