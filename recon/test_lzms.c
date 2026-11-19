/* test_lzms.c -- validate the C89 LZMS port against OS-generated vectors. */
#include <stdio.h>
#include <stdlib.h>
#include "lzms.h"

static unsigned char *ReadFileBytes(const char *path, unsigned long *size)
{
    FILE *fp;
    unsigned char *buf;
    long n;
    fp = fopen(path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    buf = (unsigned char *)malloc((size_t)(n > 0 ? n : 1));
    if (!buf || fread(buf, 1, (size_t)n, fp) != (size_t)n)
    {
        free(buf);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    *size = (unsigned long)n;
    return buf;
}

int main(void)
{
    int pass = 0, fail = 0;
    int i;
    for (i = 0; i < 6; ++i)
    {
        char tag[32];
        char ipath[256], cpath[256];
        unsigned long inLen, compLen, got;
        unsigned char *in, *comp, *out;
        int r;
        sprintf(tag, "v%d", i);
        sprintf(ipath, "lzms/%s_in.bin", tag);
        sprintf(cpath, "lzms/%s_comp.bin", tag);
        in = ReadFileBytes(ipath, &inLen);
        comp = ReadFileBytes(cpath, &compLen);
        if (!in || !comp)
        {
            printf("%s: missing vector\n", tag);
            ++fail;
            free(in);
            free(comp);
            continue;
        }
        out = (unsigned char *)malloc((size_t)(inLen > 0 ? inLen : 1));
        got = 0;
        r = LzmsRawDecompress(comp, compLen, out, inLen);
        if (r == 0 && memcmp(out, in, (size_t)inLen) == 0)
        {
            printf("%s: PASS (%lu -> %lu)\n", tag, compLen, inLen);
            ++pass;
        }
        else
        {
            printf("%s: FAIL r=%d (%lu -> %lu)\n", tag, r, compLen, inLen);
            if (inLen >= 16)
            {
                unsigned long k;
                printf("  expected: ");
                for (k = 0; k < 16; ++k) printf("%02X ", in[k]);
                printf("\n  decoded : ");
                for (k = 0; k < 16; ++k) printf("%02X ", out[k]);
                printf("\n");
            }
            ++fail;
        }
        free(out);
        free(in);
        free(comp);
    }
    printf("LZMS vectors: %d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
