/* test_xpress.c -- run the go-ntfs XPRESS vectors against the C89 port. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xpress.h"

static unsigned char *ReadFileBytes(const char *path, long *size)
{
    FILE *fp;
    unsigned char *buf;
    long n;
    fp = fopen(path, "rb");
    if (!fp)
        return NULL;
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
    *size = n;
    return buf;
}

int main(void)
{
    FILE *mf;
    char line[512];
    int pass = 0;
    int fail = 0;

    mf = fopen("xpress/manifest.txt", "r");
    if (!mf)
    {
        printf("cannot open xpress/manifest.txt\n");
        return 1;
    }
    while (fgets(line, sizeof(line), mf))
    {
        char tag[16];
        char huffStr[16];
        int huff;
        long dlen, elen;
        char name[256];
        char dpath[256], epath[256];
        unsigned char *data, *expect, *out;
        unsigned long got;
        int r;
        int ok;

        if (sscanf(line, "%15[^|]|%15[^|]|%ld|%ld|%255[^\r\n]",
                   tag, huffStr, &dlen, &elen, name) != 5)
            continue;
        huff = (strcmp(huffStr, "True") == 0);
        sprintf(dpath, "xpress/%s_data.bin", tag);
        sprintf(epath, "xpress/%s_expected.bin", tag);
        data = ReadFileBytes(dpath, &dlen);
        expect = ReadFileBytes(epath, &elen);
        if (!data || !expect)
        {
            printf("%s: cannot load vector\n", tag);
            ++fail;
            free(data);
            free(expect);
            continue;
        }
        out = (unsigned char *)malloc((size_t)(elen > 0 ? elen : 1));
        got = 0;
        if (huff)
            r = XpressHuffmanDecompress(data, (unsigned long)dlen,
                                        out, (unsigned long)elen);
        else
            r = XpressDecompress(data, (unsigned long)dlen, out,
                                 (unsigned long)elen, &got);
        ok = (r == 0) && (memcmp(out, expect, (size_t)elen) == 0) &&
             (huff || got == (unsigned long)elen);
        if (ok)
            ++pass;
        else
        {
            ++fail;
            printf("%s FAIL: r=%d got=%lu/%ld huff=%d [%s]\n",
                   tag, r, got, elen, huff, name);
        }
        free(out);
        free(data);
        free(expect);
    }
    fclose(mf);
    printf("XPRESS vectors: %d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
