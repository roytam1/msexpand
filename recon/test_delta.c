#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "delta.h"
static unsigned char *rd(const char *p, unsigned long *n)
{
    FILE *f = fopen(p, "rb");
    unsigned char *b;
    long l;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); l = ftell(f); fseek(f, 0, SEEK_SET);
    b = (unsigned char *)malloc((size_t)(l > 0 ? l : 1));
    if (!b || fread(b, 1, (size_t)l, f) != (size_t)l) { free(b); fclose(f); return NULL; }
    fclose(f); *n = (unsigned long)l; return b;
}
int main(int argc, char **argv)
{
    unsigned long dl, sl, ol, bad = 0, i;
    unsigned char *d, *s, *o, *t;
    int r;
    if (argc < 4) return 2;
    d = rd(argv[1], &dl);
    s = rd(argv[2], &sl);
    if (!d || !s) return 2;
    r = DeltaApply(d, dl, s, sl, &o, &ol);
    printf("DeltaApply r=%d out=%lu\n", r, ol);
    if (r != 0 || !o) { free(d); free(s); return 1; }
    if (getenv("DELTA_OUT"))
    {
        FILE *f = fopen(getenv("DELTA_OUT"), "wb");
        if (f) { fwrite(o, 1, ol, f); fclose(f); }
    }
    t = rd(argv[3], &ol);
    if (t)
    {
        for (i = 0; i < ol; ++i)
            if (o[i] != t[i]) ++bad;
        printf("compare: %lu / %lu bytes differ\n", bad, ol);
        if (bad)
        {
            for (i = 0; i < ol; ++i)
                if (o[i] != t[i])
                    printf("diff %lu: got %02X expected %02X\n",
                           i, o[i], t[i]);
        }
        free(t);
    }
    free(o); free(d); free(s);
    return bad ? 1 : 0;
}
