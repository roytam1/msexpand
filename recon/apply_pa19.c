/* apply_pa19.c -- OS oracle for PA19 patches using mspatcha.dll. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
typedef BOOL (WINAPI *ApplyFn)(unsigned char *, ULONG, unsigned char *, ULONG,
                               unsigned char **, ULONG, ULONG *, FILETIME *,
                               ULONG, void *, void *);
static unsigned char *rd(const char *path, long *n)
{
    FILE *f = fopen(path, "rb");
    unsigned char *b;
    long l;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); l = ftell(f); fseek(f, 0, SEEK_SET);
    b = (unsigned char *)malloc((size_t)(l > 0 ? l : 1));
    if (fread(b, 1, (size_t)l, f) != (size_t)l) { free(b); fclose(f); return NULL; }
    fclose(f); *n = l; return b;
}
int main(int argc, char **argv)
{
    HMODULE m;
    ApplyFn apply;
    unsigned char *patch, *src, *out = NULL;
    long pl, sl;
    ULONG outSize = 0, actual = 0;
    FILE *f;
    BOOL ok;
    if (argc < 4) return 2;
    m = LoadLibraryA("mspatcha.dll");
    if (!m) return 1;
    apply = (ApplyFn)GetProcAddress(m, "ApplyPatchToFileByBuffers");
    if (!apply) return 1;
    patch = rd(argv[1], &pl);
    src = rd(argv[2], &sl);
    if (!patch || !src) return 2;
    outSize = 32 * 1024 * 1024;
    out = (unsigned char *)malloc(outSize);
    ok = apply(patch, (ULONG)pl, src, (ULONG)sl, &out, outSize,
               &actual, NULL, 0, NULL, NULL);
    printf("apply ok=%d err=%lu size=%lu\n", ok, GetLastError(), actual);
    if (ok && actual)
    {
        f = fopen(argv[3], "wb");
        if (f) { fwrite(out, 1, actual, f); fclose(f); }
    }
    free(out); free(patch); free(src);
    FreeLibrary(m);
    return ok ? 0 : 1;
}
