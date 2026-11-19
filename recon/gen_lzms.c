/* gen_lzms.c -- generate raw-LZMS vectors using the OS compression API. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void *HCOMPRESSOR;
typedef LONG (WINAPI *CreateCompressorFn)(DWORD, void *, HCOMPRESSOR *);
typedef LONG (WINAPI *CompressFn)(HCOMPRESSOR, LPCVOID, SIZE_T, LPVOID,
                                  SIZE_T, PSIZE_T);
typedef LONG (WINAPI *CloseCompressorFn)(HCOMPRESSOR);

#define COMPRESS_ALGORITHM_LZMS 5
#define COMPRESS_RAW            0x20000000UL

static CreateCompressorFn pCreate;
static CompressFn         pCompress;
static CloseCompressorFn  pClose;

static unsigned char *MakeInput(int kind, unsigned long n)
{
    unsigned char *buf = (unsigned char *)malloc(n);
    unsigned long i;
    switch (kind)
    {
    case 0:
        for (i = 0; i < n; ++i) buf[i] = (unsigned char)('A' + (i % 26));
        break;
    case 1:
        for (i = 0; i < n; ++i) buf[i] = (unsigned char)(i * 7 + 3);
        break;
    case 2:
        for (i = 0; i < n; ++i)
            buf[i] = (unsigned char)((i % 3 == 0) ? i >> 8 : 'x' + (i % 5));
        break;
    default:
        for (i = 0; i < n; ++i) buf[i] = (unsigned char)(rand());
        break;
    }
    return buf;
}

static int GenOne(const char *tag, int kind, unsigned long n)
{
    unsigned char *in = MakeInput(kind, n);
    unsigned char *comp;
    SIZE_T compSize = 0;
    SIZE_T outSize = 0;
    HCOMPRESSOR h = NULL;
    LONG st;
    char path[256];
    FILE *fp;
    int ok = 0;

    st = pCreate(COMPRESS_ALGORITHM_LZMS | COMPRESS_RAW, NULL, &h);
    if (st != 1 || !h)
    {
        printf("%s: CreateCompressor failed %ld\n", tag, st);
        free(in);
        return 0;
    }
    st = pCompress(h, in, n, NULL, 0, &compSize);
    if (compSize == 0)
    {
        printf("%s: size query failed %ld\n", tag, st);
        pClose(h);
        free(in);
        return 0;
    }
    comp = (unsigned char *)malloc(compSize * 2 + 64);
    outSize = compSize * 2 + 64;
    st = pCompress(h, in, n, comp, outSize, &compSize);
    pClose(h);
    if (st != 1)
    {
        printf("%s: Compress failed %ld\n", tag, st);
        free(comp);
        free(in);
        return 0;
    }
    sprintf(path, "lzms/%s_in.bin", tag);
    fp = fopen(path, "wb");
    if (fp) { fwrite(in, 1, n, fp); fclose(fp); }
    sprintf(path, "lzms/%s_comp.bin", tag);
    fp = fopen(path, "wb");
    if (fp) { fwrite(comp, 1, compSize, fp); fclose(fp); ok = 1; }
    printf("%s: %lu -> %lu bytes\n", tag, n, (unsigned long)compSize);
    free(comp);
    free(in);
    return ok;
}

int main(void)
{
    HMODULE hmod = LoadLibraryA("cabinet.dll");
    int ok = 0;
    int i;

    if (!hmod)
    {
        printf("cannot load cabinet.dll\n");
        return 1;
    }
    pCreate = (CreateCompressorFn)GetProcAddress(hmod, "CreateCompressor");
    pCompress = (CompressFn)GetProcAddress(hmod, "Compress");
    pClose = (CloseCompressorFn)GetProcAddress(hmod, "CloseCompressor");
    if (!pCreate || !pCompress || !pClose)
    {
        printf("compression API not available\n");
        FreeLibrary(hmod);
        return 1;
    }
    srand(12345);
    ok = 1;
    for (i = 0; i < 6; ++i)
    {
        char tag[32];
        unsigned long sizes[6] = { 64, 512, 4096, 32768, 65536, 60000 };
        int kinds[6] = { 0, 1, 2, 3, 0, 2 };
        sprintf(tag, "v%d", i);
        if (!GenOne(tag, kinds[i], sizes[i])) ok = 0;
    }
    FreeLibrary(hmod);
    return ok ? 0 : 1;
}
