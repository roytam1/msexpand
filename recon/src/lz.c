/*
 * lz.c -- classic "SZDD" LZ expansion, faithful to the decompiled
 * Expand/ExpandOrCopyFile/GetHdr/LZDecode/ReadInBuf/WriteOutBuf code.
 */
#include "expand.h"

#define LZ_SIG0 'S'
#define LZ_SIG1 'Z'
#define LZ_SIG2 'D'
#define LZ_SIG3 'D'
/* The eight-byte comparison string used by IsCompressed in expand.exe is
   "SZDD" followed by the COMPRESS.EXE magic 88 F0 27 33. */
static const unsigned char g_LzMagic[8] = {
    'S', 'Z', 'D', 'D', 0x88, 0xF0, 0x27, 0x33
};

typedef struct tagLZHEADER
{
    unsigned char b[20];
} LZHEADER;

/* ------------------------------------------------------------------ */
static int ReadLittle32(const unsigned char *p)
{
    return (int)((unsigned long)p[0] |
                 ((unsigned long)p[1] << 8) |
                 ((unsigned long)p[2] << 16) |
                 ((unsigned long)p[3] << 24));
}

/* Reads the 14-byte header.  Returns 1 on success, negative on error. */
static int GetHdr(LZHEADER *hdr, HFILE fd, long *filesize)
{
    unsigned char raw[16];
    UINT n;

    *filesize = _llseek(fd, 0L, SEEK_END);
    if (*filesize < 0 || _llseek(fd, 0L, SEEK_SET) != 0L)
        return -1;
    n = _lread(fd, raw, 14);
    if (n != 14)
        return (n == (UINT)-1) ? -3 : -2;

    memcpy(hdr->b, raw, 10);
    hdr->b[10] = (unsigned char)((*(unsigned long *)(raw + 10)) & 0xFF);
    hdr->b[11] = (unsigned char)((*(unsigned long *)(raw + 10)) >> 8);
    hdr->b[12] = (unsigned char)((*(unsigned long *)(raw + 10)) >> 16);
    hdr->b[13] = (unsigned char)((*(unsigned long *)(raw + 10)) >> 24);
    memset(hdr->b + 14, 0, 6);
    *(long *)(hdr->b + 16) = *filesize;
    return 1;
}

static int IsCompressed(const LZHEADER *hdr)
{
    return memcmp(hdr->b, g_LzMagic, 8) == 0;
}

/* ------------------------------------------------------------------ */
LZCTL *InitGlobalBuffers(void)
{
    LZCTL *c;
    int sizes[2];
    int i;

    c = (LZCTL *)LocalAlloc(LMEM_FIXED, sizeof(LZCTL));
    if (!c)
        return NULL;
    memset(c, 0, sizeof(LZCTL));

    sizes[0] = 32768;
    sizes[1] = 32768;
    c->in_size = sizes[0];
    c->out_size = sizes[1];
    c->dict = (unsigned char *)LocalAlloc(LMEM_FIXED, 4224);
    c->inbuf = (unsigned char *)LocalAlloc(LMEM_FIXED, (UINT)c->in_size + 1);
    c->outbuf = (unsigned char *)LocalAlloc(LMEM_FIXED, (UINT)c->out_size);
    while ((!c->inbuf || !c->outbuf) && c->in_size > 0)
    {
        c->in_size -= 1024;
        c->out_size -= 1024;
        if (c->inbuf) LocalFree(c->inbuf);
        if (c->outbuf) LocalFree(c->outbuf);
        c->inbuf = (unsigned char *)LocalAlloc(LMEM_FIXED,
                                                (UINT)c->in_size + 1);
        c->outbuf = (unsigned char *)LocalAlloc(LMEM_FIXED,
                                                 (UINT)c->out_size);
    }
    if (!c->dict || !c->inbuf || !c->outbuf)
    {
        FreeGlobalBuffers(c);
        return NULL;
    }
    for (i = 0; i < 4096 - 16; ++i)
        c->dict[i] = 0x20;
    return c;
}

void FreeGlobalBuffers(LZCTL *c)
{
    if (!c)
        return;
    if (c->dict)  LocalFree(c->dict);
    if (c->inbuf) LocalFree(c->inbuf);
    if (c->outbuf) LocalFree(c->outbuf);
    LocalFree(c);
}

/* ------------------------------------------------------------------ */
/* The core token decoder.  Decodes exactly dstLen bytes.              */
static int LzDecodeData(const unsigned char *src, int srcLen,
                        unsigned char *dst, int dstLen)
{
    unsigned char dict[4096];
    int dictpos;
    int bitbuf;
    int spos;
    int opos;
    int i;
    int token;
    int b;
    int dist;
    int len;
    unsigned char ch;

    for (i = 0; i < 4096 - 16; ++i)
        dict[i] = 0x20;
    dictpos = 4096 - 16;
    bitbuf = 0;
    spos = 0;
    opos = 0;

    while (opos < dstLen)
    {
        bitbuf >>= 1;
        if ((bitbuf & 0x100) == 0)
        {
            if (spos >= srcLen)
                return 1;       /* soft EOF -- size field terminates */
            bitbuf = (int)src[spos++] | 0xFF00;
        }
        if (spos >= srcLen)
            return 1;
        token = (int)src[spos++];

        if (bitbuf & 1)
        {
            /* Literal byte. */
            if (opos < dstLen)
                dst[opos++] = (unsigned char)token;
            dict[dictpos] = (unsigned char)token;
            dictpos = (dictpos + 1) & 0xFFF;
        }
        else
        {
            /* Back-reference: 12-bit ring index + length 3..18. */
            if (spos >= srcLen)
                return -3;
            b = (int)src[spos++];
            dist = ((b & 0xF0) << 4) | token;
            len = (b & 0x0F) + 3;
            for (i = 0; i < len && opos < dstLen; ++i)
            {
                ch = dict[(dist + i) & 0xFFF];
                dst[opos++] = ch;
                dict[dictpos] = ch;
                dictpos = (dictpos + 1) & 0xFFF;
            }
        }
    }
    return 1;
}

/* ------------------------------------------------------------------ */
static int ExpandOrCopyFile(HFILE hIn, HFILE hOut, LZCTL *c, LZHEADER *hdr)
{
    unsigned char *inData;
    unsigned char *outData;
    long inSize;
    int outSize;
    int result;
    UINT written;
    FILETIME ftCreation, ftAccess, ftWrite;
    int haveTime;

    inSize = c->filesize;
    inData = (unsigned char *)malloc((size_t)(inSize > 0 ? inSize : 1));
    if (!inData)
        return -1;
    _llseek(hIn, 0L, SEEK_SET);
    if (_lread(hIn, inData, (UINT)inSize) != (UINT)inSize)
    {
        free(inData);
        return -1;
    }

    haveTime = GetFileTime((HANDLE)hIn, &ftCreation, &ftAccess, &ftWrite);

    if (IsCompressed(hdr))
    {
        unsigned char version = hdr->b[8];
        if (version != 'A')
        {
            free(inData);
            return -8;
        }
        outSize = ReadLittle32(hdr->b + 10);
        outData = (unsigned char *)malloc((size_t)(outSize > 0 ? outSize : 1));
        if (!outData)
        {
            free(inData);
            return -1;
        }
        result = LzDecodeData(inData + 14, (int)inSize - 14,
                              outData, outSize);
        c->out_count = outSize;
        if (result == 1)
        {
            _llseek(hOut, 0L, SEEK_SET);
            written = _lwrite(hOut, (LPSTR)outData, (UINT)outSize);
            if (written == (UINT)-1)
                result = -4;
            else if ((int)written != outSize)
                result = -2;
        }
        free(outData);
    }
    else
    {
        outSize = (int)inSize;
        _llseek(hIn, 0L, SEEK_SET);
        _llseek(hOut, 0L, SEEK_SET);
        written = _lwrite(hOut, (LPSTR)inData, (UINT)inSize);
        c->out_count = (int)written;
        if (written == (UINT)-1)
            result = -4;
        else if ((int)written != outSize)
            result = -2;
        else
            result = 1;
    }
    free(inData);

    if (result == 1 && haveTime)
        SetFileTime((HANDLE)hOut, &ftCreation, &ftAccess, &ftWrite);
    return result;
}

/* ------------------------------------------------------------------ */
int Expand(LZCTL *c)
{
    LZHEADER hdr;
    HFILE hIn = -1;
    HFILE hOut;
    long size;
    int result;
    char dest[MAX_PATH];
    int compressed;
    int action;

    if (!c)
        return -6;

    hIn = _lopen(g_pszInFileName, OF_READ);
    if (hIn == -1)
        return -1;
    size = _llseek(hIn, 0L, SEEK_END);
    _llseek(hIn, 0L, SEEK_SET);
    if (size < 0)
    {
        _lclose(hIn);
        return -1;
    }
    c->filesize = size;

    result = GetHdr(&hdr, hIn, &size);
    if (result != 1 && size >= 14)
    {
        _lclose(hIn);
        return -1;
    }

    if (!g_pszOutFileName)
    {
        _lclose(hIn);
        return -7;
    }

    strncpy(dest, g_pszOutFileName, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = 0;
    compressed = IsCompressed(&hdr);
    if (g_bDoRename)
    {
        /* Restore the '_' placeholder at the end of the name with the
           expansion character stored in byte 9 of the SZDD header. */
        size_t n = strlen(dest);
        char expchar = (char)hdr.b[9];
        const char *p;
        if (n > 0 && dest[n - 1] == '_')
        {
            for (p = dest; *p; ++p)
            {
                if (*p >= 'A' && *p <= 'Z')
                {
                    if (expchar >= 'a' && expchar <= 'z')
                        expchar = (char)(expchar - 32);
                    break;
                }
                if (*p >= 'a' && *p <= 'z')
                {
                    if (expchar >= 'A' && expchar <= 'Z')
                        expchar = (char)(expchar + 32);
                    break;
                }
            }
            dest[n - 1] = expchar;
        }
    }

    action = 2 - compressed;
    if (!ProcessNotification(g_pszInFileName, dest, action))
    {
        _lclose(hIn);
        return 0;
    }

    hOut = _lcreat(dest, 0);
    if (hOut == -1)
    {
        _lclose(hIn);
        return -2;
    }

    result = ExpandOrCopyFile(hIn, hOut, c, &hdr);
    _lclose(hIn);
    _lclose(hOut);
    return result;
}

/* ProcessNotification is implemented in expand.c (shared with DPX). */
