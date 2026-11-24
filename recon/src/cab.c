/*
 * cab.c -- minimal self-contained CAB (MSCF) reader.
 *
 * Supports compression types 0 (none) and 1 (MSZIP / raw deflate), which
 * covers the cabinets expanded by the original tool through dpx.dll for
 * ordinary use.  Other compression types report MSG_BAD_SCHEME.
 */
#include "expand.h"
#include "lzx.h"

/* The bit buffer is preloaded per CFDATA block with LzxDecodeBlock(). */
static int CabLzxFill(void *ctx, unsigned char *buf, unsigned long want)
{
    (void)ctx; (void)buf; (void)want;
    return 0;
}

/* ------------------------------------------------------------------ */
/* A small raw-DEFLATE (inflate) implementation.                        */
/* ------------------------------------------------------------------ */
typedef struct tagHUFF
{
    int count[16];
    int first[16];
    int symbol[288];
} HUFF;

typedef struct tagINFLATE
{
    const unsigned char *in;
    int inLen;
    int bitPos;
    unsigned char *win;         /* 32 KiB sliding window */
    int winPos;
    unsigned char *out;
    int outCap;
    int outLen;
} INFLATE;

static int GetBit(INFLATE *z)
{
    int v;
    if (z->bitPos >= z->inLen * 8)
        return 0;
    v = (z->in[z->bitPos >> 3] >> (z->bitPos & 7)) & 1;
    ++z->bitPos;
    return v;
}

static int GetBits(INFLATE *z, int n)
{
    int v = 0;
    int i;
    for (i = 0; i < n; ++i)
        v |= GetBit(z) << i;
    return v;
}

static void HuffBuild(HUFF *h, const unsigned char *lengths, int n)
{
    int i, len, code, index;

    for (len = 0; len < 16; ++len)
        h->count[len] = 0;
    for (i = 0; i < n; ++i)
        ++h->count[lengths[i]];
    h->count[0] = 0;

    code = 0;
    for (len = 1; len < 16; ++len)
    {
        code = (code + h->count[len - 1]) << 1;
        h->first[len] = code;
    }

    /* Symbols are stored grouped by increasing code length; the decoder
       uses 'first' and 'count' to locate the right group.  Canonical code
       VALUES must never be used as indices here: they can exceed n. */
    index = 0;
    for (len = 1; len < 16; ++len)
    {
        for (i = 0; i < n; ++i)
        {
            if (lengths[i] == len)
                h->symbol[index++] = i;
        }
    }
}

static int HuffDecode(INFLATE *z, const HUFF *h)
{
    int code = 0;
    int first = 0;
    int index = 0;
    int len, count;

    for (len = 1; len < 16; ++len)
    {
        code |= GetBit(z);
        count = h->count[len];
        if (code - count < first)
            return h->symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

static const unsigned short g_LenBase[29] = {
    3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,
    67,83,99,115,131,163,195,227,258
};
static const unsigned char g_LenExtra[29] = {
    0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0
};
static const unsigned short g_DistBase[30] = {
    1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,
    1025,1537,2049,3073,4097,6145,8193,12289,16385,24577
};
static const unsigned char g_DistExtra[30] = {
    0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,
    12,12,13,13
};
static const unsigned char g_CodeLenOrder[19] = {
    16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15
};

static void PutByte(INFLATE *z, unsigned char c)
{
    if (z->outLen < z->outCap)
        z->out[z->outLen++] = c;
    z->win[z->winPos] = c;
    z->winPos = (z->winPos + 1) & 32767;
}

static int InflateBlock(INFLATE *z, HUFF *litlen, HUFF *dist)
{
    for (;;)
    {
        int sym = HuffDecode(z, litlen);
        if (sym < 0)
            return -1;
        if (sym < 256)
        {
            PutByte(z, (unsigned char)sym);
        }
        else if (sym == 256)
        {
            return 0;
        }
        else
        {
            int li = sym - 257;
            int di;
            int length, distance;
            int i;
            if (li < 0 || li >= 29)
                return -1;
            length = g_LenBase[li] + GetBits(z, g_LenExtra[li]);
            di = HuffDecode(z, dist);
            if (di < 0 || di >= 30)
                return -1;
            distance = g_DistBase[di] + GetBits(z, g_DistExtra[di]);
            for (i = 0; i < length; ++i)
            {
                unsigned char c = z->win[(z->winPos - distance) & 32767];
                PutByte(z, c);
            }
        }
    }
}

static int InflateDynamic(INFLATE *z)
{
    HUFF litlen, dist;
    unsigned char lengths[288 + 32];
    unsigned char clLengths[19];
    int nlen, ndist, ncode;
    int i, n;
    int result;

    nlen  = GetBits(z, 5) + 257;
    ndist = GetBits(z, 5) + 1;
    ncode = GetBits(z, 4) + 4;
    if (nlen > 288 || ndist > 32)
        return -1;
    for (i = 0; i < 19; ++i)
        clLengths[i] = 0;
    for (i = 0; i < ncode; ++i)
        clLengths[g_CodeLenOrder[i]] = (unsigned char)GetBits(z, 3);
    HuffBuild(&litlen, clLengths, 19);   /* code-length tree (reuse struct) */

    for (i = 0; i < nlen + ndist;)
    {
        int sym = HuffDecode(z, &litlen);
        int repeat;
        unsigned char value;
        if (sym < 0)
            return -1;
        if (sym < 16)
        {
            lengths[i++] = (unsigned char)sym;
            continue;
        }
        if (sym == 16)
        {
            if (i == 0)
                return -1;
            value = lengths[i - 1];
            repeat = 3 + GetBits(z, 2);
        }
        else if (sym == 17)
        {
            value = 0;
            repeat = 3 + GetBits(z, 3);
        }
        else
        {
            value = 0;
            repeat = 11 + GetBits(z, 7);
        }
        if (i + repeat > nlen + ndist)
            return -1;
        for (n = 0; n < repeat; ++n)
            lengths[i++] = value;
    }

    HuffBuild(&litlen, lengths, nlen);
    HuffBuild(&dist, lengths + nlen, ndist);
    result = InflateBlock(z, &litlen, &dist);
    return result;
}

static int InflateFixed(INFLATE *z)
{
    HUFF litlen, dist;
    unsigned char lengths[288];
    unsigned char dlengths[32];
    int i;

    for (i = 0; i < 144; ++i) lengths[i] = 8;
    for (; i < 256; ++i) lengths[i] = 9;
    for (; i < 280; ++i) lengths[i] = 7;
    for (; i < 288; ++i) lengths[i] = 8;
    for (i = 0; i < 32; ++i) dlengths[i] = 5;
    HuffBuild(&litlen, lengths, 288);
    HuffBuild(&dist, dlengths, 32);
    return InflateBlock(z, &litlen, &dist);
}

static int InflateStored(INFLATE *z)
{
    int len, nlen;
    int i;

    z->bitPos = (z->bitPos + 7) & ~7;   /* byte align */
    if (z->bitPos / 8 + 4 > z->inLen)
        return -1;
    len = z->in[z->bitPos / 8] | (z->in[z->bitPos / 8 + 1] << 8);
    nlen = z->in[z->bitPos / 8 + 2] | (z->in[z->bitPos / 8 + 3] << 8);
    if ((len ^ 0xFFFF) != nlen)
        return -1;
    z->bitPos += 32;
    for (i = 0; i < len; ++i)
    {
        if (z->bitPos / 8 >= z->inLen)
            return -1;
        PutByte(z, z->in[z->bitPos / 8]);
        z->bitPos += 8;
    }
    return 0;
}

/* Decode one MSZIP CFDATA block.  The 32K window persists across blocks. */
static int InflateMszipBlock(const unsigned char *payload, int payloadLen,
                             INFLATE *z)
{
    z->in = payload;
    z->inLen = payloadLen;
    z->bitPos = 0;
    for (;;)
    {
        int final = GetBit(z);
        int type = GetBits(z, 2);
        int r;
        if (type == 0) r = InflateStored(z);
        else if (type == 1) r = InflateFixed(z);
        else if (type == 2) r = InflateDynamic(z);
        else return -1;
        if (r != 0)
            return r;
        if (final)
            break;
    }
    return 0;
}

/* CAB LZX blocks begin with a 1-bit E8 flag; strip it (MSB-first bits). */
static void StripLzxHeaderBit(unsigned char *out, const unsigned char *in,
                              unsigned long n)
{
    unsigned long i;
    for (i = 0; i < n; ++i)
    {
        unsigned next = (i + 1 < n) ? (unsigned)(in[i + 1] >> 7) : 0;
        out[i] = (unsigned char)(((unsigned)in[i] << 1) | next);
    }
}

/* ------------------------------------------------------------------ */
/* CAB structures                                                       */
/* ------------------------------------------------------------------ */
typedef struct tagCABFOLDER
{
    unsigned long coffCabStart;
    unsigned short cCFData;     /* number of CFDATA blocks in this folder */
    int typeCompress;
} CABFOLDER;

typedef struct tagCABFILE
{
    unsigned long cbFile;
    unsigned long uoffFolderStart;
    int iFolder;
    const char *name;           /* points into the read-only CAB mapping */
    unsigned long nameLen;
} CABFILE;

typedef struct tagCAB
{
    unsigned char *data;
    long dataLen;
    int mapped;                /* data is a mapping of hFile, not heap memory */
    HANDLE hFile;
    HANDLE hMap;
    unsigned long cbCabinet;   /* cfhead.cbCabinet: excludes trailing data */
    unsigned long coffFiles;
    unsigned short cFolders;
    unsigned short cFiles;
    unsigned short flags;
    CABFOLDER *folders;
    CABFILE *files;
} CAB;

static unsigned short Rd16(const unsigned char *p)
{
    return (unsigned short)(p[0] | (p[1] << 8));
}
static unsigned long Rd32(const unsigned char *p)
{
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) |
           ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

static void CabFree(CAB *cab)
{
    if (cab->data)
    {
        if (cab->mapped)
            UnmapViewOfFile(cab->data);
        else
            free(cab->data);
    }
    if (cab->hMap)
        CloseHandle(cab->hMap);
    if (cab->hFile)
        CloseHandle(cab->hFile);
    if (cab->folders) free(cab->folders);
    if (cab->files) free(cab->files);
    memset(cab, 0, sizeof(*cab));
}

/* Map the cabinet read-only.  Windows 10/11 LCU payloads keep several
 * 200-900 MB folders inside one cabinet each; copying the whole file into
 * the heap and then allocating the decoded folder as well does not fit in a
 * 32-bit process, so the cabinet image stays file-backed. */
static int CabMapFile(CAB *cab, const char *path, long *outSize)
{
    HANDLE h;
    HANDLE m;
    unsigned char *view;
    DWORD size;

    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    size = GetFileSize(h, NULL);
    if (size == 0xFFFFFFFFUL || size < 36)
    {
        CloseHandle(h);
        return 0;
    }
    m = CreateFileMappingA(h, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!m)
    {
        CloseHandle(h);
        return 0;
    }
    view = (unsigned char *)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    if (!view)
    {
        CloseHandle(m);
        CloseHandle(h);
        return 0;
    }
    cab->data = view;
    cab->mapped = 1;
    cab->hFile = h;
    cab->hMap = m;
    *outSize = (long)size;
    return 1;
}

/* A large CAB folder can take seconds to decode and callers extract many
 * files from the same folder, so keep the most recently decoded one. */
static char g_folderCachePath[MAX_PATH];
static int g_folderCacheIndex = -1;
static unsigned char *g_folderCacheData;
static unsigned long g_folderCacheLen;

static void CabDropFolderCache(void)
{
    free(g_folderCacheData);
    g_folderCacheData = NULL;
    g_folderCacheLen = 0;
    g_folderCacheIndex = -1;
    g_folderCachePath[0] = 0;
}

static int CabOpen(CAB *cab, const char *path)
{
    long size;
    unsigned long off;
    unsigned short reserveBytes = 0;
    unsigned short cbCFFolder = 0;
    unsigned char cbCFData = 0;
    int i, n;

    memset(cab, 0, sizeof(*cab));
    /* Keep at most one decoded folder image alive.  Two of these can be
     * several hundred MB each and cannot coexist with the next cabinet's
     * mapping in a 32-bit process. */
    if (g_folderCacheData && strcmp(path, g_folderCachePath) != 0)
        CabDropFolderCache();
    if (!CabMapFile(cab, path, &size))
        return 0;
    cab->dataLen = size;

    if (memcmp(cab->data, "MSCF", 4) != 0)
    {
        CabFree(cab);
        return 0;
    }
    cab->cbCabinet = Rd32(cab->data + 8);
    if (cab->cbCabinet > (unsigned long)size)
        cab->cbCabinet = (unsigned long)size;
    cab->coffFiles = Rd32(cab->data + 16);
    cab->cFolders  = Rd16(cab->data + 26);
    cab->cFiles    = Rd16(cab->data + 28);
    cab->flags     = Rd16(cab->data + 30);

    /* CFHEADER reserved fields: cbCFHeader[2], cbCFFolder[1], cbCFData[1],
     * then cbCFHeader bytes of reserved data.  The folder headers therefore
     * start at 40 + cbCFHeader, not 38 + cbCFHeader.  MSU packages always
     * set 0x0004, and getting this two bytes wrong makes every file look
     * truncated. */
    off = 36;
    if (cab->flags & 0x0004)
    {
        reserveBytes = Rd16(cab->data + 36);
        cbCFFolder = cab->data[38];
        cbCFData = cab->data[39];
        off = 40 + (unsigned long)reserveBytes;
    }
    else if (cab->flags & 0x0001)
    {
        cbCFFolder = (unsigned short)Rd16(cab->data + 36);
        off = 38;
    }

    cab->folders = (CABFOLDER *)calloc(
        cab->cFolders ? cab->cFolders : 1, sizeof(CABFOLDER));
    cab->files = (CABFILE *)calloc(
        cab->cFiles ? cab->cFiles : 1, sizeof(CABFILE));
    if (!cab->folders || !cab->files)
    {
        CabFree(cab);
        return 0;
    }

    for (i = 0; i < (int)cab->cFolders; ++i)
    {
        const unsigned char *p = cab->data + off;
        if (off + 8 > (unsigned long)cab->dataLen)
        {
            CabFree(cab);
            return 0;
        }
        cab->folders[i].coffCabStart = Rd32(p);
        cab->folders[i].cCFData = Rd16(p + 4);
        cab->folders[i].typeCompress = Rd16(p + 6);
        off += 8;
        if (cab->flags & 0x0001)
            off += cbCFFolder;
    }

    {
        unsigned long foff = cab->coffFiles;
        for (i = 0; i < (int)cab->cFiles; ++i)
        {
            const unsigned char *p;
            int nameLen;
            int nameOff = 16 + ((cab->flags & 0x0002) ? cbCFData : 0);
            if (foff + (unsigned long)nameOff > (unsigned long)cab->dataLen)
            {
                CabFree(cab);
                return 0;
            }
            p = cab->data + foff;
            cab->files[i].cbFile = Rd32(p);
            cab->files[i].uoffFolderStart = Rd32(p + 4);
            cab->files[i].iFolder = Rd16(p + 8);
            nameLen = 0;
            while (foff + (unsigned long)nameOff + (unsigned long)nameLen <
                   (unsigned long)cab->dataLen &&
                   p[nameOff + nameLen] != 0)
                ++nameLen;
            if (foff + (unsigned long)nameOff + (unsigned long)nameLen >=
                (unsigned long)cab->dataLen)
            {
                CabFree(cab);       /* unterminated name */
                return 0;
            }
            /* The name already lives in the mapped CAB; keep a pointer so a
             * 65,000-entry payload does not need megabytes of copied names. */
            cab->files[i].name = (const char *)(p + nameOff);
            cab->files[i].nameLen = (unsigned long)nameLen;
            foff += (unsigned long)nameOff + (unsigned long)nameLen + 1;
        }
    }
    return 1;
}

/* Decompress one folder into a freshly allocated buffer. */
static int CabDecompressFolder(CAB *cab, int folderIndex,
                               unsigned char **outData, unsigned long *outSize)
{
    CABFOLDER *folder;
    unsigned long size = 0;
    unsigned char *buf;
    unsigned long coff;
    int count;
    int i;
    INFLATE z;
    unsigned char *window;

    *outData = NULL;
    *outSize = 0;
    if (folderIndex < 0 || folderIndex >= (int)cab->cFolders)
        return 0;
    folder = &cab->folders[folderIndex];

    for (i = 0; i < (int)cab->cFiles; ++i)
    {
        if (cab->files[i].iFolder == folderIndex)
            size += cab->files[i].cbFile;
    }
    buf = (unsigned char *)malloc((size_t)(size ? size : 1));
    window = (unsigned char *)malloc(32768);
    if (!buf || !window)
    {
        free(buf);
        free(window);
        return 0;
    }
    memset(window, 0x20, 32768);
    memset(&z, 0, sizeof(z));
    z.win = window;
    z.winPos = 0;
    z.out = buf;
    z.outCap = (int)size;

    coff = folder->coffCabStart;
    count = 0;

    /* FDI feeds the LZX decoder one CFDATA payload at a time and resets its
     * bit buffer for each one; only the Huffman trees, repeated offsets and
     * window contents carry over.  Concatenating the payloads and decoding
     * them as one stream desyncs on large folders. */
    if ((folder->typeCompress & 0x000F) == 3)
    {
        unsigned long total = 0;
        unsigned long c = coff;
        unsigned long outpos = 0;
        int windowBits;
        int blocks = 0;
        LzxDecoder *ld;

        while (c + 8 <= cab->cbCabinet && blocks < (int)folder->cCFData)
        {
            const unsigned char *p = cab->data + c;
            unsigned short cbData = Rd16(p + 4);
            unsigned short cbUncomp = Rd16(p + 6);
            if (c + 8 + cbData > cab->cbCabinet || cbUncomp > 0x8000UL)
                break;
            total += cbUncomp;
            c += 8 + (unsigned long)cbData;
            ++blocks;
        }
        windowBits = (folder->typeCompress >> 8) & 0x1F;
        if (windowBits < 15 || windowBits > 25)
            windowBits = 15;
        if (!total || total != size)
        {
            free(buf);
            free(window);
            return -1;
        }
        ld = LzxCreate(windowBits, size, CabLzxFill, NULL);
        if (!ld)
        {
            free(buf);
            free(window);
            return -1;
        }
        c = coff;
        blocks = 0;
        while (c + 8 <= cab->cbCabinet && blocks < (int)folder->cCFData)
        {
            const unsigned char *p = cab->data + c;
            unsigned short cbData = Rd16(p + 4);
            unsigned short cbUncomp = Rd16(p + 6);
            if (c + 8 + cbData > cab->cbCabinet || cbUncomp > 0x8000UL)
                break;
            if (cbUncomp > size - outpos ||
                LzxDecodeBlock(ld, buf + outpos, cbUncomp,
                               p + 8, cbData) != 1)
            {
                LzxDestroy(ld);
                free(buf);
                free(window);
                return -1;
            }
            outpos += cbUncomp;
            c += 8 + (unsigned long)cbData;
            ++blocks;
        }
        LzxDestroy(ld);
        if (outpos != size)
        {
            free(buf);
            free(window);
            return -1;
        }
        free(window);
        z.outLen = size;
        *outData = buf;
        *outSize = size;
        return 1;
    }

    while (coff + 8 <= cab->cbCabinet && count < (int)folder->cCFData)
    {
        const unsigned char *p = cab->data + coff;
        unsigned short cbData = Rd16(p + 4);
        const unsigned char *payload = p + 8;
        if (coff + 8 + cbData > cab->cbCabinet)
            break;

        if ((folder->typeCompress & 0x000F) == 0)
        {
            int n = (int)cbData;
            if (z.outLen + n > z.outCap)
                n = z.outCap - z.outLen;
            if (n > 0)
                memcpy(buf + z.outLen, payload, (size_t)n);
            z.outLen += n;
        }
        else if ((folder->typeCompress & 0x000F) == 1)
        {
            if (cbData < 2 || payload[0] != 'C' || payload[1] != 'K')
                break;
            if (InflateMszipBlock(payload + 2, cbData - 2, &z) != 0)
                break;
        }
        else
        {
            free(buf);
            free(window);
            return -1;          /* unsupported compression type */
        }

        coff += 8 + cbData;
        ++count;
        if (count >= 100000)
            break;
    }
    free(window);
    *outData = buf;
    *outSize = (unsigned long)z.outLen;
    return 1;
}

/* ------------------------------------------------------------------ */
/* DPX "PSTREAM" containers are recognised but their CIX/delta index is
   outside the supported subset; report them instead of raw-copying them. */
int CabIsPsf(const char *path)
{
    unsigned char head[8];
    HFILE fd;
    int result;

    if (!path)
        return 0;
    fd = _lopen(path, OF_READ);
    if (fd == -1)
        return 0;
    result = (_lread(fd, (LPSTR)head, 8) == 8) &&
             (memcmp(head, "PSTREAM\0", 8) == 0);
    _lclose(fd);
    return result;
}

int CabIsCabinet(const char *path)
{
    CAB cab;
    int ok;
    if (!path)
        return 0;
    ok = CabOpen(&cab, path);
    if (!ok)
        return 0;
    g_bContainsMulti = (cab.cFiles > 1);
    CabFree(&cab);
    return 1;
}

int CabList(const char *path)
{
    CAB cab;
    int i;
    if (!CabOpen(&cab, path))
        return -1;
    for (i = 0; i < (int)cab.cFiles; ++i)
        PrintMsg(MSG_LIST_LINE, path, OnlyFileName(cab.files[i].name));
    CabFree(&cab);
    return 0;
}

/* A large CAB folder can take seconds to decode and callers extract many
 * files from the same folder, so keep the most recently decoded one. */
static int CabCachedFolder(CAB *cab, const char *cabPath, int folderIndex,
                           unsigned char **out, unsigned long *len)
{
    if (g_folderCacheData && folderIndex == g_folderCacheIndex &&
        !strcmp(cabPath, g_folderCachePath))
    {
        *out = g_folderCacheData;
        *len = g_folderCacheLen;
        return 1;
    }
    CabDropFolderCache();
    if (CabDecompressFolder(cab, folderIndex, out, len) != 1)
        return 0;
    g_folderCacheData = *out;
    g_folderCacheLen = *len;
    g_folderCacheIndex = folderIndex;
    strncpy(g_folderCachePath, cabPath, sizeof(g_folderCachePath) - 1);
    g_folderCachePath[sizeof(g_folderCachePath) - 1] = 0;
    return 1;
}

/* Write entry `index` of a cabinet (by position, not by name, so payload
 * cabinets that carry the same file name more than once extract completely). */
int CabExtractIndex(const char *cabPath, int index, const char *targetPath)
{
    CAB cab;
    int result = 1;

    if (!CabOpen(&cab, cabPath))
        return -1;
    if (index < 0 || index >= (int)cab.cFiles)
    {
        CabFree(&cab);
        return -1;
    }
    if (cab.files[index].iFolder == 0xFFFF)
    {
        CabFree(&cab);
        return -1;
    }
    else
    {
        unsigned char *folderData;
        unsigned long folderSize;
        int fr = CabCachedFolder(&cab, cabPath, cab.files[index].iFolder,
                                 &folderData, &folderSize);
        if (fr != 1)
            result = (fr == -1) ? -8 : -1;
        else if (cab.files[index].uoffFolderStart + cab.files[index].cbFile >
                 folderSize)
            result = -3;
        else
        {
            char longTo[4096];
            MakeLongPath(targetPath, longTo, sizeof(longTo));
            {
                HANDLE h = CreateFileA(longTo, GENERIC_WRITE, 0, NULL,
                                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                                       NULL);
                if (h == INVALID_HANDLE_VALUE)
                    result = -2;
                else
                {
                    DWORD written = 0;
                    if (!cab.files[index].cbFile ||
                        (WriteFile(h, folderData + cab.files[index].uoffFolderStart,
                                   cab.files[index].cbFile, &written, NULL) &&
                         written == cab.files[index].cbFile))
                        result = 1;
                    else
                        result = -4;
                    CloseHandle(h);
                }
            }
        }
    }
    CabFree(&cab);
    return result;
}

/* Bytes needed by a caller-supplied compact name table for CabExtractAll. */
long CabNamesBytes(const char *cabPath)
{
    CAB cab;
    long total = 0;
    int i;

    if (!CabOpen(&cab, cabPath))
        return -1;
    for (i = 0; i < (int)cab.cFiles; ++i)
        total += (long)cab.files[i].nameLen + 1;
    CabFree(&cab);
    return total;
}

/* Extract every entry of a cabinet in a single pass: callers used to open and
 * map the same CAB twice per entry, which for a 65,000-file payload cabinet
 * meant thousands of file-map cycles and quadratic directory parsing.  Names
 * go into a compact table (offsets[i]) to keep memory use proportional to the
 * actual name lengths. */
int CabExtractAll(const char *cabPath, const char *dir,
                  char *namesBuf, long namesCap, int *offsets,
                  int *status, int maxEntries)
{
    CAB cab;
    int i;
    int total;
    long used = 0;

    if (!CabOpen(&cab, cabPath))
        return -1;
    total = (int)cab.cFiles;
    if (total > maxEntries)
        total = maxEntries;
    for (i = 0; i < total; ++i)
    {
        char to[4096];
        char longTo[4096];
        unsigned long nameLen = cab.files[i].nameLen;
        int r = 0;

        offsets[i] = (int)used;
        if (used + (long)nameLen + 1 > namesCap)
            nameLen = 0;
        if (nameLen)
            memcpy(namesBuf + used, cab.files[i].name, (size_t)nameLen);
        namesBuf[used + nameLen] = 0;
        used += (long)nameLen + 1;
        status[i] = 0;
        JoinPath(to, sizeof(to), dir, namesBuf + offsets[i]);
        EnsureParentDir(to);
        if (cab.files[i].iFolder != 0xFFFF)
        {
            unsigned char *folderData;
            unsigned long folderSize;
            int fr = CabCachedFolder(&cab, cabPath, cab.files[i].iFolder,
                                     &folderData, &folderSize);
            if (fr == 1 &&
                cab.files[i].uoffFolderStart + cab.files[i].cbFile <= folderSize)
            {
                MakeLongPath(to, longTo, sizeof(longTo));
                {
                    HANDLE h = CreateFileA(longTo, GENERIC_WRITE, 0, NULL,
                                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                                           NULL);
                    if (h != INVALID_HANDLE_VALUE)
                    {
                        DWORD written = 0;
                        if (!cab.files[i].cbFile ||
                            (WriteFile(h, folderData + cab.files[i].uoffFolderStart,
                                       cab.files[i].cbFile, &written, NULL) &&
                             written == cab.files[i].cbFile))
                            r = 1;
                        CloseHandle(h);
                    }
                }
            }
            else if (fr == -1)
                r = -1;             /* unsupported compression scheme */
        }
        status[i] = r;
    }
    CabFree(&cab);
    return total;
}

/* Find an entry by its file name with a single cabinet directory scan. */
int CabFindEntry(const char *cabPath, const char *name, char *buf, size_t bufSize)
{
    CAB cab;
    int i;
    int ok = 0;

    if (!CabOpen(&cab, cabPath))
        return 0;
    for (i = 0; i < (int)cab.cFiles; ++i)
    {
        if (_stricmp(OnlyFileName(cab.files[i].name), OnlyFileName(name)) != 0)
            continue;
        strncpy(buf, cab.files[i].name, bufSize - 1);
        buf[bufSize - 1] = 0;
        ok = 1;
        break;
    }
    CabFree(&cab);
    return ok;
}

int CabExtractOne(const char *cabPath, const char *entryName,
                  const char *targetPath)
{
    CAB cab;
    int i;
    int result = 1;

    if (!CabOpen(&cab, cabPath))
        return -1;

    for (i = 0; i < (int)cab.cFiles; ++i)
    {
        if (strcmp(cab.files[i].name, entryName) != 0)
            continue;
        if (cab.files[i].iFolder == 0xFFFF)
        {
            result = -1;
            break;
        }
        else
        {
            unsigned char *folderData;
            unsigned long folderSize;
            int fr = CabCachedFolder(&cab, cabPath, cab.files[i].iFolder,
                                     &folderData, &folderSize);
            HFILE hOut;
            UINT written;
            if (fr != 1)
            {
                result = (fr == -1) ? -8 : -1;
                break;
            }
            if (cab.files[i].uoffFolderStart + cab.files[i].cbFile > folderSize)
            {
                result = -3;
                break;
            }
            hOut = _lcreat(targetPath, 0);
            if (hOut == -1)
            {
                result = -2;
                break;
            }
            written = _lwrite(hOut,
                (LPSTR)(folderData + cab.files[i].uoffFolderStart),
                (UINT)cab.files[i].cbFile);
            _lclose(hOut);
            if (written == (UINT)-1)
                result = -4;
            else if ((int)written != (int)cab.files[i].cbFile)
                result = -2;
            break;
        }
    }
    CabFree(&cab);
    return result;
}

/* Return the name of the Nth entry, or NULL.  Used by dpx.c. */
int CabGetEntryCount(const char *path)
{
    CAB cab;
    int n;
    if (!CabOpen(&cab, path))
        return -1;
    n = (int)cab.cFiles;
    CabFree(&cab);
    return n;
}

int CabGetEntryName(const char *path, int index, char *buf, size_t bufSize)
{
    CAB cab;
    int ok = 0;
    if (index < 0 || !CabOpen(&cab, path))
        return 0;
    if (index < (int)cab.cFiles)
    {
        strncpy(buf, cab.files[index].name, bufSize - 1);
        buf[bufSize - 1] = 0;
        ok = 1;
    }
    CabFree(&cab);
    return ok;
}
