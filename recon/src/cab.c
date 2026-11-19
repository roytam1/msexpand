/*
 * cab.c -- minimal self-contained CAB (MSCF) reader.
 *
 * Supports compression types 0 (none) and 1 (MSZIP / raw deflate), which
 * covers the cabinets expanded by the original tool through dpx.dll for
 * ordinary use.  Other compression types report MSG_BAD_SCHEME.
 */
#include "expand.h"
#include "lzx.h"

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
    int typeCompress;
} CABFOLDER;

typedef struct tagCABFILE
{
    unsigned long cbFile;
    unsigned long uoffFolderStart;
    int iFolder;
    char name[MAX_PATH];
} CABFILE;

typedef struct tagCAB
{
    unsigned char *data;
    long dataLen;
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
    if (cab->data) free(cab->data);
    if (cab->folders) free(cab->folders);
    if (cab->files) free(cab->files);
    memset(cab, 0, sizeof(*cab));
}

static int CabOpen(CAB *cab, const char *path)
{
    HFILE fd;
    long size;
    unsigned long off;
    unsigned short reserveBytes = 0;
    int i, n;

    memset(cab, 0, sizeof(*cab));
    fd = _lopen(path, OF_READ);
    if (fd == -1)
        return 0;
    size = _llseek(fd, 0L, SEEK_END);
    _llseek(fd, 0L, SEEK_SET);
    if (size < 36)
    {
        _lclose(fd);
        return 0;
    }
    cab->data = (unsigned char *)malloc((size_t)size);
    if (!cab->data)
    {
        _lclose(fd);
        return 0;
    }
    if (_lread(fd, (LPSTR)cab->data, (UINT)size) != (UINT)size)
    {
        _lclose(fd);
        CabFree(cab);
        return 0;
    }
    _lclose(fd);
    cab->dataLen = size;

    if (memcmp(cab->data, "MSCF", 4) != 0)
    {
        CabFree(cab);
        return 0;
    }
    cab->coffFiles = Rd32(cab->data + 16);
    cab->cFolders  = Rd16(cab->data + 26);
    cab->cFiles    = Rd16(cab->data + 28);
    cab->flags     = Rd16(cab->data + 30);

    off = 36;
    if (cab->flags & 0x0004)
    {
        reserveBytes = Rd16(cab->data + 36);
        off += 2;
        if (cab->flags & 0x0001)
            off += 2 + 2;        /* cbCFHeader + cbCFFolder */
        off += reserveBytes;
    }
    else if (cab->flags & 0x0001)
    {
        off += 2 + 2;
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
        cab->folders[i].typeCompress = Rd16(p + 6);
        off += 8;
        if (cab->flags & 0x0001)
            off += Rd16(cab->data + 36 + (cab->flags & 0x0004 ? 4 : 0));
    }

    {
        unsigned long foff = cab->coffFiles;
        for (i = 0; i < (int)cab->cFiles; ++i)
        {
            const unsigned char *p;
            int nameLen;
            if (foff + 16 > (unsigned long)cab->dataLen)
            {
                CabFree(cab);
                return 0;
            }
            p = cab->data + foff;
            cab->files[i].cbFile = Rd32(p);
            cab->files[i].uoffFolderStart = Rd32(p + 4);
            cab->files[i].iFolder = Rd16(p + 8);
            nameLen = 0;
            while (foff + 16 + nameLen < (unsigned long)cab->dataLen &&
                   p[16 + nameLen] != 0)
                ++nameLen;
            n = nameLen;
            if (n >= (int)sizeof(cab->files[i].name))
                n = (int)sizeof(cab->files[i].name) - 1;
            memcpy(cab->files[i].name, p + 16, (size_t)n);
            cab->files[i].name[n] = 0;
            foff += 16 + (unsigned long)nameLen + 1;
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
    while (coff + 8 <= (unsigned long)cab->dataLen)
    {
        const unsigned char *p = cab->data + coff;
        unsigned short cbData = Rd16(p + 4);
        unsigned short cbUncomp = Rd16(p + 6);
        const unsigned char *payload = p + 8;
        if (coff + 8 + cbData > (unsigned long)cab->dataLen)
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
        else if ((folder->typeCompress & 0x000F) == 3)
        {
            unsigned char *shifted;
            int windowBits;
            int dr;

            if (cbData < 2 || cbUncomp == 0 ||
                z.outLen + cbUncomp > z.outCap)
            {
                free(buf);
                free(window);
                return -1;
            }
            windowBits = (folder->typeCompress >> 8) & 0x1F;
            if (windowBits < 15 || windowBits > 21)
                windowBits = 15;
            shifted = (unsigned char *)malloc(cbData);
            if (!shifted)
            {
                free(buf);
                free(window);
                return -1;
            }
            /* lzxdec.c consumes the CAB E8 header bit itself. */
            memcpy(shifted, payload, (size_t)cbData);
            dr = LzxDecompressSeeded(shifted, cbData, buf + z.outLen,
                                     cbUncomp, windowBits, buf, z.outLen);
            free(shifted);
            if (dr != 0)
            {
                free(buf);
                free(window);
                return -1;
            }
            z.outLen += cbUncomp;
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
            int fr = CabDecompressFolder(&cab, cab.files[i].iFolder,
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
                free(folderData);
                result = -3;
                break;
            }
            hOut = _lcreat(targetPath, 0);
            if (hOut == -1)
            {
                free(folderData);
                result = -2;
                break;
            }
            written = _lwrite(hOut,
                (LPSTR)(folderData + cab.files[i].uoffFolderStart),
                (UINT)cab.files[i].cbFile);
            _lclose(hOut);
            free(folderData);
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
