/* psf.c -- PSTREAM/PSF container reader (Phase A: RAW targets). */
#include "expand.h"
#include "psf.h"
#include "xml.h"
#include "cix.h"
#include "xpress.h"
#include "lzms.h"
#include "delta.h"

#define MAX_PSF_SELECT 4096

typedef struct tagPSFSELECTION
{
    CIXFILE *file;
    char target[MAX_PATH];
} PSFSELECTION;

static unsigned long PsfRd32(const unsigned char *p)
{
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) |
           ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

int PsfExpand(void)
{
    PSFSELECTION *sel;
    unsigned char *image;
    unsigned char *index;
    unsigned long imageLen;
    unsigned long indexOff;
    unsigned long indexLen;
    long fileSize;
    FILE *fp;
    XMLNODE *xml;
    CIX cix;
    char targetDir[MAX_PATH];
    char chosen[MAX_PATH];
    char fullPath[MAX_PATH];
    char base[MAX_PATH];
    CIXFILE *f;
    int wildcardExt;
    int nSel;
    int failed;
    int i;
    const char *p;
    const char *spec;

    sel = (PSFSELECTION *)malloc(sizeof(PSFSELECTION) * MAX_PSF_SELECT);
    if (!sel)
        return 0;
    nSel = 0;
    failed = 0;
    image = NULL;
    xml = NULL;
    memset(&cix, 0, sizeof(cix));

    fp = fopen(g_pszInFileName, "rb");
    if (!fp)
    {
        free(sel);
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fileSize < 48)
    {
        fclose(fp);
        free(sel);
        return 0;
    }
    image = (unsigned char *)malloc((size_t)fileSize);
    if (!image || fread(image, 1, (size_t)fileSize, fp) != (size_t)fileSize)
    {
        free(image);
        fclose(fp);
        free(sel);
        return 0;
    }
    fclose(fp);
    imageLen = (unsigned long)fileSize;

    if (memcmp(image, "PSTREAM\0", 8) != 0)
    {
        free(image);
        free(sel);
        return 0;
    }
    indexOff = PsfRd32(image + 40);
    indexLen = PsfRd32(image + 44);
    if (indexLen == 0 || indexOff > imageLen ||
        indexLen > imageLen - indexOff ||
        indexOff + indexLen > imageLen)
    {
        free(image);
        free(sel);
        return 0;
    }
    index = image + indexOff;

    if (indexLen >= 4 &&
        (memcmp(index, "PA30", 4) == 0 || memcmp(index, "PA19", 4) == 0))
    {
        printf(Msg(MSG_BAD_SCHEME), g_pszInFileName);
        free(image);
        free(sel);
        return 0;
    }

    xml = XmlParse((const char *)index, indexLen);
    if (!xml || !CixParse(xml, &cix))
    {
        free(xml);
        free(image);
        free(sel);
        return 0;
    }
    g_bContainsMulti = (cix.count > 1);

    if (g_bContainsMulti && !g_bDoListFiles &&
        !(g_pszTargetName && IsDirectory(g_pszTargetName)))
    {
        printf(Msg(MSG_MULTI_NEEDS_DIR), g_pszInFileName);
        XmlFree(xml);
        CixFree(&cix);
        free(image);
        free(sel);
        return 2;       /* clean skip, not an error */
    }

    wildcardExt = 0;
    if (g_pszInFileName)
    {
        for (p = g_pszInFileName; *p; ++p)
        {
            if (*p == '.')
                wildcardExt = 0;
            else if (*p == '\\' || *p == '/')
                wildcardExt = 1;
        }
    }
    spec = g_pszSelectiveSpec;
    DpxComputeTargetDir(targetDir, sizeof(targetDir));

    for (f = cix.files; f; f = f->next)
    {
        strncpy(base, OnlyFileName(f->name), sizeof(base) - 1);
        base[sizeof(base) - 1] = 0;
        if (spec && !PatternMatch(base, spec, wildcardExt))
            continue;

        if (g_bDoListFiles)
        {
            PrintMsg(MSG_LIST_LINE, g_pszInFileName, base);
            ++g_nLocalFiles;
            ++g_nTotalFiles;
            continue;
        }

        if ((g_bContainsMulti || g_bDoRename) && !g_bIgnorePaths)
        {
            strncpy(chosen, f->name, sizeof(chosen) - 1);
            chosen[sizeof(chosen) - 1] = 0;
        }
        else if (!g_bContainsMulti && !g_bDoRename && g_pszTargetName &&
                 !IsDirectory(g_pszTargetName))
        {
            strncpy(chosen, OnlyFileName(g_pszTargetName), sizeof(chosen) - 1);
            chosen[sizeof(chosen) - 1] = 0;
        }
        else
        {
            strncpy(chosen, base, sizeof(chosen) - 1);
            chosen[sizeof(chosen) - 1] = 0;
        }
        JoinPath(fullPath, sizeof(fullPath), targetDir, chosen);

        if (!ProcessDpxNotification(g_pszInFileName, fullPath, 255))
            continue;
        if (nSel < MAX_PSF_SELECT)
        {
            sel[nSel].file = f;
            strncpy(sel[nSel].target, fullPath, sizeof(sel[nSel].target) - 1);
            sel[nSel].target[sizeof(sel[nSel].target) - 1] = 0;
            ++nSel;
        }
        g_bIsThereFile = 1;
    }

    if (!g_bDoListFiles && nSel > 0)
    {
        unsigned char *basisData[64];
        unsigned long basisLen[64];
        memset(basisData, 0, sizeof(basisData));
        memset(basisLen, 0, sizeof(basisLen));
        PrintMsg(MSG_DPX_EXPANDING);
        for (i = 0; i < nSel; ++i)
        {
            CIXFILE *item = sel[i].file;
            unsigned long off;
            unsigned long len;
            unsigned char *payload;
            unsigned char *decoded;
            int isHuff;
            int isXpress;
            int isLzms;
            int isDelta;
            unsigned long dlen;
            int dr;
            unsigned long got;
            HFILE hOut;
            UINT written;

            decoded = NULL;
            isDelta = 0;
            dlen = 0;
            isXpress = 0;
            isHuff = 0;
            isLzms = (strcmp(item->algId, "5") == 0 ||
                      strcmp(item->algId, "LZMS") == 0 ||
                      strcmp(item->algId, "COMPRESS_ALGORITHM_LZMS") == 0);

            isDelta = (strcmp(item->sourceType, "CIX_SOURCE_PA30") == 0 ||
                       strcmp(item->sourceType, "PA30") == 0 ||
                       strcmp(item->sourceType, "CIX_SOURCE_PA19") == 0 ||
                       strcmp(item->sourceType, "PA19") == 0);
            if (!item->hasSource || item->sourceType[0] == 0 ||
                strcmp(item->sourceType, "CIX_SOURCE_RAW") == 0 ||
                strcmp(item->sourceType, "RAW") == 0 || isDelta)
            {
                off = item->sourceOffset;
                len = item->sourceLength ? item->sourceLength : item->size;
            }
            else
            {
                printf(Msg(MSG_BAD_SCHEME), g_pszInFileName);
                failed = 1;
                continue;
            }
            if (off > imageLen || len > imageLen - off)
            {
                failed = 1;
                continue;
            }
            if (!CixVerifyHash(item, image + off, len))
            {
                failed = 1;
                continue;
            }

            isHuff = (strcmp(item->algId, "4") == 0 ||
                      strcmp(item->algId, "XPRESS_HUFF") == 0 ||
                      strcmp(item->algId, "COMPRESS_ALGORITHM_XPRESS_HUFF") == 0);
            isXpress = isHuff || (strcmp(item->algId, "3") == 0 ||
                      strcmp(item->algId, "XPRESS") == 0 ||
                      strcmp(item->algId, "COMPRESS_ALGORITHM_XPRESS") == 0);
            payload = image + off;
            if (isDelta)
            {
                unsigned b = (unsigned)item->basisId;
                unsigned char *basis = NULL;
                unsigned long blen = 0;
                if (b > 0 && b < 64)
                {
                    basis = basisData[b];
                    blen = basisLen[b];
                }
                if (!basis)
                {
                    failed = 1;
                    continue;
                }
                dr = DeltaApply(image + off, len, basis, blen,
                                &decoded, &dlen);
                if (dr != 0 || !decoded)
                {
                    failed = 1;
                    continue;
                }
                payload = decoded;
                len = dlen;
            }
            else if (isXpress || isLzms)
            {
                decoded = (unsigned char *)malloc(
                    (size_t)(item->size > 0 ? item->size : 1));
                if (!decoded)
                {
                    failed = 1;
                    continue;
                }
                if (isLzms)
                {
                    dr = LzmsDecompressData(payload, len, decoded, item->size);
                }
                else if (isHuff)
                {
                    dr = XpressHuffmanDecompress(payload, len, decoded,
                                                 item->size);
                }
                else
                {
                    got = 0;
                    dr = XpressDecompress(payload, len, decoded,
                                          item->size, &got);
                    if (dr == 0 && got != item->size)
                        dr = -1;
                }
                if (dr != 0)
                {
                    free(decoded);
                    failed = 1;
                    continue;
                }
                payload = decoded;
                len = item->size;
            }

            EnsureParentDir(sel[i].target);
            hOut = _lcreat(sel[i].target, 0);
            if (hOut == -1)
            {
                failed = 1;
                continue;
            }
            written = _lwrite(hOut, (LPSTR)payload, (UINT)len);
            _lclose(hOut);
            if (written != (UINT)len)
                failed = 1;
            if (item->id > 0 && item->id < 64)
            {
                basisData[item->id] = (unsigned char *)malloc((size_t)len);
                if (basisData[item->id])
                {
                    memcpy(basisData[item->id], payload, (size_t)len);
                    basisLen[item->id] = len;
                }
            }
            free(decoded);
        }
        if (failed)
            PrintMsg(MSG_DPX_FAIL, -1);
        else
            PrintMsg(MSG_DPX_COMPLETE);
        for (i = 0; i < 64; ++i)
            free(basisData[i]);
    }

    XmlFree(xml);
    CixFree(&cix);
    free(image);
    free(sel);
    return failed ? 0 : 1;
}
