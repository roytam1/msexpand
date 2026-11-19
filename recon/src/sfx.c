/* sfx.c -- Windows Update self-extracting package support (C89).
 *
 * Older Windows Update hotfixes are a PE stub (_sfx_.dll) followed by an
 * embedded CAB.  The CAB contains the old files, the PA19 patches and a
 * _sfx_manifest_ describing which patch turns which old file into which
 * output.  When such a marker is present, expand extracts the CAB and runs
 * those deltas natively so the caller gets the patched binaries directly.
 */
#include "expand.h"
#include "delta.h"
#include "sfx.h"

#define SFX_MAX_DELTA 64
#define SFX_MAX_COPY  32

/* ---------- small helpers ------------------------------------------------ */

static unsigned short SfxRd16(const unsigned char *p)
{
    return (unsigned short)(p[0] | (p[1] << 8));
}

static unsigned long SfxRd32(const unsigned char *p)
{
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) |
           ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

static int SfxNameIs(const unsigned char *p, unsigned long n, const char *lit)
{
    unsigned long i;
    if ((unsigned long)strlen(lit) != n)
        return 0;
    for (i = 0; i < n; ++i)
    {
        if (tolower(p[i]) != tolower((unsigned char)lit[i]))
            return 0;
    }
    return 1;
}

static int SfxReadFile(const char *path, unsigned char **out,
                       unsigned long *len)
{
    FILE *f;
    long n;
    unsigned char *b;

    f = fopen(path, "rb");
    if (!f)
        return -1;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0)
    {
        fclose(f);
        return -1;
    }
    b = (unsigned char *)malloc((size_t)n + 1);
    if (!b)
    {
        fclose(f);
        return -1;
    }
    if (n && fread(b, 1, (size_t)n, f) != (size_t)n)
    {
        free(b);
        fclose(f);
        return -1;
    }
    fclose(f);
    b[n] = 0;
    *out = b;
    *len = (unsigned long)n;
    return 0;
}

static int SfxWriteFile(const char *path, const unsigned char *b,
                        unsigned long n)
{
    FILE *f;
    f = fopen(path, "wb");
    if (!f)
        return -1;
    if (n && fwrite(b, 1, (size_t)n, f) != (size_t)n)
    {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int SfxCopyFile(const char *src, const char *dst)
{
    FILE *a;
    FILE *b;
    unsigned char buf[8192];
    size_t n;

    a = fopen(src, "rb");
    if (!a)
        return -1;
    EnsureParentDir(dst);
    b = fopen(dst, "wb");
    if (!b)
    {
        fclose(a);
        return -1;
    }
    while ((n = fread(buf, 1, sizeof(buf), a)) > 0)
        fwrite(buf, 1, n, b);
    fclose(a);
    fclose(b);
    return 0;
}

/* ---------- CAB / SFX detection ------------------------------------------ */

static int SfxCabHasMarker(const unsigned char *cab, unsigned long len)
{
    unsigned long p;
    unsigned long count;
    unsigned long i;

    if (len < 36)
        return 0;
    p = SfxRd32(cab + 16);
    count = SfxRd16(cab + 28);
    if (count == 0 || count > 100000)
        return 0;
    for (i = 0; i < count; ++i)
    {
        unsigned long n;
        const unsigned char *name;
        if (p + 16 >= len)
            return 0;
        name = cab + p + 16;
        n = 0;
        while (p + 16 + n < len && name[n])
            ++n;
        if (SfxNameIs(name, n, "_sfx_manifest_") ||
            SfxNameIs(name, n, "_sfx_.dll"))
            return 1;
        p += 16 + n + 1;
    }
    return 0;
}

/* Find an embedded CAB carrying an SFX marker.  Returns its offset and size. */
static int SfxFindCab(const unsigned char *f, unsigned long n,
                      unsigned long *off, unsigned long *len)
{
    unsigned long i;

    for (i = 0; i + 36 <= n; ++i)
    {
        unsigned long cb;
        unsigned long coff;
        unsigned long cFiles;
        if (memcmp(f + i, "MSCF", 4) != 0)
            continue;
        cb = SfxRd32(f + i + 8);
        if (cb < 36 || cb > n - i)
            continue;
        coff = SfxRd32(f + i + 16);
        cFiles = SfxRd16(f + i + 28);
        if (coff + 16 > cb || cFiles == 0 || cFiles > 100000)
            continue;
        if (SfxCabHasMarker(f + i, cb))
        {
            *off = i;
            *len = cb;
            return 1;
        }
    }
    return 0;
}

int SfxIsArchive(const char *path)
{
    unsigned char *f = NULL;
    unsigned long n = 0;
    unsigned long off = 0;
    unsigned long cb = 0;
    int r;

    if (SfxReadFile(path, &f, &n) != 0)
        return 0;
    r = SfxFindCab(f, n, &off, &cb);
    free(f);
    return r;
}

/* ---------- manifest parsing --------------------------------------------- */

static int SfxNextQuoted(char **pp, char *out, size_t cap)
{
    char *p = *pp;
    size_t n = 0;

    while (*p && *p != '"')
        ++p;
    if (!*p)
    {
        *pp = p;
        return 0;
    }
    ++p;
    while (*p && *p != '"')
    {
        if (n + 1 < cap)
            out[n++] = *p;
        ++p;
    }
    out[n] = 0;
    if (*p == '"')
        ++p;
    *pp = p;
    return 1;
}

static void SfxParseManifest(SFX *sfx)
{
    char *p = sfx->text;
    int section = 0;

    while (p && *p)
    {
        char *line = p;
        char *e = strchr(p, '\n');
        char *q;
        char a[MAX_PATH];
        char b[MAX_PATH];
        char c[MAX_PATH];

        if (e)
        {
            *e = 0;
            p = e + 1;
        }
        else
        {
            p = line + strlen(line);
        }
        q = line + strlen(line);
        if (q > line && q[-1] == '\r')
            q[-1] = 0;
        while (*line == ' ' || *line == '\t')
            ++line;
        if (*line == '[')
        {
            if (_strnicmp(line, "[Deltas]", 8) == 0)
                section = 1;
            else if (_strnicmp(line, "[Copy]", 6) == 0)
                section = 2;
            else
                section = 0;
            continue;
        }
        if (!*line || *line == ';' || !strchr(line, '='))
            continue;
        q = line;
        if (!SfxNextQuoted(&q, a, sizeof(a)) ||
            !SfxNextQuoted(&q, b, sizeof(b)))
            continue;
        if (section == 1 && sfx->nDelta < SFX_MAX_DELTA)
        {
            if (!SfxNextQuoted(&q, c, sizeof(c)))
                continue;
            strncpy(sfx->delta[sfx->nDelta].target, a, MAX_PATH - 1);
            strncpy(sfx->delta[sfx->nDelta].patch, b, MAX_PATH - 1);
            strncpy(sfx->delta[sfx->nDelta].source, c, MAX_PATH - 1);
            sfx->delta[sfx->nDelta].target[MAX_PATH - 1] = 0;
            sfx->delta[sfx->nDelta].patch[MAX_PATH - 1] = 0;
            sfx->delta[sfx->nDelta].source[MAX_PATH - 1] = 0;
            ++sfx->nDelta;
        }
        else if (section == 2 && sfx->nCopy < SFX_MAX_COPY)
        {
            strncpy(sfx->copy[sfx->nCopy].target, a, MAX_PATH - 1);
            strncpy(sfx->copy[sfx->nCopy].source, b, MAX_PATH - 1);
            sfx->copy[sfx->nCopy].target[MAX_PATH - 1] = 0;
            sfx->copy[sfx->nCopy].source[MAX_PATH - 1] = 0;
            ++sfx->nCopy;
        }
    }
}

/* ---------- load / free -------------------------------------------------- */

int SfxLoad(const char *path, SFX *sfx)
{
    unsigned char *f = NULL;
    unsigned long n = 0;
    unsigned long off = 0;
    unsigned long cb = 0;
    unsigned char *text = NULL;
    unsigned long textLen = 0;
    char tmpDir[MAX_PATH];
    FILE *h;

    memset(sfx, 0, sizeof(*sfx));
    strncpy(sfx->inputPath, path, MAX_PATH - 1);
    sfx->inputPath[MAX_PATH - 1] = 0;
    if (SfxReadFile(path, &f, &n) != 0)
        return -1;
    if (!SfxFindCab(f, n, &off, &cb))
    {
        free(f);
        return -1;
    }
    GetTempPathA(MAX_PATH, tmpDir);
    GetTempFileNameA(tmpDir, "sfx", 0, sfx->cabPath);
    h = fopen(sfx->cabPath, "wb");
    if (!h)
    {
        free(f);
        return -1;
    }
    if (fwrite(f + off, 1, (size_t)cb, h) != (size_t)cb)
    {
        fclose(h);
        free(f);
        return -1;
    }
    fclose(h);
    free(f);

    GetTempFileNameA(tmpDir, "sfx", 0, sfx->manifestPath);
    {
        int nEntries = CabGetEntryCount(sfx->cabPath);
        int k;
        char name[MAX_PATH];
        int found = 0;
        for (k = 0; k < nEntries; ++k)
        {
            if (CabGetEntryName(sfx->cabPath, k, name, sizeof(name)) &&
                _stricmp(name, "_sfx_manifest_") == 0)
            {
                found = 1;
                break;
            }
        }
        if (found &&
            CabExtractOne(sfx->cabPath, name, sfx->manifestPath) == 1 &&
            SfxReadFile(sfx->manifestPath, &text, &textLen) == 0)
        {
            sfx->text = (char *)text;
            sfx->hasManifest = 1;
            SfxParseManifest(sfx);
        }
    }
    return 0;
}

void SfxFree(SFX *sfx)
{
    if (!sfx)
        return;
    if (sfx->text)
        free(sfx->text);
    if (sfx->cabPath[0])
        DeleteFileA(sfx->cabPath);
    if (sfx->manifestPath[0])
        DeleteFileA(sfx->manifestPath);
    memset(sfx, 0, sizeof(*sfx));
}

/* ---------- extraction + patch application ------------------------------- */

static int SfxEntrySelected(const char *entry, const char *base)
{
    const char *p;
    int wildcardExt = 0;

    if (!g_pszSelectiveSpec)
        return 1;
    for (p = entry; *p; ++p)
    {
        if (*p == '\\' || *p == '/')
            wildcardExt = 1;
    }
    return PatternMatch(base, g_pszSelectiveSpec, wildcardExt);
}

int SfxExpandFile(SFX *sfx, const char *destDir)
{
    char targetDir[MAX_PATH];
    char entry[MAX_PATH];
    char target[MAX_PATH];
    char patchPath[MAX_PATH];
    char srcPath[MAX_PATH];
    char cwd[MAX_PATH];
    unsigned char *sel;
    unsigned char *patch = NULL;
    unsigned char *source = NULL;
    unsigned char *result = NULL;
    unsigned long patchLen, sourceLen, resultLen;
    int count;
    int nSel = 0;
    int failed = 0;
    int i;

    if (IsDirectory(destDir))
    {
        strncpy(targetDir, destDir, MAX_PATH - 1);
        targetDir[MAX_PATH - 1] = 0;
    }
    else
    {
        DirNameOf(destDir, targetDir, sizeof(targetDir));
        if (!targetDir[0])
        {
            GetCurrentDirectoryA(sizeof(cwd), cwd);
            strncpy(targetDir, cwd, MAX_PATH - 1);
            targetDir[MAX_PATH - 1] = 0;
        }
    }

    count = CabGetEntryCount(sfx->cabPath);
    if (count < 0)
        return -1;
    sel = (unsigned char *)calloc((size_t)(count ? count : 1), 1);
    if (!sel)
        return -1;

    for (i = 0; i < count; ++i)
    {
        char *base;
        if (!CabGetEntryName(sfx->cabPath, i, entry, sizeof(entry)))
            continue;
        base = OnlyFileName(entry);
        if (g_bDoListFiles)
        {
            PrintMsg(MSG_LIST_LINE, sfx->inputPath, base);
            ++g_nLocalFiles;
            ++g_nTotalFiles;
            continue;
        }
        if (!SfxEntrySelected(entry, base))
            continue;
        JoinPath(target, sizeof(target), targetDir, entry);
        EnsureParentDir(target);
        if (CabExtractOne(sfx->cabPath, entry, target) != 1)
        {
            failed = 1;
            continue;
        }
        PrintMsg(MSG_EXPANDING, sfx->inputPath, target);
        sel[i] = 1;
        ++nSel;
        ++g_nLocalFiles;
        ++g_nTotalFiles;
    }

    if (g_bDoListFiles)
    {
        free(sel);
        return 1;
    }
    if (!nSel)
    {
        PrintMsg(MSG_NO_MATCH, sfx->inputPath,
                 g_pszSelectiveSpec ? g_pszSelectiveSpec : "*");
        free(sel);
        return 0;
    }

    for (i = 0; i < sfx->nDelta; ++i)
    {
        SFXDELTA *d = &sfx->delta[i];
        int rc;

        if (g_pszSelectiveSpec &&
            !PatternMatch(OnlyFileName(d->target), g_pszSelectiveSpec, 1))
            continue;

        JoinPath(target, sizeof(target), targetDir, d->target);
        JoinPath(patchPath, sizeof(patchPath), targetDir, d->patch);
        JoinPath(srcPath, sizeof(srcPath), targetDir, d->source);

        if (_access(patchPath, 0) != 0)
        {
            EnsureParentDir(patchPath);
            if (CabExtractOne(sfx->cabPath, d->patch, patchPath) != 1)
            {
                failed = 1;
                continue;
            }
        }
        if (_access(srcPath, 0) != 0)
        {
            EnsureParentDir(srcPath);
            if (CabExtractOne(sfx->cabPath, d->source, srcPath) != 1)
            {
                failed = 1;
                continue;
            }
        }
        if (SfxReadFile(patchPath, &patch, &patchLen) != 0 ||
            SfxReadFile(srcPath, &source, &sourceLen) != 0)
        {
            free(patch);
            free(source);
            patch = NULL;
            source = NULL;
            failed = 1;
            continue;
        }
        rc = DeltaApply(patch, patchLen, source, sourceLen,
                        &result, &resultLen);
        free(patch);
        free(source);
        patch = NULL;
        source = NULL;
        if (rc != 0 || !result)
        {
            failed = 1;
            continue;
        }
        EnsureParentDir(target);
        if (SfxWriteFile(target, result, resultLen) != 0)
            failed = 1;
        PrintMsg(MSG_EXPANDING, sfx->inputPath, target);
        free(result);
        result = NULL;
        ++g_nLocalFiles;
        ++g_nTotalFiles;
    }

    for (i = 0; i < sfx->nCopy; ++i)
    {
        SFXCOPY *cp = &sfx->copy[i];
        char from[MAX_PATH];
        char to[MAX_PATH];

        if (g_pszSelectiveSpec &&
            !PatternMatch(OnlyFileName(cp->target), g_pszSelectiveSpec, 1))
            continue;
        JoinPath(from, sizeof(from), targetDir, cp->source);
        JoinPath(to, sizeof(to), targetDir, cp->target);
        if (_access(from, 0) != 0)
        {
            EnsureParentDir(from);
            if (CabExtractOne(sfx->cabPath, cp->source, from) != 1)
            {
                failed = 1;
                continue;
            }
        }
        if (SfxCopyFile(from, to) != 0)
            failed = 1;
        PrintMsg(MSG_COPYING, sfx->inputPath, to);
    }

    free(sel);
    if (failed)
    {
        PrintMsg(MSG_DPX_FAIL, -1);
        return 0;
    }
    PrintMsg(MSG_DPX_COMPLETE);
    return 1;
}
