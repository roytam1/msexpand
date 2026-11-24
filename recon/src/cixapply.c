/* cixapply.c -- apply the RAW / PA30 targets of a _manifest_.cix.xml.
 *
 * The manifest in an MSU's inner CAB lists the output files, the CAB entry
 * holding each delta (or RAW payload) and, for deltas, the CIX id of the
 * basis file.  Bases can themselves be delta outputs, so files are resolved
 * in as many passes as needed. */
#include "expand.h"
#include "cix.h"
#include "delta.h"
#include "cixapply.h"
#include <time.h>

/* CIX target paths in modern NDP packages routinely exceed MAX_PATH, so all
 * file I/O here goes through \\?\ paths. */
static int ReadWhole(const char *path, unsigned char **out, unsigned long *len)
{
    char longPath[4096];
    HANDLE h;
    DWORD size;
    unsigned char *b;

    MakeLongPath(path, longPath, sizeof(longPath));
    h = CreateFileA(longPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    size = GetFileSize(h, NULL);
    if (size == 0xFFFFFFFFUL)
    {
        CloseHandle(h);
        return -1;
    }
    b = (unsigned char *)malloc((size_t)size ? (size_t)size : 1);
    if (!b)
    {
        CloseHandle(h);
        return -1;
    }
    if (size)
    {
        DWORD got = 0;
        if (!ReadFile(h, b, size, &got, NULL) || got != size)
        {
            free(b);
            CloseHandle(h);
            return -1;
        }
    }
    CloseHandle(h);
    *out = b;
    *len = (unsigned long)size;
    return 0;
}

static int WriteWhole(const char *path, const unsigned char *b,
                      unsigned long n)
{
    char longPath[4096];
    HANDLE h;

    MakeLongPath(path, longPath, sizeof(longPath));
    h = CreateFileA(longPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    if (n)
    {
        DWORD written = 0;
        if (!WriteFile(h, b, n, &written, NULL) || written != n)
        {
            CloseHandle(h);
            return -1;
        }
    }
    CloseHandle(h);
    return 0;
}

static CIXFILE *FindById(CIX *cix, int id)
{
    CIXFILE *f;
    for (f = cix->files; f; f = f->next)
    {
        if (f->id == id)
            return f;
    }
    return NULL;
}

static int IsDelta(const CIXFILE *f, const char *type)
{
    return f->hasSource && _stricmp(f->sourceType, type) == 0;
}

int CixApplyCab(const char *cabPath, const char *outDir)
{
    char tmpDir[4096];
    char manifestPath[4096];
    char target[4096];
    char sourcePath[4096];
    char patchPath[4096];
    unsigned char *text = NULL;
    unsigned char *patch = NULL;
    unsigned char *basis = NULL;
    unsigned char *result = NULL;
    unsigned long textLen, patchLen, basisLen, resultLen;
    XMLNODE *xml;
    CIX cix;
    unsigned char *done;
    CIXFILE *f2;
    CIXFILE *done2;
    int pass;
    int produced = 0;
    int verified = 0;
    int i;
    int nEntries;
    char entry[4096];

    nEntries = CabGetEntryCount(cabPath);
    if (nEntries <= 0)
        return 0;
    if (!CabFindEntry(cabPath, "_manifest_.cix.xml", entry, sizeof(entry)))
        return 0;

    /* When the CAB folder was unpacked by the OS fallback the manifest is
     * already in the output directory; prefer that copy. */
    {
        char local[4096];
        int fromTemp = 0;
        JoinPath(local, sizeof(local), outDir, "_manifest_.cix.xml");
        if (_access(local, 0) == 0)
        {
            strncpy(manifestPath, local, sizeof(manifestPath) - 1);
            manifestPath[sizeof(manifestPath) - 1] = 0;
        }
        else
        {
            GetTempPathA(MAX_PATH, tmpDir);
            GetTempFileNameA(tmpDir, "cix", 0, manifestPath);
            fromTemp = 1;
            if (CabExtractOne(cabPath, entry, manifestPath) != 1)
            {
                DeleteFileA(manifestPath);
                return 0;
            }
        }
        if (ReadWhole(manifestPath, &text, &textLen) != 0)
        {
            if (fromTemp)
                DeleteFileA(manifestPath);
            return 0;
        }
        if (fromTemp)
            DeleteFileA(manifestPath);
    }

    xml = XmlParse((const char *)text, textLen);
    free(text);
    if (!xml || !CixParse(xml, &cix))
    {
        if (xml)
            XmlFree(xml);
        return 0;
    }
    XmlFree(xml);
    if (cix.count <= 0)
    {
        CixFree(&cix);
        return 0;
    }

    done = (unsigned char *)calloc((size_t)cix.count, 1);
    if (!done)
    {
        CixFree(&cix);
        return 0;
    }

    ProgressStage("Patching", cix.count);
    for (pass = 0; pass <= cix.count; ++pass)
    {
        int progress = 0;
        CIXFILE *f;
        for (i = 0, f = cix.files; f; f = f->next, ++i)
        {
            int rc;
            double t0 = 0;
            if (getenv("PA30_TIMING"))
                t0 = (double)clock() / CLOCKS_PER_SEC;
            if (done[i])
                continue;

            JoinPath(target, sizeof(target), outDir, f->name);
            if (getenv("PA30_DEBUG")) fprintf(stderr, "CIX target: %s\n", f->name);
            EnsureParentDir(target);

            if (IsDelta(f, "RAW"))
            {
                JoinPath(sourcePath, sizeof(sourcePath), outDir, f->sourceName);
                if (ReadWhole(sourcePath, &basis, &basisLen) != 0)
                    continue;
                rc = WriteWhole(target, basis, basisLen);
                free(basis);
                basis = NULL;
                if (rc != 0)
                    continue;
            }
            else if (IsDelta(f, "PA30"))
            {
                CIXFILE *bf;
                JoinPath(patchPath, sizeof(patchPath), outDir, f->sourceName);
                if (ReadWhole(patchPath, &patch, &patchLen) != 0)
                    continue;
                bf = FindById(&cix, f->basisId);
                if (bf)
                {
                    char basisPath[4096];
                    JoinPath(basisPath, sizeof(basisPath), outDir, bf->name);
                    if (ReadWhole(basisPath, &basis, &basisLen) != 0)
                    {
                        free(patch);
                        patch = NULL;
                        continue;
                    }
                }
                else
                {
                    basis = (unsigned char *)malloc(1);
                    basisLen = 0;
                }
                rc = DeltaApply(patch, patchLen, basis, basisLen,
                                &result, &resultLen);
                free(patch);
                free(basis);
                patch = NULL;
                basis = NULL;
                if (rc != 0 || !result)
                    continue;
                rc = WriteWhole(target, result, resultLen);
                free(result);
                result = NULL;
                if (rc != 0)
                    continue;
            }
            else
            {
                char from[4096];
                JoinPath(from, sizeof(from), outDir,
                         f->hasSource ? f->sourceName : f->name);
                if (ReadWhole(from, &basis, &basisLen) != 0)
                    continue;
                rc = WriteWhole(target, basis, basisLen);
                free(basis);
                basis = NULL;
                if (rc != 0)
                    continue;
            }
            done[i] = 1;
            if (getenv("PA30_TIMING") && i < 40)
                fprintf(stderr, "TIMING %u %s %.3f\n", i, f->name,
                        (double)clock() / CLOCKS_PER_SEC - t0);
            ProgressItem("Patching", i + 1, cix.count, f->name, "OK");
            ++progress;
            ++produced;
        }
        if (!progress)
            break;
    }
    /* Report each unresolved target once, after every pass had a chance to
     * resolve its basis chain, instead of once per retry. */
    for (i = 0, done2 = cix.files; done2; done2 = done2->next, ++i)
        if (!done[i])
            ProgressItem("Patching", i + 1, cix.count, done2->name, "FAIL");
    ProgressSummary("Patching", produced, cix.count);

    ProgressStage("Verification", cix.count);
    for (i = 0, f2 = cix.files; f2; f2 = f2->next, ++i)
    {
        unsigned char *out = NULL;
        unsigned long outLen = 0;
        const char *status;
        JoinPath(target, sizeof(target), outDir, f2->name);
        if (ReadWhole(target, &out, &outLen) != 0)
            status = "FAIL";
        else if (!f2->hashLen)
            status = "SKIP";
        else if (CixVerifyTargetHash(f2, out, outLen))
            status = "OK";
        else
            status = "FAIL";
        free(out);
        if (strcmp(status, "FAIL") != 0)
            ++verified;
        ProgressItem("Verification", i + 1, cix.count, f2->name, status);
    }
    ProgressSummary("Verification", verified, cix.count);

    free(done);
    CixFree(&cix);
    return produced;
}
