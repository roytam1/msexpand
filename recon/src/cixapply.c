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

static int ReadWhole(const char *path, unsigned char **out, unsigned long *len)
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
    b = (unsigned char *)malloc((size_t)n ? (size_t)n : 1);
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
    *out = b;
    *len = (unsigned long)n;
    return 0;
}

static int WriteWhole(const char *path, const unsigned char *b,
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
    char tmpDir[MAX_PATH];
    char manifestPath[MAX_PATH];
    char target[MAX_PATH];
    char sourcePath[MAX_PATH];
    char patchPath[MAX_PATH];
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
    char entry[MAX_PATH];
    int found = 0;

    nEntries = CabGetEntryCount(cabPath);
    if (nEntries <= 0)
        return 0;
    for (i = 0; i < nEntries; ++i)
    {
        if (!CabGetEntryName(cabPath, i, entry, sizeof(entry)))
            continue;
        if (_stricmp(OnlyFileName(entry), "_manifest_.cix.xml") == 0)
        {
            found = 1;
            break;
        }
    }
    if (!found)
        return 0;

    /* When the CAB folder was unpacked by the OS fallback the manifest is
     * already in the output directory; prefer that copy. */
    {
        char local[MAX_PATH];
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
                    char basisPath[MAX_PATH];
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
                char from[MAX_PATH];
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
