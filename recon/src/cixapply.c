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
    int pass;
    int produced = 0;
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

    GetTempPathA(MAX_PATH, tmpDir);
    GetTempFileNameA(tmpDir, "cix", 0, manifestPath);
    if (CabExtractOne(cabPath, entry, manifestPath) != 1 ||
        ReadWhole(manifestPath, &text, &textLen) != 0)
    {
        DeleteFileA(manifestPath);
        return 0;
    }
    DeleteFileA(manifestPath);

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

    for (pass = 0; pass <= cix.count; ++pass)
    {
        int progress = 0;
        CIXFILE *f;
        for (i = 0, f = cix.files; f; f = f->next, ++i)
        {
            int rc;
            if (done[i])
                continue;

            JoinPath(target, sizeof(target), outDir, f->name);
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
            ++progress;
            ++produced;
        }
        if (!progress)
            break;
    }

    free(done);
    CixFree(&cix);
    return produced;
}
