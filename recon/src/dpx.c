/*
 * dpx.c -- the "Delta Package Expander" code path of expand.exe.
 *
 * The original routes every cabinet through dpx.dll's COM job API.  This
 * reconstruction folds that behaviour into the EXE: enumerate the cabinet
 * directory, apply the -F: pattern, print the same notifications and
 * extract the selected files with the integrated CAB reader.
 */
#include "expand.h"
#include "cixapply.h"

#define MAX_SELECT 4096

typedef struct tagSELECTION
{
    char entry[4096];
    char target[4096];
    int index;                  /* entry position inside the cabinet */
} SELECTION;

int ProcessDpxNotification(const char *source, const char *name, int action)
{
    if (!action || (action > 2 && action != 255))
        return 1;

    if (g_bDoListFiles)
    {
        PrintMsg(MSG_LIST_LINE, source, OnlyFileName(name));
        ++g_nLocalFiles;
        ++g_nTotalFiles;
        return 0;
    }
    if (ActuallyTheSameFile(source, name))
    {
        PrintMsg(MSG_SAME_FILE, source);
        return 0;
    }
    ++g_nLocalFiles;
    ++g_nTotalFiles;
    if (action == 1)
        PrintMsg(MSG_EXPANDING, source, name);
    else if (action == 255)
        PrintMsg(MSG_ADDING_QUEUE, name);
    else
    {
        g_bCopiedFlag = 1;
        PrintMsg(MSG_COPYING, source, name);
    }
    return 1;
}

void DpxComputeTargetDir(char *buf, size_t bufSize)
{
    char cwd[MAX_PATH];

    if (g_bDoListFiles)
    {
        if (g_pszTargetName && IsDirectory(g_pszTargetName))
            strncpy(buf, g_pszTargetName, bufSize - 1);
        else
            DirNameOf(g_pszInFileName, buf, bufSize);
        buf[bufSize - 1] = 0;
    }
    else if (g_bContainsMulti || (g_pszTargetName &&
             IsDirectory(g_pszTargetName)))
    {
        strncpy(buf, g_pszTargetName ? g_pszTargetName : ".",
                bufSize - 1);
        buf[bufSize - 1] = 0;
    }
    else
    {
        DirNameOf(g_pszTargetName ? g_pszTargetName : g_pszInFileName,
                  buf, bufSize);
    }
    if (!buf[0])
    {
        GetCurrentDirectoryA(sizeof(cwd), cwd);
        strncpy(buf, cwd, bufSize - 1);
        buf[bufSize - 1] = 0;
    }
}

/* Last resort for a CAB folder our LZX decoder cannot handle (for example a
 * very large 2 MB-window stream): ask the system expand.exe to unpack it.
 * Only reached when native extraction has already failed. */
static int CabExtractAllViaOS(const char *cabPath, const char *dir)
{
    char cmd[4096];
    char sysdir[MAX_PATH];
    char expand[MAX_PATH];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD code = 1;

    if (getenv("CAB_NO_OS")) return 0;
    GetSystemDirectoryA(sysdir, sizeof(sysdir));
    _snprintf(expand, sizeof(expand) - 1, "%s\\expand.exe", sysdir);
    expand[sizeof(expand) - 1] = 0;
    _snprintf(cmd, sizeof(cmd) - 1, "\"%s\" \"%s\" -F:* \"%s\"",
              expand, cabPath, dir);
    cmd[sizeof(cmd) - 1] = 0;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL,
                        &si, &pi))
        return 0;
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code == 0;
}

/* True when `path` starts with the MSCF cabinet signature. */
static int DpxIsCabFile(const char *path)
{
    FILE *f;
    char sig[4];
    size_t n;

    f = fopen(path, "rb");
    if (!f)
        return 0;
    n = fread(sig, 1, sizeof(sig), f);
    fclose(f);
    return n == sizeof(sig) && memcmp(sig, "MSCF", 4) == 0;
}

/* Expand every entry of `cabPath` into `dir` (one level).  A folder our LZX
 * decoder cannot handle is handed to the system expand.exe as a last resort. */
static int DpxExtractCabLevel(const char *cabPath, const char *dir)
{
    int count;
    int j;
    int ok = 0;
    int osFallback = 0;
    char *namesBuf;
    int *offsets;
    int *status;
    long bytes;

    count = CabGetEntryCount(cabPath);
    if (count <= 0)
        return 0;
    bytes = CabNamesBytes(cabPath);
    if (bytes <= 0)
        return 0;
    namesBuf = (char *)malloc((size_t)bytes);
    offsets = (int *)calloc((size_t)count, sizeof(int));
    status = (int *)calloc((size_t)count, sizeof(int));
    if (!namesBuf || !offsets || !status)
    {
        free(namesBuf);
        free(offsets);
        free(status);
        return 0;
    }
    count = CabExtractAll(cabPath, dir, namesBuf, bytes, offsets, status, count);
    if (count < 0)
    {
        free(namesBuf);
        free(offsets);
        free(status);
        return 0;
    }
    ProgressStage("Nested CAB", count);
    for (j = 0; j < count; ++j)
    {
        if (status[j] != 1 && !osFallback && CabExtractAllViaOS(cabPath, dir))
        {
            printf("Nested CAB folder extracted by the OS fallback: %s\n",
                   OnlyFileName(cabPath));
            osFallback = 1;
        }
        if (osFallback && status[j] != 1)
        {
            char to[4096];
            char longTo[4096];
            JoinPath(to, sizeof(to), dir, namesBuf + offsets[j]);
            MakeLongPath(to, longTo, sizeof(longTo));
            if (_access(longTo, 0) == 0)
                status[j] = 1;
        }
    }
    for (j = 0; j < count; ++j)
    {
        if (status[j] == 1)
            ++ok;
        ProgressItem("Nested CAB", j + 1, count, namesBuf + offsets[j],
                     status[j] == 1 ? "OK" : "FAIL");
    }
    ProgressSummary("Nested CAB", ok, count);
    free(namesBuf);
    free(offsets);
    free(status);
    return ok;
}

/* Collect the cabinets a packaging descriptor in `dir` points at:
 *   toc.xml              -- <Package CabName="SSU-....cab" .../>
 *   cabinet.cablist.ini  -- Cabinet1 = Cab_1_for_KB....cab
 * Returns how many names were stored. */
static int DpxReadCabList(const char *dir, char names[][MAX_PATH], int max)
{
    static const char *descriptors[2] = { "toc.xml", "cabinet.cablist.ini" };
    char path[MAX_PATH];
    unsigned char *text = NULL;
    long size = 0;
    FILE *f;
    int d;
    int n = 0;

    for (d = 0; d < 2 && n == 0; ++d)
    {
        JoinPath(path, sizeof(path), dir, descriptors[d]);
        f = fopen(path, "rb");
        if (!f)
            continue;
        if (fseek(f, 0, SEEK_END) == 0)
        {
            size = ftell(f);
            if (size > 0 && size < 1024 * 1024 && fseek(f, 0, SEEK_SET) == 0)
            {
                text = (unsigned char *)malloc((size_t)size + 1);
                if (text && fread(text, 1, (size_t)size, f) != (size_t)size)
                {
                    free(text);
                    text = NULL;
                }
                if (text)
                    text[size] = 0;
            }
        }
        fclose(f);
        if (!text)
            continue;

        {
            long i;
            for (i = 0; i + 4 <= size; ++i)
            {
                if (_strnicmp((const char *)text + i, ".cab", 4) != 0)
                    continue;
                {
                    long b = i;
                    long len;
                    int k;
                    int dup = 0;
                    while (b > 0 && (isalnum(text[b - 1]) || text[b - 1] == '_' ||
                                     text[b - 1] == '-' || text[b - 1] == '.'))
                        --b;
                    len = i + 4 - b;
                    if (len <= 4 || len >= MAX_PATH)
                        continue;
                    for (k = 0; k < n; ++k)
                        if ((long)strlen(names[k]) == len &&
                            _strnicmp(names[k], (const char *)text + b, len) == 0)
                            dup = 1;
                    if (!dup && n < max)
                    {
                        memcpy(names[n], text + b, (size_t)len);
                        names[n][len] = 0;
                        ++n;
                    }
                }
            }
        }
        free(text);
        text = NULL;
    }
    return n;
}

/* Expand one cabinet into `dir`, then apply its CIX manifest and follow the
 * packaging descriptors it carries.  Payload cabinets legitimately ship
 * ordinary `.cab` data files (constraintindex.cab, ...), so the walk follows
 * the descriptors instead of expanding every cabinet it meets. */
static void DpxExpandCab(const char *cabPath, const char *dir, int depth)
{
    CreateDirectoryA(dir, NULL);
    DpxExtractCabLevel(cabPath, dir);
    (void)CixApplyCab(cabPath, dir);

    if (depth < 6)
    {
        char names[64][MAX_PATH];
        int n = DpxReadCabList(dir, names, 64);
        int i;
        for (i = 0; i < n; ++i)
        {
            char cab[MAX_PATH];
            char sub[MAX_PATH];
            size_t len;
            JoinPath(cab, sizeof(cab), dir, names[i]);
            if (!DpxIsCabFile(cab))
                continue;
            strncpy(sub, cab, sizeof(sub) - 1);
            sub[sizeof(sub) - 1] = 0;
            len = strlen(sub);
            if (len > 4 && _stricmp(sub + len - 4, ".cab") == 0)
                sub[len - 4] = 0;
            DpxExpandCab(cab, sub, depth + 1);
        }
    }
}

/* A cabinet inside a cabinet is common in Windows Update packages: the MSU
 * holds a combined CAB which in turn holds the SSU and payload CABs, and the
 * payload CAB lists its data cabinets in cabinet.cablist.ini. */
static void DpxNestedCab(const char *cabPath, const char *targetDir)
{
    int count;
    int i;

    count = CabGetEntryCount(cabPath);
    if (count <= 0)
        return;
    for (i = 0; i < count; ++i)
    {
        char entry[4096];
        char full[4096];
        char sub[4096];
        size_t n;

        if (!CabGetEntryName(cabPath, i, entry, sizeof(entry)))
            continue;
        JoinPath(full, sizeof(full), targetDir, entry);
        if (!DpxIsCabFile(full))
            continue;

        strncpy(sub, full, sizeof(sub) - 1);
        sub[sizeof(sub) - 1] = 0;
        n = strlen(sub);
        if (n > 4 && _stricmp(sub + n - 4, ".cab") == 0)
            sub[n - 4] = 0;
        DpxExpandCab(full, sub, 0);
    }
}

int DpxExpandFile(void)
{
    SELECTION *sel;
    char targetDir[4096];
    char chosen[4096];
    char fullPath[4096];
    char entry[4096];
    char base[4096];
    int count;
    int i;
    int nSel;
    int wildcardExt;
    int result;
    int failed;
    const char *src;
    const char *spec;
    char *p;

    sel = (SELECTION *)malloc(sizeof(SELECTION) * MAX_SELECT);
    if (!sel)
        return 0;
    nSel = 0;
    failed = 0;

    src = g_pszInFileName;
    spec = g_pszSelectiveSpec;

    wildcardExt = 0;
    if (src)
    {
        for (p = (char *)src; *p; ++p)
        {
            if (*p == '.')
                wildcardExt = 0;
            else if (*p == '\\' || *p == '/')
                wildcardExt = 1;
        }
    }

    DpxComputeTargetDir(targetDir, sizeof(targetDir));

    count = CabGetEntryCount(src);
    if (count < 0)
    {
        free(sel);
        return 0;
    }

    for (i = 0; i < count; ++i)
    {
        if (!CabGetEntryName(src, i, entry, sizeof(entry)))
            continue;
        strncpy(base, OnlyFileName(entry), sizeof(base) - 1);
        base[sizeof(base) - 1] = 0;

        if (spec && !PatternMatch(base, spec, wildcardExt))
            continue;

        if (g_bDoListFiles)
        {
            PrintMsg(MSG_LIST_LINE, src, base);
            ++g_nLocalFiles;
            ++g_nTotalFiles;
            continue;
        }

        if ((g_bContainsMulti || g_bDoRename) && !g_bIgnorePaths)
        {
            strncpy(chosen, entry, sizeof(chosen) - 1);
            chosen[sizeof(chosen) - 1] = 0;
        }
        else if (!g_bContainsMulti && !g_bDoRename && g_pszTargetName &&
                 !IsDirectory(g_pszTargetName))
        {
            /* Single file, no rename: the target name itself is used. */
            const char *t = g_pszTargetName ? g_pszTargetName : g_pszInFileName;
            strncpy(chosen, OnlyFileName(t), sizeof(chosen) - 1);
            chosen[sizeof(chosen) - 1] = 0;
        }
        else
        {
            strncpy(chosen, base, sizeof(chosen) - 1);
            chosen[sizeof(chosen) - 1] = 0;
        }

        JoinPath(fullPath, sizeof(fullPath), targetDir, chosen);

        if (!ProcessDpxNotification(src, fullPath, 255))
            continue;

        if (nSel < MAX_SELECT)
        {
            strncpy(sel[nSel].entry, entry, sizeof(sel[nSel].entry) - 1);
            sel[nSel].entry[sizeof(sel[nSel].entry) - 1] = 0;
            strncpy(sel[nSel].target, fullPath, sizeof(sel[nSel].target) - 1);
            sel[nSel].target[sizeof(sel[nSel].target) - 1] = 0;
            sel[nSel].index = i;
            ++nSel;
        }
        g_bIsThereFile = 1;
    }

    if (!g_bDoListFiles && nSel > 0)
    {
        PrintMsg(MSG_DPX_EXPANDING);
        for (i = 0; i < nSel; ++i)
        {
            int r;
            EnsureParentDir(sel[i].target);
            r = CabExtractIndex(src, sel[i].index, sel[i].target);
            if (r != 1)
            {
                failed = 1;
                if (r == -8)
                {
                    PrintMsg(MSG_BAD_SCHEME, src);
                }
                else
                {
                    DisplayErrorMessage(r);
                }
            }
        }
        if (failed)
            PrintMsg(MSG_DPX_FAIL, -1);
        else
        {
            PrintMsg(MSG_DPX_COMPLETE);
            /* The input cabinet may itself carry a CIX manifest (an SSU or a
             * payload CAB handed to the tool directly). */
            (void)CixApplyCab(src, targetDir);
            DpxNestedCab(src, targetDir);
        }
    }

    result = failed ? 0 : 1;
    free(sel);
    return result;
}
