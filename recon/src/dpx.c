/*
 * dpx.c -- the "Delta Package Expander" code path of expand.exe.
 *
 * The original routes every cabinet through dpx.dll's COM job API.  This
 * reconstruction folds that behaviour into the EXE: enumerate the cabinet
 * directory, apply the -F: pattern, print the same notifications and
 * extract the selected files with the integrated CAB reader.
 */
#include "expand.h"

#define MAX_SELECT 4096

typedef struct tagSELECTION
{
    char entry[MAX_PATH];
    char target[MAX_PATH];
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

int DpxExpandFile(void)
{
    SELECTION *sel;
    char targetDir[MAX_PATH];
    char chosen[MAX_PATH];
    char fullPath[MAX_PATH];
    char entry[MAX_PATH];
    char base[MAX_PATH];
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
            ++nSel;
        }
        g_bIsThereFile = 1;
    }

    if (!g_bDoListFiles && nSel > 0)
    {
        PrintMsg(MSG_DPX_EXPANDING);
        for (i = 0; i < nSel; ++i)
        {
            int r = CabExtractOne(src, sel[i].entry, sel[i].target);
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
            PrintMsg(MSG_DPX_COMPLETE);
    }

    result = failed ? 0 : 1;
    free(sel);
    return result;
}
