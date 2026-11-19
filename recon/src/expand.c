/*
 * expand.c -- main program driver, argument parsing, notifications.
 */
#include "expand.h"

/* ------------------------------------------------------------------ */
int  g_iTarget = -1;
int  g_bDoRename = 0;
int  g_bIgnorePaths = 0;
int  g_bDisplayHelp = 0;
int  g_bTargetIsDir = 0;
int  g_nNumFileSpecs = 0;
int  g_bDoListFiles = 0;
char *g_pszSelectiveSpec = NULL;
char *g_pszKeyFile = NULL;
int  g_nCabEncryption = 0;
char *g_pszInFileName = NULL;
char *g_pszTargetName = NULL;
char *g_pszOutFileName = NULL;
int  g_nTotalFiles = 0;
int  g_nLocalFiles = 0;
int  g_bContainsMulti = 0;
int  g_bCopiedFlag = 0;
int  g_bIsThereFile = 0;

static int g_nextArg = 0;
static long g_totalOrig = 0;
static long g_totalNew = 0;

/* ------------------------------------------------------------------ */
int ParseArguments(int argc, char **argv)
{
    int i;
    unsigned char c;
    unsigned char upper;
    char dbcs[3];
    char *arg;

    g_iTarget = -1;
    g_bDoRename = 0;
    g_bIgnorePaths = 0;
    g_bDisplayHelp = 0;
    g_bTargetIsDir = 0;
    g_nNumFileSpecs = 0;
    g_bDoListFiles = 0;
    g_pszSelectiveSpec = NULL;
    g_pszKeyFile = NULL;
    g_nCabEncryption = 0;

    for (i = 1; i < argc; ++i)
    {
        arg = argv[i];
        if (arg[0] == '/' || arg[0] == '-')
        {
            c = (unsigned char)arg[1];
            if (IsDBCSLeadByte(c))
            {
                dbcs[0] = (char)arg[1];
                dbcs[1] = (char)arg[2];
                dbcs[2] = 0;
                printf(Msg(MSG_BAD_SWITCH_DBCS), dbcs);
                return 0;
            }
            upper = (unsigned char)toupper(c);
            if (upper == 'R')
            {
                g_bDoRename = 1;
            }
            else if (upper == 'I')
            {
                g_bDoRename = 1;
                g_bIgnorePaths = 1;
            }
            else if (upper == '?')
            {
                g_bDisplayHelp = 1;
            }
            else if (upper == 'D')
            {
                g_bDoRename = 1;
                g_bDoListFiles = 1;
            }
            else if (upper == 'F' && arg[2] == ':' && arg[3] &&
                     !g_pszSelectiveSpec)
            {
                g_pszSelectiveSpec = arg + 3;
            }
            else if (upper == 'K' && arg[2] == ':' && arg[3] &&
                     !g_pszKeyFile)
            {
                g_pszKeyFile = arg + 3;
            }
            else if (upper == 'E' && arg[2] == ':' && arg[3])
            {
                g_nCabEncryption = atoi(arg + 3);
            }
            else
            {
                printf(Msg(MSG_BAD_SWITCH), (int)c);
                return 0;
            }
        }
        else
        {
            g_iTarget = i;
            if (!IsDirectory(arg))
                ++g_nNumFileSpecs;
        }
    }
    if (g_iTarget != -1 && argv[g_iTarget])
        g_bTargetIsDir = IsDirectory(argv[g_iTarget]);
    return 1;
}

int CheckArguments(void)
{
    if (g_nNumFileSpecs < 1)
    {
        printf(Msg(MSG_NO_FILES));
        return 0;
    }
    if (g_nNumFileSpecs == 1)
    {
        if (!g_bDoRename && !g_bTargetIsDir)
        {
            if (!g_bDoListFiles)
            {
                printf(Msg(MSG_NO_DEST), g_pszTargetName);
                return 0;
            }
            return 1;
        }
        if (g_bDoListFiles && g_bTargetIsDir == 1)
        {
            printf(Msg(MSG_NO_DEST_DIR));
            return 0;
        }
        return 1;
    }
    if (g_nNumFileSpecs <= 2 || g_bDoRename || g_bTargetIsDir)
    {
        if (g_bDoListFiles && g_bTargetIsDir == 1)
        {
            printf(Msg(MSG_NO_DEST_DIR));
            return 0;
        }
        return 1;
    }
    if (!g_bDoListFiles)
    {
        printf(Msg(MSG_DEST_NOT_DIR), g_pszTargetName);
        return 0;
    }
    return 1;
}

int GetNextFileArg(char **argv)
{
    int i;
    int limit;

    limit = g_iTarget;
    for (i = g_nextArg + 1; ; ++i)
    {
        if (i > limit)
            return -1;
        if (!argv[i] || (argv[i][0] != '/' && argv[i][0] != '-') &&
            (i < limit || !g_bTargetIsDir))
            break;
    }
    if (IsDirectory(argv[i]))
    {
        g_nextArg = i;
        limit = g_iTarget;
        for (i = g_nextArg + 1; ; ++i)
        {
            if (i > limit)
                return -1;
            if (!argv[i] || (argv[i][0] != '/' && argv[i][0] != '-') &&
                (i < limit || !g_bTargetIsDir))
            {
                if (!IsDirectory(argv[i]))
                    break;
            }
        }
    }
    g_nextArg = i;
    return i;
}

int IsDirectory(const char *path)
{
    DWORD attr;
    if (!path)
        return 0;
    attr = GetFileAttributesA(path);
    if (attr == 0xFFFFFFFF)
        return 0;
    return (attr & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
}

char *ExtractFileName(const char *path)
{
    const char *p;
    const char *last = path;

    if (!path)
        return (char *)path;
    for (p = path; *p; ++p)
    {
        if (*p == '/' || *p == '\\' || *p == ':')
            last = p + 1;
    }
    return (char *)last;
}

void MakePathName(char *dest, const char *path)
{
    char *name;
    size_t len;

    if (!dest || !path)
        return;
    name = ExtractFileName(path);
    if (!*name || strcmp(name, ".") == 0)
        return;
    len = strlen(dest);
    if (len > 0 && dest[len - 1] != '/' && dest[len - 1] != '\\' &&
        dest[len - 1] != ':')
    {
        strcat(dest, "\\");
    }
    strcat(dest, name);
}

int ActuallyTheSameFile(const char *a, const char *b)
{
    char fa[MAX_PATH], fb[MAX_PATH];
    if (!a || !b)
        return 0;
    if (!GetFullPathNameA(a, MAX_PATH, fa, NULL))
        return 0;
    if (!GetFullPathNameA(b, MAX_PATH, fb, NULL))
        return 0;
    return lstrcmpiA(fa, fb) == 0;
}

int ProcessNotification(const char *source, const char *dest, int action)
{
    if (g_bDoListFiles)
    {
        PrintMsg(MSG_LIST_LINE, source, OnlyFileName(dest));
        ++g_nLocalFiles;
        ++g_nTotalFiles;
        return 0;
    }
    if (ActuallyTheSameFile(source, dest))
    {
        PrintMsg(MSG_SAME_FILE, source);
        return 0;
    }
    ++g_nLocalFiles;
    ++g_nTotalFiles;
    if (action == 1)
        PrintMsg(MSG_EXPANDING, source, dest);
    else
    {
        g_bCopiedFlag = 1;
        PrintMsg(MSG_COPYING, source, dest);
    }
    return 1;
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    LZCTL *c;
    char dest[MAX_PATH];
    int idx;
    int result;
    int exitCode;
    long orig, updated;
    int pct;

    setvbuf(stderr, NULL, _IONBF, 0);
    printf(Msg(MSG_BANNER));
    if (!ParseArguments(argc, argv))
        return 1;
    if (g_iTarget >= 0)
        g_pszTargetName = argv[g_iTarget];
    else
        g_pszTargetName = NULL;

    if (g_bDisplayHelp)
    {
        printf(Msg(MSG_HELP));
        return 0;
    }
    if (!CheckArguments())
        return 1;

    c = InitGlobalBuffers();
    if (!c)
    {
        printf(Msg(MSG_INIT_FAIL));
        return 1;
    }

    exitCode = 0;
    g_nextArg = 0;

    while ((idx = GetNextFileArg(argv)) != -1)
    {
        g_bCopiedFlag = 0;
        g_bIsThereFile = 0;
        g_pszInFileName = CharLowerA(argv[idx]);
        g_nLocalFiles = 0;

        if (g_nNumFileSpecs == 2 && !g_bTargetIsDir && !g_bDoRename)
        {
            if (g_pszTargetName)
            {
                strncpy(dest, g_pszTargetName, sizeof(dest) - 1);
                dest[sizeof(dest) - 1] = 0;
            }
            else
                dest[0] = 0;
            (void)GetNextFileArg(argv);   /* consume the destination */
        }
        else if (g_bTargetIsDir)
        {
            if (g_pszTargetName)
            {
                strncpy(dest, g_pszTargetName, sizeof(dest) - 1);
                dest[sizeof(dest) - 1] = 0;
            }
            else
                dest[0] = 0;
            MakePathName(dest, g_pszInFileName);
        }
        else if (g_pszTargetName)
        {
            strncpy(dest, g_pszTargetName, sizeof(dest) - 1);
            dest[sizeof(dest) - 1] = 0;
        }
        else
        {
            strncpy(dest, g_pszInFileName, sizeof(dest) - 1);
            dest[sizeof(dest) - 1] = 0;
        }
        g_pszOutFileName = CharLowerA(dest);

        if (CabIsPsf(g_pszInFileName))
        {
            result = PsfExpand();
            if (result != 2)
            {
                exitCode = result != 1;
                if (result != 1)
                    DisplayErrorMessage(result);
            }
            printf("\n");
            goto nextFile;
        }

        if (CabIsCabinet(g_pszInFileName))
        {
            int callDpx;
            callDpx = 1;
            if (g_bContainsMulti)
            {
                if (g_nNumFileSpecs == 1 && !g_bDoListFiles &&
                    !g_pszSelectiveSpec)
                {
                    printf(Msg(MSG_NEEDS_F_SWITCH));
                    goto nextFile;
                }
                if (!g_bTargetIsDir && !g_bDoListFiles)
                {
                    printf(Msg(MSG_MULTI_NEEDS_DIR), g_pszInFileName);
                    goto nextFile;
                }
            }
            if (callDpx)
            {
                result = DpxExpandFile();
                exitCode = result != 1;
                if (result != 1)
                    DisplayErrorMessage(result);
            }
        }
        else
        {
            result = Expand(c);
            if (result != 1)
            {
                exitCode = result;
                DisplayErrorMessage(result);
                printf("\n");
                continue;
            }
        }

        if (g_bContainsMulti)
        {
            if (!g_nLocalFiles)
                PrintMsg(MSG_NO_MATCH, g_pszInFileName,
                         g_pszSelectiveSpec ? g_pszSelectiveSpec : "*");
        }
        else
        {
            orig = c->filesize;
            updated = c->out_count;
            if (orig > 0 && updated > 0)
            {
                if (g_bCopiedFlag)
                {
                    PrintMsg(MSG_COPIED_SUMMARY, g_pszInFileName, orig);
                }
                else
                {
                    pct = (int)((100 * updated) / orig) - 100;
                    PrintMsg(MSG_EXPANDED_SUMMARY, g_pszInFileName,
                             orig, updated, pct);
                    g_totalOrig += orig;
                    g_totalNew += updated;
                }
            }
        }
        printf("\n");

    nextFile:
        ;
    }

    FreeGlobalBuffers(c);

    if (!g_totalNew || g_bDoListFiles)
    {
        if (g_nTotalFiles > 1)
            PrintMsg(MSG_TOTAL_FILES, g_nTotalFiles);
    }
    else if (g_nTotalFiles > 1)
    {
        int pct2 = (int)((100 * g_totalNew) / g_totalOrig) - 100;
        PrintMsg(MSG_TOTAL_SUMMARY, g_nTotalFiles, g_totalOrig,
                 g_totalNew, pct2);
    }
    return exitCode;
}
