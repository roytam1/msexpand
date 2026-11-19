/*
 * messages.c -- hardcoded English message table.
 *
 * The original expand.exe loads these from an MUI RT_STRING resource.  The
 * text below was recovered verbatim from the RT_STRING blocks of the
 * supplied expand.exe binary (blocks 1..3, lang 1033) and is reproduced
 * here so the reconstruction is a single self-contained EXE.
 */
#include "expand.h"

typedef struct tagMSGENTRY
{
    int id;
    const char *text;
} MSGENTRY;

static const MSGENTRY g_Messages[] = {
    { MSG_INIT_FAIL,
      "Insufficient memory for buffers.\n" },
    { MSG_DEST_NOT_DIR,
      "Destination is not a directory: %s.\n" },
    { MSG_BAD_SWITCH,
      "Unrecognized switch -%c.\n" },
    { MSG_NO_FILES,
      "No files specified.\n" },
    { MSG_NO_DEST,
      "No destination specified for: %s.\n" },
    { MSG_CANT_OPEN_IN,
      "Can't open input file: %s.\n" },
    { MSG_CANT_READ_IN,
      "Can't read from input file: %s.\n" },
    { MSG_CANT_OPEN_OUT,
      "Can't open output file: %s.\n" },
    { MSG_NO_DISK_SPACE,
      "Out of disk space writing output file: %s.\n" },
    { MSG_BANNER,
      "Microsoft (R) File Expansion Utility\n"
      "Copyright (c) Microsoft Corporation. All rights reserved.\n\n" },
    { MSG_GENERIC_FAIL,
      "Expanding %s to %s failed.\n" },
    { MSG_SAME_FILE,
      "Cannot expand a file onto itself: %s.\n" },
    { MSG_EXPANDED_SUMMARY,
      "%s: %ld bytes expanded to %ld bytes, %d%% increase.\n" },
    { MSG_TOTAL_SUMMARY,
      "Total increase: %d files, %ld bytes expanded to %ld bytes, "
      "%d%% increase.\n" },
    { MSG_HELP,
      "Expands one or more compressed files.\n"
      "\n"
      "EXPAND [-R] Source Destination\n"
      "EXPAND -R Source [Destination]\n"
      "EXPAND -I Source [Destination]\n"
      "EXPAND -D Source.cab [-F:Files]\n"
      "EXPAND Source.cab -F:Files Destination\n"
      "\n"
      "  -R\t\tRename expanded files.\n"
      "  -I\t\tRename expanded files but ignore directory structure.\n"
      "  -D\t\tDisplay list of files in source.\n"
      "  Source\tSource file specification.  Wildcards may be used.\n"
      "  -F:Files\tName of files to expand from a .CAB.\n"
      "  Destination\tDestination file | path specification.\n"
      "\t\tDestination may be a directory.\n"
      "\t\tIf Source is multiple files and -r is not specified,\n"
      "\t\tDestination must be a directory.\n" },
    { MSG_BAD_SWITCH_DBCS,
      "Unrecognized switch -%s.\n" },
    { MSG_EXPANDING,
      "Expanding %s to %s.\n" },
    { MSG_COPYING,
      "Copying %s to %s.\n" },
    { MSG_COPIED_SUMMARY,
      "%s: %ld bytes copied.\n" },
    { MSG_BAD_FORMAT,
      "Error in compressed input file format: %s.\n" },
    { MSG_BAD_SCHEME,
      "Unrecognized compression scheme: %s.\n" },
    { MSG_NO_DEST_DIR,
      "No destination directory expected.\n" },
    { MSG_LIST_LINE,
      "%s: %s\n" },
    { MSG_TOTAL_FILES,
      "%d files total.\n" },
    { MSG_NO_MATCH,
      "%s: No files matching '%s'.\n" },
    { MSG_MULTI_NEEDS_DIR,
      "%s: Destination directory required for a multi-file CAB.\n\n" },
    { MSG_NEEDS_F_SWITCH,
      "The source file contains multiple files.  The -F:filespec option is\n"
      "required to specify which file(s) are to be expanded.  -F:* may be\n"
      "used to expand all files.  Type EXPAND -? for more details.\n" },
    { MSG_DPX_FAIL,
      "\nOne or more files could not be expanded. Delta Package Expander "
      "Returned 0x%x \n" },
    { MSG_DPX_ALL_OK,
      "\nAll Files expanded successfully \n" },
    { MSG_DLL_LOAD_FAIL,
      "\nFailed to Load DLL, %S, hr=0x%x" },
    { MSG_DLL_LOAD_DPX,
      "\nFailed to Load dpx.dll" },
    { MSG_DPX_INCOMPLETE,
      "\nExpanding File %s Incomplete, Error Code=0x%x" },
    { MSG_DPX_EXPANDING,
      "\nExpanding Files ....\n" },
    { MSG_DPX_COMPLETE,
      "\nExpanding Files Complete ..." },
    { MSG_ADDING_QUEUE,
      "Adding %s to Extraction Queue\n" },
    { MSG_PROGRESS,
      "Progress: %I64u out of %I64u files" },
    { MSG_ERROR_DESC,
      "\nError Description: %s\n" },
    { MSG_SFX_VERIFY_FAIL,
      "Verification failed for %s: computed %s, expected %s.\n" }
};

const char *Msg(int id)
{
    unsigned int i;
    for (i = 0; i < sizeof(g_Messages) / sizeof(g_Messages[0]); ++i)
    {
        if (g_Messages[i].id == id)
            return g_Messages[i].text;
    }
    return "";
}

int PrintMsgV(int id, va_list ap)
{
    return vprintf(Msg(id), ap);
}

int PrintMsg(int id, ...)
{
    va_list ap;
    int n;
    va_start(ap, id);
    n = PrintMsgV(id, ap);
    va_end(ap);
    return n;
}

void DisplayErrorMessage(int code)
{
    int id;
    const char *arg1;
    const char *arg2;

    if (code == 0)
        return;

    arg1 = g_pszInFileName ? g_pszInFileName : "";
    arg2 = g_pszOutFileName ? g_pszOutFileName : "";

    switch (code)
    {
    case -1:  id = MSG_CANT_OPEN_IN;  break;
    case -2:  id = MSG_CANT_OPEN_OUT; break;
    case -3:  id = MSG_BAD_FORMAT;    break;
    case -4:  id = MSG_NO_DISK_SPACE; break;
    case -8:  id = MSG_BAD_SCHEME;    break;
    default:  id = MSG_GENERIC_FAIL;  break;
    }

    if (id == MSG_GENERIC_FAIL)
        printf(Msg(id), arg1, arg2);
    else if (id == MSG_CANT_OPEN_OUT || id == MSG_NO_DISK_SPACE)
        printf(Msg(id), arg2);
    else
        printf(Msg(id), arg1);
}
