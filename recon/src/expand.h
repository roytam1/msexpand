/*
 * expand.h -- common declarations for the C89 reconstruction of expand.exe
 *
 * C89 / MSVC6 compatible.  No C++ constructs, no inline, no declarations
 * after statements, no // comments.
 */
#ifndef EXPAND_H
#define EXPAND_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <io.h>
#include <fcntl.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* Message resource identifiers (recovered from expand.exe RT_STRING)  */
/* ------------------------------------------------------------------ */
#define MSG_INIT_FAIL          1
#define MSG_DEST_NOT_DIR       2
#define MSG_BAD_SWITCH         3
#define MSG_NO_FILES           4
#define MSG_NO_DEST            5
#define MSG_CANT_OPEN_IN       6
#define MSG_CANT_READ_IN       7
#define MSG_CANT_OPEN_OUT      8
#define MSG_NO_DISK_SPACE      9
#define MSG_BANNER             10
#define MSG_GENERIC_FAIL       11
#define MSG_SAME_FILE          12
#define MSG_EXPANDED_SUMMARY   13
#define MSG_TOTAL_SUMMARY      15
#define MSG_HELP               16
#define MSG_BAD_SWITCH_DBCS    19
#define MSG_EXPANDING          20
#define MSG_COPYING            21
#define MSG_COPIED_SUMMARY     22
#define MSG_BAD_FORMAT         23
#define MSG_BAD_SCHEME         24
#define MSG_NO_DEST_DIR        25
#define MSG_LIST_LINE          26
#define MSG_TOTAL_FILES        27
#define MSG_NO_MATCH           28
#define MSG_MULTI_NEEDS_DIR    29
#define MSG_NEEDS_F_SWITCH     30
#define MSG_DPX_FAIL           31
#define MSG_DPX_ALL_OK         32
#define MSG_DLL_LOAD_FAIL      33
#define MSG_DLL_LOAD_DPX       34
#define MSG_DPX_INCOMPLETE     35
#define MSG_DPX_EXPANDING      36
#define MSG_DPX_COMPLETE       37
#define MSG_ADDING_QUEUE       38
#define MSG_PROGRESS           39
#define MSG_ERROR_DESC         40

/* ------------------------------------------------------------------ */
/* Global program state (addresses in comments are from the IDB)       */
/* ------------------------------------------------------------------ */
extern int       g_iTarget;          /* 40CC30 */
extern int       g_bDoRename;        /* 40CC38 */
extern int       g_bIgnorePaths;     /* 40CC24 */
extern int       g_bDisplayHelp;     /* 40CC34 */
extern int       g_bTargetIsDir;     /* 40CC3C */
extern int       g_nNumFileSpecs;    /* 40CC2C */
extern int       g_bDoListFiles;     /* 40CC28 */
extern char     *g_pszSelectiveSpec; /* 40CC20 */
extern char     *g_pszKeyFile;       /* 40B374 */
extern int       g_nCabEncryption;   /* 40B378 */
extern char     *g_pszInFileName;    /* 40B384 area */
extern char     *g_pszTargetName;
extern char     *g_pszOutFileName;   /* 40C408 */
extern int       g_nTotalFiles;      /* 40B380 */
extern int       g_nLocalFiles;      /* 40C400 */
extern int       g_bContainsMulti;   /* 40C404 */
extern int       g_bCopiedFlag;      /* 40C388 */
extern int       g_bIsThereFile;     /* 40B388 area */

/* ------------------------------------------------------------------ */
/* LZ control block                                                    */
/* ------------------------------------------------------------------ */
typedef struct tagLZCTL
{
    unsigned char *dict;
    unsigned char *inbuf;
    unsigned char *inend;
    unsigned char *incur;
    unsigned char *outbuf;
    unsigned char *outend;
    unsigned char *outcur;
    int            eof_flag;
    int            dict_base;
    long           filesize;
    int            out_count;
    int            in_size;
    int            out_size;
    int            bitbuf;
    int            dict_pos;
} LZCTL;

/* ------------------------------------------------------------------ */
/* Prototypes                                                          */
/* ------------------------------------------------------------------ */
/* messages.c */
const char *Msg(int id);
int  PrintMsg(int id, ...);
int  PrintMsgV(int id, va_list ap);
void DisplayErrorMessage(int code);

/* expand.c */
int  ParseArguments(int argc, char **argv);
int  CheckArguments(void);
int  GetNextFileArg(char **argv);
int  IsDirectory(const char *path);
char *ExtractFileName(const char *path);
void MakePathName(char *dest, const char *path);
int  ActuallyTheSameFile(const char *a, const char *b);
int  PatternMatch(const char *str, const char *pat, int wildcardExt);
int  ProcessNotification(const char *source, const char *dest, int action);
int  ProcessDpxNotification(const char *source, const char *name, int action);
void DpxComputeTargetDir(char *buf, size_t bufSize);
int  PsfExpand(void);

/* lz.c */
LZCTL *InitGlobalBuffers(void);
void FreeGlobalBuffers(LZCTL *c);
int  Expand(LZCTL *c);

/* cab.c */
int  CabIsCabinet(const char *path);
int  CabIsPsf(const char *path);
int  CabList(const char *path);
int  CabExtractOne(const char *cabPath, const char *entryName,
                   const char *targetPath);
int  CabGetEntryCount(const char *path);
int  CabGetEntryName(const char *path, int index, char *buf, size_t bufSize);

/* dpx.c */
int  DpxExpandFile(void);

/* util.c */
int  AnsiToWide(const char *src, WCHAR **out);
int  WideToAnsi(const WCHAR *src, char **out);
void JoinPath(char *dest, size_t destSize, const char *dir, const char *name);
char *DirNameOf(const char *path, char *buf, size_t bufSize);
char *OnlyFileName(const char *path);
void EnsureParentDir(const char *path);

#endif /* EXPAND_H */
