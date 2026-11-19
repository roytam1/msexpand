#ifndef SFX_H
#define SFX_H

#include "expand.h"

/* A Windows Update self-extracting package: a PE stub with an embedded CAB
 * that carries _sfx_manifest_ and/or _sfx_.dll.  SfxLoad() carves the CAB to
 * a temporary file and parses the manifest; SfxExpandFile() extracts it and
 * applies the manifest's delta entries with DeltaApply(). */

typedef struct tagSFXDELTA
{
    char target[MAX_PATH];
    char patch[MAX_PATH];
    char source[MAX_PATH];
} SFXDELTA;

typedef struct tagSFXCOPY
{
    char target[MAX_PATH];
    char source[MAX_PATH];
} SFXCOPY;

/* [Verify] "target" = 32 hex digits (MD5 of the final output). */
typedef struct tagSFXVERIFY
{
    char target[MAX_PATH];
    char hash[33];
} SFXVERIFY;

/* [Delete] "pattern" -- DOS wildcards, applied to files this run wrote. */
typedef struct tagSFXDELETE
{
    char pattern[MAX_PATH];
} SFXDELETE;

typedef struct tagSFX
{
    char inputPath[MAX_PATH];
    char cabPath[MAX_PATH];
    char manifestPath[MAX_PATH];
    char *text;
    SFXDELTA delta[64];
    int nDelta;
    SFXCOPY copy[32];
    int nCopy;
    SFXVERIFY verify[64];
    int nVerify;
    SFXDELETE del[32];
    int nDelete;
    int hasManifest;
} SFX;

int  SfxIsArchive(const char *path);
int  SfxLoad(const char *path, SFX *sfx);
int  SfxExpandFile(SFX *sfx, const char *destDir);
void SfxFree(SFX *sfx);

#endif /* SFX_H */
