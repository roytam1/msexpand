#ifndef CIX_H
#define CIX_H

#include "xml.h"

#define CIX_MAX_HASH 64

typedef struct tagCIXFILE
{
    char name[MAX_PATH];
    unsigned long size;
    int id;
    int hasSource;
    int basisId;
    char sourceType[32];
    char sourceName[MAX_PATH];
    unsigned long sourceOffset;
    unsigned long sourceLength;
    char algId[32];
    char hashAlg[32];
    unsigned char hash[CIX_MAX_HASH];
    int hashLen;
    struct tagCIXFILE *next;
} CIXFILE;

typedef struct tagCIX
{
    char name[MAX_PATH];
    char type[16];
    unsigned long length;
    CIXFILE *files;
    int count;
} CIX;

int CixParse(XMLNODE *root, CIX *out);
void CixFree(CIX *cix);
CIXFILE *CixFind(CIX *cix, const char *name);
int CixVerifyHash(CIXFILE *file, const unsigned char *data,
                  unsigned long len);

#endif
