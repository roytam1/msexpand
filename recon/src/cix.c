/* cix.c -- parse the subset of CIX XML used by DPX containers. */
#include "expand.h"
#include "cix.h"
#include "hash.h"

static unsigned long AttrUL(XMLNODE *node, const char *name)
{
    const char *s = XmlAttr(node, name);
    if (!s)
        return 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        return strtoul(s + 2, NULL, 16);
    return strtoul(s, NULL, 10);
}

static void CopyAttr(char *dest, size_t destSize, XMLNODE *node,
                     const char *name)
{
    const char *s = XmlAttr(node, name);
    dest[0] = 0;
    if (s)
    {
        strncpy(dest, s, destSize - 1);
        dest[destSize - 1] = 0;
    }
}

static void ReadHash(XMLNODE *node, CIXFILE *file)
{
    const char *value;
    unsigned char tmp[CIX_MAX_HASH];
    int n;

    CopyAttr(file->hashAlg, sizeof(file->hashAlg), node, "alg");
    file->hashLen = 0;
    value = XmlAttr(node, "value");
    if (!value)
        return;
    n = HexToBytes(value, tmp, (int)sizeof(tmp));
    if (n <= 0)
        return;
    memcpy(file->hash, tmp, (size_t)n);
    file->hashLen = n;
}

static CIXFILE *ParseFile(XMLNODE *node)
{
    CIXFILE *f;
    XMLNODE *h;
    XMLNODE *delta;
    XMLNODE *source;

    f = (CIXFILE *)calloc(1, sizeof(CIXFILE));
    if (!f)
        return NULL;
    CopyAttr(f->name, sizeof(f->name), node, "name");
    CopyAttr(f->algId, sizeof(f->algId), node, "algId");
    f->size = AttrUL(node, "length");
    f->id = (int)AttrUL(node, "id");

    h = XmlChild(node, "Hash");
    if (h)
        ReadHash(h, f);

    delta = XmlChild(node, "Delta");
    if (delta)
    {
        XMLNODE *basis = XmlChild(delta, "Basis");
        if (basis)
            f->basisId = (int)AttrUL(basis, "file");
    }
    source = delta ? XmlChild(delta, "Source") : XmlChild(node, "Source");
    if (source)
    {
        f->hasSource = 1;
        CopyAttr(f->sourceType, sizeof(f->sourceType), source, "type");
        CopyAttr(f->sourceName, sizeof(f->sourceName), source, "name");
        if (!f->algId[0])
            CopyAttr(f->algId, sizeof(f->algId), source, "algId");
        f->sourceOffset = AttrUL(source, "offset");
        f->sourceLength = AttrUL(source, "length");
        h = XmlChild(source, "Hash");
        if (h)
            ReadHash(h, f);   /* source hash takes precedence */
    }
    return f;
}

int CixParse(XMLNODE *root, CIX *out)
{
    XMLNODE *container;
    XMLNODE *files;
    XMLNODE *f;
    CIXFILE **tail;

    memset(out, 0, sizeof(*out));
    if (!root)
        return 0;
    container = XmlFind(root, "Container");
    if (!container)
        container = XmlFind(root, "container");
    if (!container)
        return 0;

    CopyAttr(out->name, sizeof(out->name), container, "name");
    CopyAttr(out->type, sizeof(out->type), container, "type");
    out->length = AttrUL(container, "length");

    files = XmlChild(container, "Files");
    if (!files)
        files = XmlChild(container, "files");
    if (!files)
        return 1;

    tail = &out->files;
    for (f = files->firstChild; f; f = f->next)
    {
        CIXFILE *item;
        if (strcmp(f->name, "File") != 0 && strcmp(f->name, "file") != 0)
            continue;
        item = ParseFile(f);
        if (!item)
            continue;
        *tail = item;
        tail = &item->next;
        ++out->count;
    }
    return 1;
}

void CixFree(CIX *cix)
{
    CIXFILE *f = cix->files;
    while (f)
    {
        CIXFILE *next = f->next;
        free(f);
        f = next;
    }
    cix->files = NULL;
    cix->count = 0;
}

CIXFILE *CixFind(CIX *cix, const char *name)
{
    CIXFILE *f;
    if (!cix || !name)
        return NULL;
    for (f = cix->files; f; f = f->next)
    {
        if (strcmp(f->name, name) == 0)
            return f;
        if (strcmp(OnlyFileName(f->name), OnlyFileName(name)) == 0)
            return f;
    }
    return NULL;
}

int CixVerifyHash(CIXFILE *file, const unsigned char *data,
                  unsigned long len)
{
    unsigned char computed[4];
    unsigned long crc;
    int n;

    if (!file || file->hashLen <= 0)
        return 1;    /* nothing to verify */

    if (strcmp(file->hashAlg, "CRC32") == 0 ||
        strcmp(file->hashAlg, "CIX_HASH_CRC32") == 0 ||
        strcmp(file->hashAlg, "32") == 0)
    {
        crc = Crc32(data, len);
        computed[0] = (unsigned char)((crc >> 24) & 0xFF);
        computed[1] = (unsigned char)((crc >> 16) & 0xFF);
        computed[2] = (unsigned char)((crc >> 8) & 0xFF);
        computed[3] = (unsigned char)(crc & 0xFF);
        n = file->hashLen < 4 ? file->hashLen : 4;
        return memcmp(computed, file->hash, (size_t)n) == 0;
    }
    /* MD5/SHA* are not implemented in Phase A. */
    return 1;
}
