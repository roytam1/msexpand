/*
 * util.c -- string / path / pattern helpers used by both the LZ and DPX
 * code paths.  Plain C89, Win32 API only.
 */
#include "expand.h"

int AnsiToWide(const char *src, WCHAR **out)
{
    int n, bytes;
    WCHAR *buf;

    *out = NULL;
    if (!src)
        return 0;
    n = MultiByteToWideChar(CP_ACP, 0, src, -1, NULL, 0);
    if (n <= 0)
        return 0;
    bytes = (n + 1) * (int)sizeof(WCHAR);
    buf = (WCHAR *)malloc((size_t)bytes);
    if (!buf)
        return 0;
    if (!MultiByteToWideChar(CP_ACP, 0, src, -1, buf, n))
    {
        free(buf);
        return 0;
    }
    buf[n - 1] = 0;
    *out = buf;
    return 1;
}

int WideToAnsi(const WCHAR *src, char **out)
{
    int n;
    char *buf;

    *out = NULL;
    if (!src)
        return 0;
    n = WideCharToMultiByte(CP_ACP, 0, src, -1, NULL, 0, NULL, NULL);
    if (n <= 0)
        return 0;
    buf = (char *)malloc((size_t)n + 1);
    if (!buf)
        return 0;
    if (!WideCharToMultiByte(CP_ACP, 0, src, -1, buf, n, NULL, NULL))
    {
        free(buf);
        return 0;
    }
    buf[n - 1] = 0;
    *out = buf;
    return 1;
}

char *OnlyFileName(const char *path)
{
    const char *p;
    const char *last = path;

    if (!path)
        return (char *)path;
    for (p = path; *p; ++p)
    {
        if (*p == '\\' || *p == '/' || *p == ':')
            last = p + 1;
    }
    return (char *)last;
}

char *DirNameOf(const char *path, char *buf, size_t bufSize)
{
    char *name;
    size_t n;

    if (!path || !buf || bufSize == 0)
        return NULL;
    name = OnlyFileName(path);
    n = (size_t)(name - path);
    if (n > 0 && (path[n - 1] == '\\' || path[n - 1] == '/'))
        --n;
    if (n >= bufSize)
        n = bufSize - 1;
    memcpy(buf, path, n);
    buf[n] = 0;
    if (n == 0)
    {
        GetCurrentDirectoryA((DWORD)bufSize, buf);
    }
    return buf;
}

void JoinPath(char *dest, size_t destSize, const char *dir, const char *name)
{
    size_t dl, nl, pos;
    int needSep;

    if (!dest || destSize == 0)
        return;
    dest[0] = 0;
    if (!dir)
        dir = "";
    if (!name)
        name = "";

    dl = strlen(dir);
    while (dl > 0 && (dir[dl - 1] == '\\' || dir[dl - 1] == '/'))
        --dl;
    nl = strlen(name);
    while (nl > 0 && (name[0] == '\\' || name[0] == '/'))
    {
        ++name;
        --nl;
    }

    needSep = (dl > 0 && nl > 0 && dir[dl - 1] != ':' &&
               dir[dl - 1] != '\\' && dir[dl - 1] != '/');

    pos = 0;
    if (dl > 0)
    {
        if (dl >= destSize)
            dl = destSize - 1;
        memcpy(dest, dir, dl);
        pos = dl;
    }
    if (needSep && pos < destSize - 1)
        dest[pos++] = '\\';
    if (nl > 0)
    {
        if (pos + nl >= destSize)
            nl = destSize - 1 - pos;
        if (nl > 0)
            memcpy(dest + pos, name, nl);
        pos += nl;
    }
    dest[pos] = 0;
}

void EnsureParentDir(const char *path)
{
    char buf[MAX_PATH];
    char *p;
    char *start;
    char save;
    size_t n;

    if (!path)
        return;
    n = strlen(path);
    if (n >= sizeof(buf))
        n = sizeof(buf) - 1;
    memcpy(buf, path, n);
    buf[n] = 0;

    start = buf;
    if (buf[0] == '\\' && buf[1] == '\\')
        start = buf + 2;
    else if (buf[1] == ':')
        start = buf + 2;

    for (p = start; *p; ++p)
    {
        if (*p != '\\' && *p != '/')
            continue;
        save = *p;
        *p = 0;
        if (buf[0] != 0)
            CreateDirectoryA(buf, NULL);
        *p = save;
    }
}

static int CharFold(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c + 32;
    return c;
}

/* Case-insensitive single character comparison. */
static int CharacterMatch(char a, char b)
{
    return CharFold((unsigned char)a) == CharFold((unsigned char)b);
}

/*
 * DOS wildcard matcher.  '*' matches any sequence, '?' matches exactly one
 * character.  wildcardExt affects the treatment of a trailing dot.
 */
int PatternMatch(const char *str, const char *pat, int wildcardExt)
{
    const char *s = str;
    const char *p = pat;
    const char *starPat = NULL;
    const char *starStr = NULL;
    int matched;

    if (!s || !p)
        return 0;

    while (*s)
    {
        if (*p == '*')
        {
            starPat = p++;
            starStr = s;
            continue;
        }
        if (*p == '?' || CharacterMatch(*p, *s))
        {
            ++p;
            ++s;
            continue;
        }
        if (starPat)
        {
            p = starPat + 1;
            ++starStr;
            s = starStr;
            continue;
        }
        return 0;
    }

    while (*p == '*')
        ++p;

    if (*p == 0)
        return 1;

    /* A trailing dot in the pattern is optional in DOS wildcard semantics. */
    if (*p == '.' && p[1] == 0 && wildcardExt)
        return 1;
    matched = (*p == 0);
    return matched;
}
