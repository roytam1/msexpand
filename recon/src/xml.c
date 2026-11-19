/* xml.c -- minimal UTF-8 XML DOM parser, sufficient for CIX manifests. */
#include "expand.h"
#include "xml.h"

#define XML_MAX_DEPTH 64

static char *DupN(const char *s, unsigned long n)
{
    char *p;
    if (n > 0xFFFFFFUL)
        return NULL;
    p = (char *)malloc((size_t)n + 1);
    if (!p)
        return NULL;
    memcpy(p, s, (size_t)n);
    p[n] = 0;
    return p;
}

static XMLNODE *NewNode(const char *name, unsigned long nameLen)
{
    XMLNODE *n = (XMLNODE *)calloc(1, sizeof(XMLNODE));
    if (!n)
        return NULL;
    n->name = DupN(name, nameLen);
    if (!n->name)
    {
        free(n);
        return NULL;
    }
    return n;
}

static void AddChild(XMLNODE *parent, XMLNODE *child)
{
    if (!parent || !child)
        return;
    if (parent->lastChild)
        parent->lastChild->next = child;
    else
        parent->firstChild = child;
    parent->lastChild = child;
}

static void AddAttr(XMLNODE *node, const char *name, unsigned long nameLen,
                    const char *value, unsigned long valueLen)
{
    XMLATTR *a;
    if (!node)
        return;
    a = (XMLATTR *)calloc(1, sizeof(XMLATTR));
    if (!a)
        return;
    a->name = DupN(name, nameLen);
    a->value = DupN(value, valueLen);
    if (!a->name || !a->value)
    {
        free(a->name);
        free(a->value);
        free(a);
        return;
    }
    a->next = node->attrs;
    node->attrs = a;
}

static void AppendText(XMLNODE *node, const char *s, unsigned long n)
{
    unsigned long oldLen;
    char *p;

    if (!node || n == 0)
        return;
    oldLen = node->text ? (unsigned long)strlen(node->text) : 0;
    p = (char *)realloc(node->text, (size_t)(oldLen + n + 1));
    if (!p)
        return;
    node->text = p;
    memcpy(p + oldLen, s, (size_t)n);
    p[oldLen + n] = 0;
}

/* Decode XML entities into a fresh string. */
static char *DecodeEntities(const char *s, unsigned long n)
{
    char *out;
    unsigned long i, j;
    if (!s || n > 0xFFFFFFUL)
        return NULL;
    out = (char *)malloc((size_t)n + 1);
    if (!out)
        return NULL;
    j = 0;
    for (i = 0; i < n; ++i)
    {
        if (s[i] != '&')
        {
            out[j++] = s[i];
            continue;
        }
        if (n - i >= 6 && memcmp(s + i, "&quot;", 6) == 0)
        {
            out[j++] = '"';
            i += 5;
        }
        else if (n - i >= 6 && memcmp(s + i, "&apos;", 6) == 0)
        {
            out[j++] = '\'';
            i += 5;
        }
        else if (n - i >= 5 && memcmp(s + i, "&lt;", 4) == 0)
        {
            out[j++] = '<';
            i += 3;
        }
        else if (n - i >= 5 && memcmp(s + i, "&gt;", 4) == 0)
        {
            out[j++] = '>';
            i += 3;
        }
        else if (n - i >= 6 && memcmp(s + i, "&amp;", 5) == 0)
        {
            out[j++] = '&';
            i += 4;
        }
        else
        {
            out[j++] = s[i];
        }
    }
    out[j] = 0;
    return out;
}

static int NameEnd(const char *p, const char *end)
{
    int i = 0;
    while (p + i < end)
    {
        char c = p[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
            c == '>' || c == '/' || c == '=')
            break;
        ++i;
    }
    return i;
}

static void SkipSpace(const char **pp, const char *end)
{
    while (*pp < end && (**pp == ' ' || **pp == '\t' ||
           **pp == '\r' || **pp == '\n'))
        ++(*pp);
}

XMLNODE *XmlParse(const char *buf, unsigned long len)
{
    const char *p = buf;
    const char *end = buf + len;
    XMLNODE *stack[XML_MAX_DEPTH];
    int depth = 0;
    XMLNODE *root = NULL;

    if (!buf || len == 0)
        return NULL;
    if (len >= 3 && (unsigned char)p[0] == 0xEF &&
        (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF)
        p += 3;

    while (p < end)
    {
        if (*p != '<')
        {
            const char *start = p;
            while (p < end && *p != '<')
                ++p;
            if (depth > 0)
            {
                char *txt = DecodeEntities(start, (unsigned long)(p - start));
                if (txt)
                {
                    AppendText(stack[depth - 1], txt,
                               (unsigned long)strlen(txt));
                    free(txt);
                }
            }
            continue;
        }

        if (p + 2 <= end && memcmp(p, "<?", 2) == 0)
        {
            p += 2;
            while (p + 2 <= end && memcmp(p, "?>", 2) != 0)
                ++p;
            if (p + 2 <= end)
                p += 2;
            continue;
        }
        if (p + 4 <= end && memcmp(p, "<!--", 4) == 0)
        {
            p += 4;
            while (p + 3 <= end && memcmp(p, "-->", 3) != 0)
                ++p;
            if (p + 3 <= end)
                p += 3;
            continue;
        }
        if (p + 9 <= end && memcmp(p, "<![CDATA[", 9) == 0)
        {
            const char *start = p + 9;
            p += 9;
            while (p + 3 <= end && memcmp(p, "]]>", 3) != 0)
                ++p;
            if (depth > 0)
                AppendText(stack[depth - 1], start, (unsigned long)(p - start));
            if (p + 3 <= end)
                p += 3;
            continue;
        }
        if (p + 2 <= end && memcmp(p, "</", 2) == 0)
        {
            p += 2;
            while (p < end && *p != '>')
                ++p;
            if (p < end)
                ++p;
            if (depth > 0)
                --depth;
            continue;
        }

        /* Opening tag. */
        ++p;
        {
            const char *nameStart = p;
            int nameLen;
            int selfClosing = 0;
            XMLNODE *node;

            nameLen = NameEnd(p, end);
            p += nameLen;
            if (nameLen == 0)
            {
                if (p < end)
                    ++p;
                continue;
            }
            node = NewNode(nameStart, (unsigned long)nameLen);
            if (!node)
                break;
            if (!root)
                root = node;
            else if (depth > 0)
                AddChild(stack[depth - 1], node);

            for (;;)
            {
                const char *aname;
                int aLen;
                const char *valueStart = NULL;
                unsigned long valueLen = 0;

                SkipSpace(&p, end);
                if (p >= end || *p == '>')
                {
                    if (p < end)
                        ++p;
                    break;
                }
                if (*p == '/')
                {
                    selfClosing = 1;
                    while (p < end && *p != '>')
                        ++p;
                    if (p < end)
                        ++p;
                    break;  /* self-closing: do not push */
                }
                aname = p;
                aLen = NameEnd(p, end);
                p += aLen;
                SkipSpace(&p, end);
                if (aLen == 0 || p >= end || *p != '=')
                    break;
                ++p;
                SkipSpace(&p, end);
                if (p >= end || (*p != '"' && *p != '\''))
                    break;
                {
                    char quote = *p++;
                    valueStart = p;
                    while (p < end && *p != quote)
                        ++p;
                    valueLen = (unsigned long)(p - valueStart);
                    if (p < end)
                        ++p;
                }
                {
                    char *dec = DecodeEntities(valueStart, valueLen);
                    if (dec)
                    {
                        AddAttr(node, aname, (unsigned long)aLen, dec,
                                (unsigned long)strlen(dec));
                        free(dec);
                    }
                }
            }
            if (!selfClosing && depth < XML_MAX_DEPTH)
            {
                stack[depth] = node;
                ++depth;
            }
        }
    }
    return root;
}

void XmlFree(XMLNODE *root)
{
    XMLATTR *a;
    XMLNODE *n;
    if (!root)
        return;
    n = root->firstChild;
    while (n)
    {
        XMLNODE *next = n->next;
        XmlFree(n);
        n = next;
    }
    a = root->attrs;
    while (a)
    {
        XMLATTR *next = a->next;
        free(a->name);
        free(a->value);
        free(a);
        a = next;
    }
    free(root->name);
    free(root->text);
    free(root);
}

const char *XmlAttr(XMLNODE *node, const char *name)
{
    XMLATTR *a;
    if (!node || !name)
        return NULL;
    for (a = node->attrs; a; a = a->next)
    {
        if (strcmp(a->name, name) == 0)
            return a->value;
    }
    return NULL;
}

XMLNODE *XmlChild(XMLNODE *node, const char *name)
{
    XMLNODE *c;
    if (!node || !name)
        return NULL;
    for (c = node->firstChild; c; c = c->next)
    {
        if (strcmp(c->name, name) == 0)
            return c;
    }
    return NULL;
}

XMLNODE *XmlFind(XMLNODE *node, const char *name)
{
    XMLNODE *c;
    if (!node)
        return NULL;
    if (strcmp(node->name, name) == 0)
        return node;
    for (c = node->firstChild; c; c = c->next)
    {
        XMLNODE *r = XmlFind(c, name);
        if (r)
            return r;
    }
    return NULL;
}
