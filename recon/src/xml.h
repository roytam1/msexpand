#ifndef XML_H
#define XML_H

typedef struct tagXMLATTR
{
    char *name;
    char *value;
    struct tagXMLATTR *next;
} XMLATTR;

typedef struct tagXMLNODE
{
    char *name;
    XMLATTR *attrs;
    char *text;
    struct tagXMLNODE *firstChild;
    struct tagXMLNODE *lastChild;
    struct tagXMLNODE *next;
} XMLNODE;

XMLNODE *XmlParse(const char *buf, unsigned long len);
void XmlFree(XMLNODE *root);
const char *XmlAttr(XMLNODE *node, const char *name);
XMLNODE *XmlChild(XMLNODE *node, const char *name);
XMLNODE *XmlFind(XMLNODE *node, const char *name);

#endif
