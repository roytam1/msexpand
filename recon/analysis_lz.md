# Analysis: Classic LZ expansion path in `expand.exe.c`

Source: `\\roy-xp\c\devel\cabarc\expand.exe.c` (Hex-Rays decompilation of a modern
`expand.exe`, image base `0x400000`, ANSI/LZ "SZDD" legacy path as opposed to the
DPX/CAB path). All line numbers refer to that file. Addresses quoted below are the
IDA guesses embedded as comments in the decompilation.

--------------------------------------------------------------------------------
## 1. Executive summary of the data flow

```
main
  -> InitGlobalBuffers()               allocates one "LZ control block"
  -> Expand(in, out, control)          top-level driver, one physical file
       -> GetIOHandle(input,1,...)     opens input read-only, stores its size in control+36
       -> GetHdr(&hdr14, in, &size)    reads/parses the 14-byte SZDD header
       -> IsCompressed(&hdr14)         strcmp(header[0..7], "SZDD")
       -> ProcessNotification(...)     prints "Expanding"/"Copying" (or lists files)
       -> _lcreat(out, 0)              creates/writes the output file
       -> ExpandOrCopyFile(in, out, control)
            -> GetHdr(...)             (header re-read)
            -> if compressed:  LZDecode(in, out, size-1, unused, unused, control)
               else:           lz_CopyFile(in, out, control)
            -> WriteOutBuf('F', out, control)   (flushes pending output; byte is a dummy)
            -> GetFileTime / SetFileTime        (preserve timestamps)
            -> verify bytes written == uncompressed size for compressed input
  -> FreeGlobalBuffers()
```

Return convention used throughout: `1` = success; `0` = "skip / not an error";
negative values are errors (`-1 .. -8`, `-2/-4` from write helpers, `500` from
`ReadInBuf` = soft EOF).

--------------------------------------------------------------------------------
## 2. Global variables touched by these functions

| Name | Address (from IDB) | Meaning / use |
|---|---|---|
| `String2` | (const data) | `const CHAR String2[] = "SZDD";` (line 392). Compared by `IsCompressed`. |
| `hResInstance` | not annotated (decl. line 438) | HINSTANCE of the loaded MUI resource DLL used by `LoadStringA`/`LoadStringW`. Read by `DisplayErrorMessage`, `PrintMessage`, `ProcessNotification`, `main`. |
| `ErrorMsg` | not annotated (decl. line 470, `CHAR[2048]`) | scratch buffer for `LoadStringA` + `CharToOemA` + `_printf`. Written by `DisplayErrorMessage`, `ProcessNotification`, main/argument parsing. |
| `ErrorMsgW` | `0x40B388` (line 1661) | `WCHAR[2048]` scratch for `LoadStringW` in `PrintMessage`. |
| `pszInFileName` | not annotated (decl. line 465) | global input (source) file name; used as printf argument for input-related errors and by `Expand`. |
| `pszOutFileName` | `0x40C408` | global output (destination) file name; read by `Expand` and used as printf argument for output-related errors. |
| `bDoRename` | `0x40CC38` | `expand -r` flag: when 1, `MakeExpandedName()` restores the filename character stored in the LZ header. Read by `Expand`. |
| `bDoListFiles` | `0x40CC28` | `-d`/list-only flag; causes `ProcessNotification` to print "expanding ... to ..." style listing and return 0 (abort expansion). |
| `nLocalFiles` | `0x40C400` | per-input-file counter incremented by `ProcessNotification`. |
| `nTotalFiles` | `0x40B380` | total files counter incremented by `ProcessNotification`. |
| `dword_40C388` | `0x40C388` | set to 1 by `ProcessNotification` when notification kind != 1 (i.e. copy path); used by main to choose the "copied" vs "expanded" summary message. |
| `bContainsMultipleFiles` | `0x40C404` | set by `IsDiamondFile`; selects the DPX/CAB path in main. |
| `FdiContext`/`FdiError` | decl. lines 463-464 | FDI state; only relevant to the DIAMOND path, not the LZ path. |
| `NlsMbCodePageTag` | imported (ntdll), line 592 | Boolean "current ACP is DBCS". Read by `LZCharNextA`, `LZCharPrevA`, `LZIsCharLowerA`, `LZIsCharUpperA` and indirectly by `ExtractFileName`, `MakePathName`, `MakeExpandedName`, `StringRevChar`. |

Note: `InitGlobalBuffers`/`FreeGlobalBuffers`, `GetIOHandle`, `lz_CopyFile`,
`GetHdr`, `IsCompressed`, `LZDecode`, `ReadInBuf`, `WriteOutBuf`,
`ExtractFileName`, `MakePathName`, `MakeExpandedName`, `StringRevChar`,
`PatternMatch`, `CharacterMatch`, `ActuallyTheSameFile(W)` and the `SpdFdi*`
wrappers touch **no named globals** directly (the buffer block is heap state,
not a global; main keeps its handle in a local `inited`).

--------------------------------------------------------------------------------
## 3. The 14-byte "SZDD" header (read by `GetHdr`)

The classic Microsoft COMPRESS.EXE (LZ / SZDD) file begins with a 14-byte header,
then the raw compressed token stream. Field offsets below are the offsets written
into the `a1` structure by `GetHdr` (line 4178); file offsets are identical.

```
 file off   size  field written by GetHdr        meaning
 --------   ----  -----------------------------  ---------------------------------
 0x00       4     *(DWORD*)(a1+0)  = Buffer[0]   signature, ASCII "SZDD" (0x445A5A53)
 0x04       4     *(DWORD*)(a1+4)  = Buffer[1]   reserved second DWORD; byte 4 must
                                                 be NUL for IsCompressed() to match
 0x08       1     *(BYTE *)(a1+8)  = v13         version byte; must be 0x41 ('A')
                                                 (checked as HIBYTE(v15) in ExpandOrCopyFile)
 0x09       1     *(BYTE *)(a1+9)  = v14         "expansion character": original last
                                                 filename character replaced by '_'
                                                 by compress.exe; used by MakeExpandedName
 0x0A       4     *(DWORD*)(a1+12) = LE32(v15[0..3])  UNCOMPRESSED data size in bytes
 0x0E       ...   compressed token stream starts here (LZDecode seeks to 14)
```

`GetHdr` also stores the physical file length (from `_llseek(fd,0,SEEK_END)`) at
`a1+16`. The caller passes `a3 = control+36`, so `control+36` always ends up holding
the *physical* source-file size (GetIOHandle stores it there first, GetHdr
overwrites it with the same value). `control+36` is also used by the check
"`file size >= 14 => a short/failed header read is fatal`".

`IsCompressed` (line 4221) copies the first 8 header bytes into a 9-byte local
(`String1[0..3] = *this`, `[4..7] = this[1]`, `[8] = 0`) and calls
`lstrcmpA(String1, "SZDD")`. Net effect: **compressed iff bytes 0..3 == "SZDD"
and byte 4 == 0**. A file shorter than 14 bytes still gets a zeroed header block
and is therefore treated as uncompressed (raw copy).

--------------------------------------------------------------------------------
## 4. The LZ control block allocated by `InitGlobalBuffers`

`InitGlobalBuffers(int a1)` (line 3662; `a1` is unused) returns a `LocalAlloc(0x40,
0x54)` (84-byte) handle to a struct whose fields are (offsets confirmed by all
users):

```
 +0   BYTE  *dict      dictionary buffer, GlobalAlloc(0x40, 0x1080) = 4224 bytes
                       (used as a 4096-byte circular buffer)
 +4   BYTE  *inbuf     input buffer, GlobalAlloc(0x40, InSize+1)   (InSize starts 0x8000)
 +8   BYTE  *inend     one-past-end pointer for input buffer
 +12  BYTE  *incur     current read pointer in input buffer
 +16  BYTE  *outbuf    output buffer, GlobalAlloc(0x40, OutSize)   (OutSize starts 0x8000)
 +20  BYTE  *outend    one-past-end pointer for output buffer
 +24  BYTE  *outcur    current write pointer in output buffer
 +28  int    eof_flag  "push-back byte pending" flag (see ReadInBuf)
 +32  int    dict_base 16 initially: first dict byte not pre-filled with spaces
 +36  LONG   filesize  physical source-file size (GetIOHandle/GetHdr)
 +40  int    out_count total number of bytes emitted (LZDecode / lz_CopyFile)
 +44  int    in_size   input buffer size (starts 0x8000, decremented on alloc failure)
 +48  int    out_size  output buffer size (starts 0x8000, decremented on alloc failure)
 +52  int    bitbuf    shift register holding the current 8-bit control byte
 +56  int    dict_pos  dictionary write index, masked with 0xFFF each advance
```

Allocation strategy: start with 32768-byte buffers; if either GlobalAlloc fails,
subtract 1024 from both sizes and retry until one reaches zero (then free
everything and fail). `FreeGlobalBuffers` (line 3707) frees fields +0, +4, +16
if non-NULL, zeroes them, and `LocalFree`s the block. Neither touches globals.

--------------------------------------------------------------------------------
## 5. `GetHdr` — exact algorithm (C89 reconstruction)

```c
int GetHdr(char *hdr14, HFILE fd, LONG *filesize)
{
    int  i, val = 0;
    UINT n;
    int  buf[2];
    unsigned char b8, b9;    /* file bytes 8 and 9 */
    unsigned char tail[6];   /* file bytes 10..15; only [0..3] used */

    *filesize = _llseek(fd, 0L, SEEK_END);        /* physical length */
    if (*filesize < 0 || _llseek(fd, 0L, SEEK_SET) != 0)
        return -1;
    n = _lread(fd, buf, 14);                      /* one-shot header read */
    if (n != 14)
        return (n == (UINT)-1) ? -3 : -2;         /* 2*(n==-1)-3 */

    memcpy(hdr14 + 0, buf, 8);                    /* signature + reserved dword */
    b8 = ((unsigned char *)buf)[8]; b9 = ((unsigned char *)buf)[9];
    hdr14[8] = b8;               /* file byte 8: version (v13)          */
    hdr14[9] = b9;               /* file byte 9: expansion char (v14)  */
    /* bytes 10..13 are tail[0..3] = v15[0..3]: */
    val = 0;
    for (i = 0; i < 4; ++i)
        val |= (int)tail[i] << (8 * i);            /* little-endian 32-bit size */
    *(int *)(hdr14 + 12) = val;                    /* uncompressed size */
    *(LONG *)(hdr14 + 16) = *filesize;             /* physical size */
    return 1;
}
```
(The decompiler's `v11 = (unsigned char)v15[v10] << v9; v9 += 8;` is exactly the
LE32 assembly above.) A `_lread` result of -1 yields -3, any other short read
yields -2.

--------------------------------------------------------------------------------
## 6. `LZDecode` — EXACT reconstruction of the token stream

Signature (line 4234): `int LZDecode(HFILE in, HFILE out, int last, int unused1,
int unused2, LZCTL *c)`. `last = uncompressed_size - 1`; `unused1/unused2` are
garbage (`v4` in ExpandOrCopyFile, flagged "possibly undefined" by Hex-Rays) and
are never read. `out == -2` means "no output file" (discard decoded bytes).

### 6.1 Setup

```
 c->dict_base = 16;
 if (_llseek(in, 14, SEEK_SET) != 14) return -1;   /* skip header */
 if (out == -2 || _llseek(out, 0, SEEK_SET) == 0) {
    c->inend  = c->inbuf + c->in_size + 1;
    c->eof_flag = 0;
    c->incur  = c->inend;          /* force first ReadInBuf */
    c->outend = c->outbuf + c->out_size;
    c->outcur = c->outbuf;
    for (i = 0; i < 4096 - c->dict_base; ++i) c->dict[i] = 0x20; /* spaces */
    c->dict_pos = 4096 - c->dict_base;  /* = 4080 */
    c->bitbuf = 0;
    ... read first token byte via ReadInBuf(&ch, in, c) ...
 } else return -2;
```

The dictionary is a 4096-byte ring. Bytes `0..4079` are pre-filled with spaces
(`0x20`); the remaining 16 bytes are left as allocated, because the first 16
emitted bytes will be written there before any back-reference can reach them.
`dict_pos` starts at 4080 and wraps mod 4096.

### 6.2 Control-byte mechanism

`bitbuf` is a 16-bit shift register in the low word of an `int`:

```
 bitbuf >>= 1;
 if ((bitbuf & 0x100) == 0) {         /* all 8 bits consumed */
     bitbuf = token_byte | 0xFF00;    /* load a new control byte, marker bits in 8..15 */
     token_byte = next_input_byte();  /* the data byte for THIS token */
 }
 if (bitbuf & 1)  -> literal token
 else             -> back-reference token
```

Exactly 8 tokens are governed by one control byte, consumed **LSB first**. Bit=1
means literal; bit=0 means back-reference. After the 8th shift the marker
`0xFF00` has moved to `0x00FF`, so bit 8 becomes 0 and a new control byte is
loaded. `next_input_byte()` takes the byte either directly from the input buffer
(`*incur++`) or via `ReadInBuf` when `incur >= inend`.

### 6.3 Literal token (bit = 1)

```
 emit(token_byte);           /* append to output buffer / flush if full */
 dict[dict_pos] = token_byte;
 dict_pos = (dict_pos + 1) & 0xFFF;
```

### 6.4 Back-reference token (bit = 0)

Read one extra byte `b` (the "second token byte"). Then:

```
 distance = ((unsigned)b & 0xF0)*16 | (unsigned)token_byte;  /* 12-bit ring index */
                                  /* i.e. distance = ((b >> 4) << 8) | first_byte */
 length   = (b & 0x0F) + 3;                                  /* 3..18 bytes */
 for (i = 0; i < length; ++i) {
     ch = dict[(distance + i) & 0xFFF];
     emit(ch);
     dict[dict_pos] = ch;
     dict_pos = (dict_pos + 1) & 0xFFF;
 }
```

(The decompiler expresses `length` as `v26 = (b & 0x0F) + 2` and then loops with
`v21 = 0,1,... <= v26`, i.e. `v26+1 = (b & 0x0F)+3` bytes.) Crucially,
`distance` is an **absolute index into the 4096-byte ring buffer**, not a relative
distance from the current output position; the compressor mirrors the same
monotonically advancing ring index. Because the copy loop writes each emitted
byte back into the ring at `dict_pos`, overlapping copies work naturally.

### 6.5 Output and EOF

`emit(ch)`: if `outcur >= outend` then increment `c->out_count` and call
`WriteOutBuf(ch, out, c)` (flush + place `ch` at the start of the output buffer);
otherwise store `*outcur++ = ch` and increment `c->out_count`.

Each loop iteration re-reads the next token byte: if `incur >= inend` it calls
`ReadInBuf(&ch, in, c)`; return values other than 1 or 500 are propagated as
errors, `500` (EOF) ends decompression successfully with return 1. Otherwise the
byte is taken directly from `*incur++`.

The main loop condition is `while (c->out_count <= last)` with
`last = uncompressed_size - 1`, so the decoder emits **exactly** the number of
bytes declared in the header. On normal completion, if `incur == inbuf + 1` it
sets `eof_flag = 1`, otherwise it rewinds `incur` by one byte (push-back).

### 6.6 The "special 0x00 / 0x01 tokens" question

In the canonical Microsoft LZ (SZDD) format the back-reference byte pair
`(first=0x00, second=0x00)` and `(first=0x00, second=0x01)` are reserved:
traditionally `0x00 0x00` encodes a literal NUL byte and `0x00 0x01` denotes
end-of-stream (some references swap those two meanings). **This decompilation
contains no explicit special-case branch**: both pairs are treated as ordinary
back-references (distance 0 / 256, lengths 3 / 4, reading the space-initialized
dictionary). The decoder instead relies on the 14-byte header's uncompressed-size
field to terminate, so an explicit end-of-stream token is unnecessary; and the
`if (v26 >= 0)` test at line 4345 is a decompiler artifact (always true for a
length nibble) rather than a special-token check. For a byte-exact reimplementation
of *this* binary, follow rules 6.2-6.5 literally. If interoperability with classic
`compress.exe` output is required, add the reserved-pair handling before the
generic back-reference path.

--------------------------------------------------------------------------------
## 7. `ReadInBuf` / `WriteOutBuf` — exact algorithms

```c
int ReadInBuf(BYTE *outch, HFILE fd, LZCTL *c)
{
    UINT n;
    *c->inbuf = *(c->inend - 1);          /* preserve last byte of previous chunk */
    n = _lread(fd, c->inbuf + 1, c->in_size);
    if (n != c->in_size) {
        if (n == (UINT)-1) return -1;
        if (n == 0) return 500;            /* soft EOF */
        c->inend = c->inbuf + n + 1;       /* short final chunk */
    }
    if (c->eof_flag == 0) {
        if (c->in_size == 0) return -1;
        *outch = c->inbuf[1];              /* first freshly-read byte */
        c->incur = c->inbuf + 2;
    } else {
        *outch = c->inbuf[0];              /* consume pushed-back byte */
        c->eof_flag = 0;
    }
    return 1;
}

int WriteOutBuf(char ch, HFILE fd, LZCTL *c)
{
    const char *p = c->outbuf;
    UINT pending = (UINT)(c->outcur - p);
    c->outcur = p;                         /* reset output pointer */
    if (fd != -2) {
        UINT w = _lwrite(fd, p, pending);
        if (w != pending) return (w == (UINT)-1) ? -4 : -2;
    }
    *c->outcur++ = ch;                     /* place new byte at buffer start */
    return 1;
}
```
The `inbuf[0] = *(inend-1)` trick lets a back-reference that crosses a 32 KiB
input-buffer refill still see the preceding byte(s). `WriteOutBuf` is also used
once as a pure flush in `ExpandOrCopyFile` with dummy byte `'F'` (70), which is
written but never observed.

--------------------------------------------------------------------------------
## 8. Function-by-function reference

### `InitGlobalBuffers` (line 3662) / `FreeGlobalBuffers` (line 3707)
Covered in section 4. Parameters: `a1` unused; both return a LocalAlloc handle
(or NULL). Globals: none.

### `GetIOHandle` (line 3734)
```c
int GetIOHandle(LPCSTR path, int attr, int *phandle, LONG *psize)
{
    if (!path) { *phandle = -2; return 1; }        /* -2 = null output sink */
    if (!attr) {  *phandle = _lcreat(path, 0);
                  return (*phandle == -1) ? -2 : 1; }
    *phandle = _lopen(path, 0);                    /* read-only open */
    if (*phandle != -1) {
        *psize = _llseek(*phandle, 0, 2);          /* file size */
        if (*psize >= 0 && _llseek(*phandle, 0, 0) == 0) return 1;
        _lclose(*phandle);
    }
    return -1;
}
```
`attr == 0` means create-for-write, nonzero means open-for-read (Expand passes 1).
Returns 1 on success, -2 (create failure), -1 (open/seek failure). Globals: none.

### `ExtractFileName` (line 3767)
Walks the ANSI string with `LZCharNextA` (DBCS-aware), remembering the position
just after every `/`, `\\` or `:` separator; returns a pointer to the last path
component (the file name). Globals: `NlsMbCodePageTag` indirectly.

### `MakePathName` (line 3789)
`char MakePathName(char *dest, int src)`: `fn = ExtractFileName(src)`. If `fn`
is not empty and is not exactly `"."`, appends `\\` to `dest` unless `dest`
already ends in `/`, `\\` or `:`, then appends `fn` (both via `_strcat_s(dest,
0x104, ...)`). Returns the `_strcat_s` status. Globals: none.

### `MakeExpandedName` (line 3813)
`int MakeExpandedName(BYTE *path, BYTE expandchar)`:
1. Find the '.' in the file-name part of `path` (DBCS-aware scan).
2. If an extension exists and `expandchar` is an ASCII letter: determine the case
   of the first alphabetic character in `path` and force `expandchar` to matching
   case (upper -> lower with +32, lower -> upper with -32).
3. Replace the extension: if it is a single `_` (or ends in `_`) replace that
   `_` with `expandchar`; if the extension is empty and the file name ends in
   '.', strip the trailing dot.
This restores filenames that `compress.exe` truncated by replacing the last
character with `_` (the original character is stored at header offset 9).
Globals: none (DBCS helpers read `NlsMbCodePageTag`).

### `lz_CopyFile` (line 3903)
```c
int lz_CopyFile(HFILE in, HFILE out, LZCTL *c)
{
    if (_llseek(in, 0, 0)) return -1;
    if (out != -2 && _llseek(out, 0, 0)) return -2;
    c->inend = c->inbuf + c->in_size + 1;   /* v8 */
    c->incur = c->inend;
    c->outcur = c->outbuf;                  /* = c->outbuf (field +16) */
    c->eof_flag = 0;
    c->outend = c->outbuf + c->out_size;
    c->out_count = 0;
    for (n = _lread(in, c->inbuf, c->in_size); ; n = _lread(in, c->inbuf, c->in_size)) {
        if (!n) break;
        if (n == (UINT)-1) return -1;
        w = _lwrite(out, c->inbuf, n);
        if (w != n) return (w == (UINT)-1) ? -4 : -2;
        c->out_count += w;
        if (n != c->in_size) break;
    }
    return 1;
}
```
Raw chunk copy; reuses the same control block fields. Globals: none.

### `ExpandOrCopyFile` (line 3949)
`int ExpandOrCopyFile(void *inHandle, DWORD outHandle, LZCTL *c)` (the `a2`
parameter is really the `HFILE` output handle stored via a FILETIME-shaped local):
1. Zero a local 14-byte header structure; call `GetHdr(&hdr, in, &c->filesize)`.
   If it fails and `c->filesize >= 14`, return -1.
2. `compressed = IsCompressed(&hdr)`.
3. If compressed: require header version byte 8 == 0x41 ('A') else **return -8**;
   `result = LZDecode(in, out, uncompressed_size - 1, garbage, garbage, c)`.
   Else: `result = lz_CopyFile(in, out, c)`.
4. If `result == 1`: flush via `WriteOutBuf('F', out, c)`; if that fails return
   its code; copy the input file's creation/access/write times to the output via
   `GetFileTime`/`SetFileTime` (failure -> -1). For compressed input, require
   `c->out_count == uncompressed_size`, else **return -3**. Return 1.
Globals: none directly (all state through `c`).

### `Expand` (line 4011)
`int Expand(int unused1, int unused2, LZCTL *c)`:
1. If `c == NULL` return -6.
2. `GetIOHandle(pszInFileName, 1, &hFile, &c->filesize)`; if != 1 return that code.
3. `GetHdr(&hdr, hFile, &c->filesize)`; if it fails and `filesize >= 14`, close and
   return -1.
4. If `pszOutFileName == NULL`, close and return -7.
5. `_strcpy_s(dest[260], 0x104, pszOutFileName)`; if `bDoRename == 1`, call
   `MakeExpandedName(dest, hdr.byte9)`.
6. `compressed = IsCompressed(&hdr)`; call `ProcessNotification(pszInFileName,
   dest, 2 - compressed)`; if it returns 0 -> abort (return 0).
7. `hOut = _lcreat(dest, 0)`; if -1, close input and return -2.
8. `result = ExpandOrCopyFile(hFile, hOut, c)`; close both handles; return result.
Globals read: `bDoRename` (`0x40CC38`), `pszOutFileName` (`0x40C408`),
`pszInFileName`; indirectly `bDoListFiles`, `nLocalFiles`, `nTotalFiles`,
`dword_40C388`, `hResInstance`, `ErrorMsg` through `ProcessNotification`.

### `IsCompressed` (line 4221)
Described in section 3. Reads global `String2` ("SZDD"). Returns BOOL.
Note `v4 = 0` at line 4229 is the NUL terminator of the local 9-byte string.

### `StringRevChar` (line 1317)
Returns a pointer to the **last** `\\` in the ANSI string (DBCS-aware iteration),
or NULL. Used by `ProcessNotification` to print just the file name. Globals: none
direct; `NlsMbCodePageTag` indirectly.

### `CharacterMatch` (line 1345)
ASCII case-insensitive equality: fold 'A'-'Z' to 'a'-'z' by adding 32, compare.
Globals: none.

### `PatternMatch` (line 1360)
DOS wildcard matcher (`*` = any sequence, `?` = one char) with case folding via
`CharacterMatch` and special handling of `.` / trailing-dot. `a3` is an
"allow short match" flag (initialized to 1 by callers, cleared after a wildcard
backtrack). Hex-Rays notes `v8`/`v9` as possibly undefined and mangles the
recursive call at line 1426 (conceptually `PatternMatch(a1, pattern, a3)`).
Globals: none.

### `PrintMessage` (line 1637)
`DWORD PrintMessage(LPCWSTR fmt_id, ...)`: the first argument is actually an
integer resource ID cast to a pointer (callers use `(LPCWSTR)0x1A` etc.):
```
 LoadStringW(hResInstance, (UINT)fmt_id, ErrorMsgW, 2048);
 _vswprintf_s(Buffer, 0x800, ErrorMsgW, ArgList);
 Block = NULL;
 cp = GetConsoleOutputCP();
 if (WideToCodePage(Buffer, cp, &Block) >= 0) n = _printf("%s", Block);
 if (Block) _free(Block);
 return n;
```
Globals read/written: `hResInstance`, `ErrorMsgW` (`0x40B388`).

### `DisplayErrorMessage` (line 883) — error-code -> message-ID map
```
 code   LoadStringA ID   printf arguments
 -----  ----------------  ----------------------------------------------
 -8     0x18 (24)         pszInFileName     (bad/unsupported LZ version)
 -3     0x17 (23)         pszInFileName     (size mismatch after LZ decode)
 -2     8                pszOutFileName    (cannot create/open output file)
 -4     9                pszOutFileName    (output write failure, _lwrite == -1)
 -1     6                pszInFileName     (input open/read/header failure)
 other  0x0B (11)         pszInFileName, pszOutFileName (generic expand failure)
 0      (none)            returns an uninitialized value; prints nothing
```
Every branch except `code == 0` does `CharToOemA(ErrorMsg, ErrorMsg)` first.
Globals used: `hResInstance`, `ErrorMsg`, `pszInFileName`, `pszOutFileName`.

### `ActuallyTheSameFile` / `ActuallyTheSameFileW` (lines 927/939)
`GetFullPathNameA/W` both names into 260-char buffers, then `lstrcmpiA/W` them;
TRUE iff they resolve to the same path. Globals: none.

### `SpdFdi*` wrappers (lines 1444-1497)
```
 SpdFdiAlloc(cb)            = LocalAlloc(0, cb)
 SpdFdiFree(pv)             = LocalFree(pv)
 SpdFdiOpen(name, oflag)    = _lopen(name, ((oflag & 1) ? 1 : (oflag & 2)) | 0x20)
                              /* 0x20 = OF_SHARE_DENY_WRITE */
 SpdFdiRead(hf,pv,cb)       = _lread(hf, pv, cb)
 SpdFdiWrite(hf,pv,cb)      = _lwrite(hf, pv, cb); if -1, calls GetLastError() (discarded)
 SpdFdiClose(hf)            = { _lclose(hf); return 0; }
 SpdFdiSeek(hf,dist,type)   = _llseek(hf, dist, type)
```
They are the FDI callback thunks for the CAB/DPX path; they touch no globals and
are not used by the classic LZ path.

--------------------------------------------------------------------------------
## 9. Complete `LoadStringA` resource-ID inventory (with inferred meaning)

| ID (dec) | Site(s) | Apparent message meaning |
|---|---|---|
| 1 | main 1133 | init failure: "Not enough memory / cannot initialize" |
| 2 | CheckArguments 807 | too many input files for one destination |
| 3 | ParseArguments 727 | unknown/invalid switch `%s` |
| 4 | CheckArguments 775 | usage / no file specified |
| 5 | CheckArguments 787 | single file, no rename/dir: "must specify destination" |
| 6 | DisplayErrorMessage -1 | cannot read/open input `%s` |
| 8 | DisplayErrorMessage -2 | cannot create/write output `%s` |
| 9 | DisplayErrorMessage -4 | output write error `%s` |
| 0x0A (10) | main 1109 | startup banner / version string |
| 0x0B (11) | DisplayErrorMessage (other) | generic "cannot expand %s to %s" |
| 0x0C (12) | ProcessNotification 974 | source and destination are the same file |
| 0x0D (13) | main 1241 | success/compression-ratio summary (`%s %s %d%%`) |
| 0x0F (15) | main 1280 | total-files/bytes summary |
| 0x10 (16) | main 1117 | full help text (`/?`) |
| 0x13 (19) | ParseArguments 667 | invalid DBCS switch byte |
| 0x14 (20) | ProcessNotification 983 | "Expanding %s to %s" |
| 0x15 (21) | ProcessNotification 988 | "Copying %s to %s" |
| 0x16 (22) | main 1235 | "Copied %s to %s" (copy-path summary) |
| 0x17 (23) | DisplayErrorMessage -3 | "uncompressed size mismatch / bad data" |
| 0x18 (24) | DisplayErrorMessage -8 | "invalid version of compressed file" |
| 0x19 (25) | CheckArguments 798 | conflict: list mode with directory target |
| 0x1A (26) | ProcessNotification 965 | list-only line "%s -> %s" |
| 0x1B (27) | main 1267 | "Total files: %d" |
| 0x1C (28) | main 1221 | "No files matching %s found in %s" |
| 0x1D (29) | main 1191 | multi-file cabinet needs rename/target |
| 0x1E (30) | main 1198 | "cabinet contains a single file" notice |

`PrintMessage` (LoadString**W**, IDs passed as the pointer argument) uses IDs
0x0C, 0x14, 0x15, 0x1A and 0x26 (38) from `ProcessDpxNotification`
(lines 1010-1033) for the Unicode/DPX equivalents.

--------------------------------------------------------------------------------
## 10. Return-code cross reference (important for reimplementation)

| Code | Produced by | Meaning |
|---|---|---|
| 1 | all drivers | success |
| 0 | ProcessNotification | user cancelled / listing-only: abort current file |
| -1 | GetIOHandle, GetHdr, Expand, ExpandOrCopyFile | generic input/header/time failure |
| -2 | GetIOHandle (create), lz_CopyFile/LZDecode (seek), WriteOutBuf (short write) | output file problem |
| -3 | GetHdr (short read), LZDecode (input read failure), ExpandOrCopyFile (size mismatch) |
| -4 | WriteOutBuf / lz_CopyFile (`_lwrite == -1`) | hard output write error |
| -5 | (not used in this path) |
| -6 | Expand | NULL control block |
| -7 | Expand | no output file name |
| -8 | ExpandOrCopyFile | header version byte != 'A' |
| 500 | ReadInBuf | soft EOF, treated as success by LZDecode |

