# PA19 and PA30 patch formats

This document describes the two Microsoft binary delta/patch containers that
`expand` understands. Both start with a 4-byte ASCII magic and both use
little-endian fixed-width fields. Where a format is bit-packed, bits are read
**least-significant-bit first inside each byte**.

| Magic | Format | Producer | Contents |
|-------|--------|----------|----------|
| `PA19` | legacy `mspatcha` patch | `mspatchc` / `MakeCab` era | LZXD-compressed sections |
| `PA30` | `msdelta` "compo" delta | `msdelta` | compo LZ stream + RIFT table |

The reference implementation is `recon/src/delta.c` (`Pa19Apply` and the
`DeltaApply` PA30 path). `recon/COMPO_SPEC.md` holds additional compo research
notes.

## Conventions

### Fixed-width integers

All multi-byte fixed fields are little-endian: `u8`, `u16`, `u32`.

### Variable-length integers (`uvar`, `svar`)

Used by the PA19 header only. These are **not** LEB128: a **clear** bit 7 means
"another byte follows"; a **set** bit 7 terminates the value.

```
uvar:  byte0 = bits 0..6 data            (7 bits)
       byteN = bits 0..6 data            (7 bits, N > 0)
       high bit 1 = last byte
       value = sum(data_i << (7*i))

svar:  byte0 = bits 0..5 magnitude       (6 bits)
       bit 6  = sign (1 = negative)
       bit 7  = 1 = last byte
       byteN  = bits 0..6 data            (7 bits)
       value = sign ? -magnitude : magnitude
```

Sign is sign-magnitude, not two's complement.

### Bit reader

The bit reader is a 32-bit sliding window over the byte stream, filled from the
LSB end. `br_init` begins at bit offset 3, skipping a **3-bit zero leader** at
the start of each bit-packed region. Reading past the end yields zero bits.

### Canonical Huffman

PA19/LZXD codes and the PA30 compo codes are canonical Huffman codes. The
compo `IntFormat` consumes its code bits MSB-first from the window; the LZXD
and compo length/distance codes are consumed LSB-first.

---

# PA19

A PA19 patch stores one or more independently decodable *sections*. Each
section carries a chunked LZXD stream plus the metadata needed to rebuild the
decoder's 32 KiB history window from the old file.

## Header

```
offset  field
0       "PA19"
4       flags1_raw (u32); flags1 = flags1_raw XOR 0x00800000
8       [extendedFlags (u32)]           if flags1 & 0x80000000
        [newFileTime  (u32)]            if !(flags1 & 0x00800000)
        [newFileCoffBase (u16 << 16)]   if !(flags1 & 0x00040000)
        [coffTimeDelta (svar)]          (same condition)
        [resourceHint  (svar)]          if !(flags1 & 0x00400000)
        newFileSize (uvar)
        newFileCrc  (u32)
        [windowBits (u8)]               if extendedFlags & 0x00010000
        sectionCount (u8)               (1..16)
        sections...
```

Notes:

* `flags1` is stored with bit `0x00800000` inverted, so the decoder XORs the
  raw word before testing flags.
* `newFileTime` is the target COFF timestamp when present.
* `newFileCoffBase` is stored as only the high 16 bits of the preferred image
  base; the low 16 bits are zero.
* `coffTimeDelta` is a signed difference between the header timestamp and the
  target COFF time; the effective target COFF time is
  `newFileTime - coffTimeDelta`.
* `resourceHint` is the target resource-section timestamp hint.
* `windowBits` is explicit only when the extended-flag bit is set; otherwise it
  is derived from the old and new sizes (below).

### Derived window size

`windowBits` is chosen so that the LZXD window can hold the new size plus the
old size rounded up to 32 KiB:

```
need    = newFileSize + ((oldSize + 0x7FFF) & ~0x7FFF)
maxWin  = (flags1 & 0x4) ? 0x2000000 : 0x800000
w       = maxWin; while ((w >> 1) >= need) w >>= 1
if (w < 0x20000) w = 0x20000
bits    = smallest b with (1 << b) >= w
windowBits = max(bits, 15)
```

## Section record

Sections are stored back-to-back in the header, and their compressed payloads
are stored back-to-back after the header in the same order.

```
sourceOffsetDelta (svar)   sourceOffset = newFileSize + sourceOffsetDelta
targetCrc         (u32)
ignoreCount       (u8)     (<= 16)
    offsetDelta (svar), length (uvar)      repeated ignoreCount times
retainCount       (u8)     (<= 16)
    offDelta (svar), offNewDelta (svar), length (uvar)
riftCount         (uvar)
    deltaPos (uvar), deltaNew (svar)       repeated riftCount times
[groups]                                 if flags1 & 0x40000000
    groupCount (uvar)                    (<= 16)
    3 * groupCount svars
compressedLength  (uvar)
```

### Ignore and retain ranges

`ignore` and `retain` describe byte ranges of the old file that must be copied
verbatim rather than fed to the transform. Ranges are delta-coded against a
running accumulator that advances by `delta + length` for each range.

`retain` additionally records the destination offset as
`offNew = off + offNewDelta`.

### RIFT map

The RIFT (relocation/fixup) map records corresponding `(oldRva, newRva)`
positions. Both coordinates are delta-coded against running accumulators that
persist across entries:

```
prevOld = 0; prevNew = 0
for each entry:
    prevOld += deltaPos
    prevNew += deltaNew
    entry = { oldRva = prevOld, newRva = prevNew }
```

For PA19 the map is used to drive the PE transform of the seed image (see
*Seed image*). For PA30 the same table is used directly as a copy source
during decompression.

### Output groups

When `flags1 & 0x40000000` is set, the section carries an explicit group table
of triples. Each triple is decoded with three running accumulators:

```
a = 0; b = 0; c = 0; d = 0
for each group:
    a += svar; groups[3*i + 0] = a          # output start
    b += svar; c += b; groups[3*i + 1] = c  # source window offset
    d += svar << 15; groups[3*i + 2] = d    # output length
last group length = newFileSize - last group's output start
```

When the bit is clear there is a single implicit group:

```
{ 0, min(oldSize, 1 << windowBits), newFileSize }
```

## Compressed payload

For each section, the next `compressedLength` bytes after the header are a
sequence of chunks:

```
u16 chunkSize
u8  chunkPayload[chunkSize]
...
```

Chunks are consumed until `compressedLength` bytes have been used. Each chunk
is an LZXD block that produces **at most 32768 output bytes**; the section's
total output is spread across consecutive chunks.

LZXD details specific to PA19:

* The bit cache is re-initialised at the start of **every chunk** (the decoder
  reads 4 bytes and sets the 16-bit counter), so no bits carry over between
  chunks.
* The main tree, length tree and the three LRU repeat offsets persist across
  chunk boundaries; only the bit-buffer state resets.
* `EXTRALONGMATCHES` is enabled: a match length of exactly 257 is followed by
  an extra 9-bit code, which may itself be extended (nested 9/6/3-bit
  continuations), producing lengths beyond the normal 257 maximum.
* Decoding starts from a pre-filled history window (below), not from zeros.

A section with `compressedLength == 0` is a *header-only* section: its output
is simply the normalised seed image truncated to the section's output length.

## Seed image

The LZXD stream repeatedly references the old file through the 32 KiB history
window. The encoder built the patch against a **transformed copy** of the old
file, so the decoder must reconstruct exactly that copy before decoding.

The transform is driven by the section metadata and header flags:

1. Copy the old file.
2. Normalise the PE headers: clear or replace the COFF timestamp and the PE
   checksum, and apply the rebase implied by `newFileCoffBase`, unless the
   corresponding `NO_TIMESTAMP` / `NO_REBASE` / `NO_RESTIMEFIX` bits disable
   it.
3. Apply the RIFT map: relocate absolute addresses, then fix relative branches
   (`E8`/`E9` JMP/CALL displacements) and import/export tables.
4. Rewrite the resource section timestamp hint when enabled.

The `ExtendedOptionFlags` word can individually suppress relocation, import,
export, relative-JMP, relative-CALL and resource rewriting
(`PATCH_TRANSFORM_NO_*` bits `0x01`..`0x20`). Two generation-selector bits
(observed value `0x300`) choose the transform variant.

The decoder then seeds each section's LZXD window with
`seedImage + group.sourceOffset`, `group.sourceWindowLength` bytes.

## Checksums

`newFileCrc` and each section `targetCrc` are stored but are not required for
decoding; they are verification values.

---

# PA30

PA30 is the `msdelta` container. Its header is bit-packed; its payload is a
"compo" stream with its own integer codec and Huffman-compressed LZ data.

## Container header

```
offset  field
0       "PA30"
4       FILETIME (8 bytes, not needed by the decoder)
12      bitstream, 3-bit zero leader skipped:
            version    = read_int()
            code       = read_int()   1 = raw, 2/4/8 = PE machine type
            flags      = read_int()
            targetSize = read_int()
            hashAlg    = read_int()
            hash       = read_blob()
        payload...
```

`read_blob()` reads an `read_int()` length, **byte-aligns the reader**, then
consumes that many raw bytes. The payload starts at the first byte after the
hash blob.

### `read_int()` (compo nibble-granularity integer)

```
n = number of leading 0 bits before the terminating 1 bit
consume the 1 bit
if n < 8:  value = read_bits(4*n + 4)
else:      value = read_bits(32); discard read_bits(4*n - 28)
```

`n` is capped at 15; a longer run yields `0xFFFFFFFF` (error).

## Payload

```
preBlob   = read_blob()      # pre-image; loaded but unused by the apply path
patchBlob = read_blob()      # the actual compo stream
```

The payload reader starts at bit offset 0 (the 3-bit leader was already
consumed by the header reader), and it is byte-aligned when it starts because
the preceding `read_blob` aligned it.

## Patch blob

`patchBlob` is a fresh bitstream (3-bit zero leader skipped) with three parts:

### 1. RIFT table

```
empty = read_bits(1)
if empty == 0: table is empty
else:
    formatLeft = IntFormat()
    formatRift = IntFormat()
    n = read_int()
    left = 0; rift = 0
    for i in 0..n-1:
        left += if_read_number(formatLeft)
        rift += if_read_number(formatRift)
        entry[i] = (left, left + rift)
    sort entries by left
```

Both accumulators persist across entries. Each entry maps a target interval
`[left, left+rift)` to the corresponding bytes of the old file.

### 2. CompositeFormat

```
isDefault = read_bits(1)
if isDefault == 1:
    one segment, boundary 0, all code lengths zero
else:
    nSeg = read_int()
    boundaries = cumulative read_int() deltas
    for i in 0..38: metaLen[i] = read_bits(4)
    build a 39-symbol canonical Huffman code from metaLen
    for each segment: read its 872 code lengths with the meta-Huffman
                      run-length scheme
```

Segments select which compression format applies to each output position.

### 3. Compressed data

The remaining bits are the compo symbol stream. Decoding writes exactly
`targetSize` bytes:

* `symbol < 0x100` - literal byte.
* `symbol == 0x54000` - RIFT match: translate the current target position
  through the RIFT table and copy from the old file, bounded by the interval.
* `symbol in 0x54001..0x54003` - repeat one of the last three distances.
* otherwise - LZ match at distance `symbol - 0x54003`, with overlap allowed.

`CompressionFormat::ReadSymbol` uses a main Huffman table over 0x258 symbols;
for a match symbol, `k = (symbol - 256) >> 3` and the low 3 bits select the
length table. `k < 3` gives a raw 14/16/18-bit distance with wrap; `k >= 3`
uses a secondary Huffman length code.

## IntFormat

The compo integer codec is a 252-symbol canonical Huffman code with a compact
description:

```
n1  = read_bits(8)
n2  = read_bits(8)
run = read_bits(8)
len[0..n1-1]          = read_bits(4) + 1     # "small" symbols
base                  = read_bits(4) + 1
len[126..126+n2-1]    = read_bits(4) + 1     # "large" (negative) symbols
fill len[n1..125]  with base, decrementing base every `run` symbols
fill len[126+n2..251] with base, decrementing base every `run` symbols
```

Decoding a number:

```
s = decode_symbol()
consume len[s] bits
neg = (s >= 126)
if neg: s -= 126
if s >= 4:
    extra = (s >> 1) - 1
    v = (((s & 1) + 2) << extra) | read_bits(extra)
else:
    v = s
return neg ? ~v : v
```

Note that the Huffman code bits themselves are consumed **MSB-first**, unlike
the LSB-first bit reader used everywhere else.

---

# Implementation status

* PA19 apply is implemented natively and validated byte-exact against the
  system `mspatcha.dll` across the IE6 patch corpus, including the PE seed
  transform (`recon/src/pefix.c`) and the LZXD decoder
  (`recon/src/mslzx.c`). PA19 application still prefers `mspatcha.dll` when
  present and falls back to the native path (force it with `PA19_NO_OS=1`).
* PA30 header parsing, the `IntFormat`, the RIFT table, the CompositeFormat
  header and the compo decompressor are implemented in `recon/src/delta.c`.
* CAB folders of types 0, 1 and 3 (LZX) are decoded natively by
  `recon/src/cab.c`; an LZX folder's CFDATA payloads are concatenated into
  one continuous stream before decoding, because the Huffman trees, repeat
  offsets and E8 translation persist across block boundaries.

---

# Windows Update SFX container

Older Windows Update hotfixes are self-extracting packages: a PE stub followed
by an ordinary CAB. The stub is `_sfx_.dll` (bundled inside the CAB), and the
CAB also carries a plain-text `_sfx_manifest_`. Detection can therefore key on
either marker.

```
PE stub (MZ/PE)
embedded CAB ("MSCF" at a nonzero offset)
    _sfx_manifest_
    _sfx_.dll
    <old files>        e.g. rtmgdr\*.dll
    <PA19 patches>     e.g. *.dll._p
    update\...         installer files
```

The manifest is an INI-style file:

```
[Options]
Run = "update\update.exe"
PatchDll = "_sfx_.dll"

[Deltas]
"RTMQFE\danim.dll" = "danim.dll._p", "RTMGDR\danim.dll"

[Verify]
"RTMQFE\danim.dll" = <32 hex digits, MD5>

[Copy]
"update\iecustom.dll" = "iecustom.dll"

[Delete]
"*._p"
"_sfx_.dll"
```

Each `[Deltas]` line gives the output path, the patch path and the old-file
path; applying the patch (PA19 or PA30) to the old file produces the output.
`[Copy]` lines copy a CAB entry to another path, `[Verify]` holds MD5 hashes,
and `[Delete]` lists files the stub removes after installing.

`expand_recon.exe` detects this container, carves the CAB to a temporary file,
extracts it (including LZX folders), applies every manifest delta with
`DeltaApply()` and honours `[Copy]`, writing patched binaries directly. `-F:`
selection applies to both CAB entries and delta targets; a selected delta
target pulls in its patch and source automatically.

---

# Implementation status (continued)

* SFX handling lives in `recon/src/sfx.c` and is wired into `recon/src/expand.c`.
  On the IE6 SP1 KB2722913 hotfix it produces all 18 patched binaries
  byte-identically to the SFX-generated `RTMQFE` outputs, both with OS
  delegation and with `PA19_NO_OS=1`.
* MSU handling lives in `recon/src/dpx.c` (nested cabinets) and
  `recon/src/cixapply.c` (CIX targets). On
  `windows8.1-kb2959977-x86_5ccf...msu` it extracts the outer CAB, the
  nested payload CAB, and all 513 CIX targets — every target matches its
  manifest SHA256 and declared length.

---

# MSU (Microsoft Update Standalone Package) layout

An `.msu` is itself an ordinary CAB (possibly with `flags = 0x0004`
reserved header fields). Its entries include `WSUSSCAN.cab`, a payload CAB,
and XML metadata. The payload CAB is LZX-compressed and carries a
`_manifest_.cix.xml` plus numbered delta blobs.

```
MSU (CAB)
  WSUSSCAN.cab
  <kb>-<arch>.cab                 # nested payload CAB (often LZX:21)
  <kb>-pkgProperties.txt
  <kb>.xml

nested payload CAB
  _manifest_.cix.xml              # CIX index
  0, 1, 2, ...                    # PA30 delta blobs
  <raw payload files>
```

The CIX manifest is a namespaced XML document (`xmlns="urn:ContainerIndex"`)
with this shape:

```xml
<Container name="..." type="CAB" length="..." version="1">
  <Files>
    <File id="27" name="..." length="11132" ...>
      <Delta>
        <Source type="RAW" name="..."/>
      </Delta>
    </File>
    <File id="158" name="...\wuauclt.exe" length="49544" ...>
      <Delta>
        <Source type="PA30" name="0"/>
        <Basis file="27"/>
      </Delta>
    </File>
  </Files>
</Container>
```

`Source type="RAW"` means the bytes come directly from the named CAB entry.
`Source type="PA30"` means the named CAB entry holds a PA30 delta; the
`Basis` element names the CIX `id` of the source file. Bases may themselves
be PA30 outputs, so targets form chains and must be resolved in dependency
order. `expand_recon.exe` extracts the nested CAB into a directory named
after it and resolves the CIX targets there.
