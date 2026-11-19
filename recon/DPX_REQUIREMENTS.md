# What full DPX support needs

Scope: make the standalone `expand_recon.exe` expand **CIX-manifest cabinets**
and **PSTREAM/PSF containers**, with PA19/PA30 deltas and LZMS/XPress
payloads. This is the part of `dpx.dll` that the current `recon/` build
does not implement.

## 1. The container families

| Family | How recognised | Current status |
|---|---|---|
| Plain MSCF cabinet | `"MSCF"` at offset 0 | Done (`recon/src/cab.c`, MSZIP + stored) |
| Cabinet + CIX manifest | `"MSCF"` plus a CFFILE named `_manifest_.cix.xml` (or `_sfx_manifest_`, which dpx rejects with `E_NOTIMPL`) | Manifest ignored, so payloads are written raw |
| PSTREAM / PSF | 8 bytes `"PSTREAM\0"` | Detected and rejected (`CabIsPsf`) |

Both advanced families use the **same CIX XML schema**. A CIX manifest
describes *targets* (output files) and *sources* (byte ranges), plus
hashes, deltas and bases.

## 2. The compression / delta layer stack

```
container framing          MSCF CAB             PSTREAM header + index
        |                     |                          |
manifest/index            _manifest_.cix.xml      index blob at +0x28/+0x2C
        |                     |                   (optionally PA19/PA30 compressed)
CIX target data           RAW offset range       RAW / PA19 / PA30 source range
        |                     |                          |
postprocess codec         algId 3/4/5            algId 3/4/5 (LZMS "postprocess")
                         (XPress/XPressHuff/LZMS) same
        |
delta apply               PA19 (mspatcha) / PA30 (msdelta -> mspatcha + LZX)
        |
hash verification         CRC32 / MD5 / SHA1 / SHA256 / SHA384 / SHA512
```

Important correction from the new references: PA30 does **not** have a
simple copy/add instruction stream. `msdelta.dll` wraps `mspatcha.dll`;
the patch body is an **LZX-compressed diff stream** plus a descriptor of
source ranges and "extra" literal blocks. So delta support implies an
LZX decoder.

## 3. Component checklist

| # | Component | Source reference | Est. C89 lines | Notes |
|---|---|---|---|---|
| 1 | PSTREAM header + index extraction | `dpx.dll.c` `GetPsfIndexFromBuffer` (5537), `ProvideContainerIndex` (3101) | 150–250 | 48-byte header; fields at +0x28 (index offset), +0x2C (length). Index may start with `PA30`/`PA19` magic. |
| 2 | Minimal UTF-8 XML parser + CIX model | `CixContainer::FromXml` (27832), `CixTarget` (28162), `CixSource` (28622), `CixDelta` (28382), `CixBasis` (28769), `CixHash` (28956); string pool `off_10057000` | 400–600 | Only ~20 element/attribute names needed: `Container`, `Files/File`, `Hash`, `Delta`, `Source`, `Basis`, `Aliases`, `Location`, `SearchOption`; attributes `name,type,version,length,offset,size,alg,algId,value,file,loc,id,time,attr,norm,normFlags,attempts,filter,targetName,aliasName`. |
| 3 | Hash verification | `DpxValidateHash` (21429) | 100 (CRC32) + 300–400 (SHA-256/MD5) | CRC32 alg=32; MD5 0x8003, SHA1 0x8004, SHA256 0x800C, SHA384 0x800D, SHA512 0x800E. Can defer the CryptoAPI algs initially. |
| 4 | XPRESS / XPRESS-HUFF decode | **`go-ntfs/parser/xpress.go`** (`XpressDecompress`, `XpressHuffmanDecompress`) + `xpress_test_data.go` (Apache-2.0); alternative: `ms-compress/` (GPLv3) | 600–900 | Go reference is the safer port: complete, documented, has 357 KB of test vectors. `ms-compress` has a convenient `ms_decompress()` C API but is GPLv3 and needs heavy VC98 shims (`stdint.h`, variadic macros, intrinsics). |
| 5 | LZMS decode | **`wimlib-1.14.5/src/lzms_decompress.c` + `lzms_common.c`** (LGPL-2.1+), with `lzms_constants.h`; fallback: decompiled `cabinet.dll.c` `LzmsDecompress` | ~900–1,200 after shims | Clean raw-block decompressor requiring the uncompressed size up front. Needs a compatibility header (u8/u16/u32/u64, bool, restrict, forceinline, strip SIMD/x86_64 blocks) and dpx's own chunk framing — **not** wimlib's WIM resource framing. |
| 6 | LZX decode (needed by deltas) | `mspatcha.dll.c` `LZX_Decode*`/`decode_data`; **`wimlib-1.14.5/src/lzx_decompress.c` + `lzx_common.c`** (LGPL-2.1+); root `CabLzx.cpp/.h` (C++) | 700–1,400 | wimlib's LZX is a clean C implementation; verify it handles the patch variant (E8 filter, window sizes) before relying on it. |
| 7 | PA19 / PA30 delta apply | `mspatcha.dll.c` `DecodePatchHeader` (804), `CreateNewFileBufferFromPatchData` (1245), `ApplyRawLzxPatchToBuffer` (2412); `msdelta.dll.c` `SplitPatchHeader` grammar (16357), `ApplyPayload` (16317) | 1,200–2,000 | PA30 header is a bit-packed stream (`BitReadInt`/`BitReadBuffer`), not a fixed C struct. PA19 descriptor has sections + extra ranges. Skip creation/normalization/PE-Rift paths. |
| 8 | CAB LZX/Quantum folders | root `CabLzx.cpp`, `CabQuantum.cpp` | 1,000–1,500 | Only needed for CIX cabinets whose `typeCompress` is 2 or 3. |
| 9 | Basis / sandbox resolution | `CJob::FetchSandboxFile`, `RetrieveSingleAsset`, `CixBasis`/`CixAlias`/`CixSearch` | 200–400 | Deltas need a previously extracted target or an asset as source; resolve by `file=` raw id / `loc=` search id. |
| 10 | Integration with `DpxExpandFile` | `recon/src/dpx.c` | 200–300 | Map CIX targets to `-F:` selection, list mode, progress messages, counters. |

**Native total: roughly 5,000–7,500 lines of C89.** With wimlib supplying
clean LZMS/LZX implementations and go-ntfs supplying XPRESS, no codec has
to be written from a decompilation. The remaining high-effort item is the
PA19/PA30 descriptor logic (#7), and the main correctness risk is making
all the codec contracts (chunk framing, up-front sizes, E8 filtering)
agree at their boundaries.

## 4. What the newly added files actually give us

* `mspatcha.dll.c/.lst` — the real patch engine: varint decoder, patch
  descriptor, LZX diff decoder, CRC32, extra-block copying. This is the
  primary reference for #6 and #7.
* `msdelta.dll.c/.lst` — the thin COM/compo wrapper: the PA30 outer header
  grammar (`SplitPatchHeader`) and `ApplyPayload` sequence. It delegates
  the actual patch application to `mspatcha.dll`, so do **not** look for
  the delta bit-flipping engine here.
* `go-ntfs/parser/xpress.go` — a compact, documented XPRESS + XPRESS-HUFF
  decoder with `xpress_test_data.go` (357 KB of vectors). Direct porting
  reference for #4.
* Root `CabDecode.cpp`, `CabLzx.cpp`, `CabQuantum.cpp` — existing C++ CAB
  codec implementations (LZX, Quantum) that can be translated to C89 for
  #8.
* `wimlib-1.14.5/` — clean C implementations of the two hardest codecs:
  `src/lzms_decompress.c` (raw LZMS block) and `src/lzx_decompress.c`
  (raw LZX block), plus the shared Huffman helpers in
  `decompress_common.c` / `compress_common.c`. Both expose the same simple
  contract: `decompress(in, in_len, out, out_len, private)`, with
  `out_len` required up front. They do **not** parse containers; dpx's
  `DecompressData` chunk framing (magic `0x01584344`, 16-byte headers of
  `[compSize, _, rawSize, _]`) must be implemented separately. MSVC6
  porting needs a shim header for fixed-width types, `bool`, `restrict`,
  `forceinline`, `STATIC_ASSERT`, `likely/unlikely`, aligned malloc, and
  removal of the x86_64/SSE/AVX branches. Roughly 2,300–2,700 C89 lines
  for LZMS + LZX after stripping.
* `ms-compress/` — C++98 template implementation with a convenient
  `extern "C"` one-shot API `ms_decompress(format, in, in_len, out,
  &out_len)` for LZNT1 (2), XPRESS (3) and XPRESS-HUFF (4). No C++11
  constructs, but VC98 lacks `stdint.h`, variadic macros, several
  intrinsics and `__restrict`, and the supplied build targets MinGW-w64 /
  VS2015+. It is also **GPLv3**, so linking it would make the whole EXE
  GPLv3. Preferred route remains the Apache-2.0 go-ntfs Go reference.

### Licensing summary
| Source | Licence | Consequence |
|---|---|---|
| `go-ntfs/parser/xpress*.go` | Apache-2.0 | Safe to port into the EXE with attribution |
| `wimlib` codec files | LGPL-2.1+ (shared helpers MIT) | Keep notices; dynamic or static linking with notice/relinking rights |
| `ms-compress` | GPLv3 | Whole EXE becomes GPLv3 if linked |
| Decompiled `dpx.dll`/`mspatcha.dll`/`msdelta.dll`/`cabinet.dll` | Microsoft proprietary | Use **as behavioural specification only**, not as source to copy |

## 5. Test material — what is missing

There are **no PSF/PSTREAM or CIX sample files** anywhere in the workspace.
Before or alongside implementation you need:

1. **Synthetic PSF**: trivial to hand-build — 48-byte header with
   `"PSTREAM\0"`, index offset/length, a UTF-8 `<Container>` XML with one
   RAW `<Source offset=… length=…>`, then raw bytes. Exercises #1–#3.
2. **PA30 vectors**: done — `gen_delta.c` + `testdata/delta/`. mspatcha
   has no public patch-creation API, so PA19 still has no test vector.
3. **LZMS/XPress vectors**: `CreateCompressor(5)` / `CreateCompressor(4)`
   from `cabinet.dll`; XPress additionally has go-ntfs's test data.
4. **Real CIX cabinet / PSF**: ideally one Windows Update `.msu` or
   compressed CAB with `_manifest_.cix.xml`, to validate the full pipeline.

## 6. Recommended phasing

1. **Phase A — DONE.** `recon/src/{xml,cix,psf,hash}.c` implement the PSF
   reader, CIX XML parser, RAW target extraction, CRC32 verification and
   nested output directories. Verified with `testdata/psf/sample.psf`:
   `-D` lists both targets, `-F:*` extracts both with correct contents and
   CRC32 checks, and the original 15-case regression still passes.
2. **Phase B — DONE.** `recon/src/xpress.c` is a C89 port of both MS-XCA
   decoders from go-ntfs (Apache-2.0). All 40 bundled vectors pass via
   `recon/test_xpress.bat`. CIX `algId` 3 and 4 are wired into PSF target
   extraction and verified with `testdata/psf/xpress_00.psf` /
   `xpress_39.psf`.
3. **Phase C — PA30 DONE.** `recon/src/delta.c` now contains a working
   C89 port of the compo decompressor: `IntFormat` (252-symbol static
   Huffman int codec), `RiftTable` reader, `CompositeFormat` header,
   `CompressionLengths::Read`, `CompressionFormat::ReadSymbol` and the
   `Decompress` loop with repeat distances. Both real `CreateDeltaB`
   vectors decode byte-identically (`test_delta.bat`), and a PSF with a
   PA30 delta target extracts correctly (`testdata/psf/delta.psf`).
   `recon/src/lzx.c` is a validated C89 LZX port
   (4/4 synthetic vectors) with a seeded-window API for delta sources.
   `recon/src/delta.c` implements PA30 outer-header parsing and payload
   blob extraction (validated against real `CreateDeltaB`-generated
   vectors) plus a spec-based PA19 applier. **Still missing:** PA30's
   compo patch-stream decoder. A first layer is now implemented and
   validated on real vectors: `IntFormat` (252-symbol static Huffman int
   codec), `RiftTable` reading, and `CompositeFormat` header parsing — both
   vectors use an empty rift table and the default composite format. The
   remaining work (CompressionLengths::Read, CompressionFormat::ReadSymbol,
   OffsetRiftTable and the Decompress loop) is mapped in **COMPO_SPEC.md**.
   PA19 now has **real test vectors**: `IE6.0SP1-KB2722913-...EXE` contains
   an embedded LZX CAB with `*.dll._p` PA19 patches; `extrac32.exe` extracts
   them, and `apply_pa19.c` uses `mspatcha.dll` as an oracle. The PA19 header
   parser was corrected against these patches (flags bits 23/18/22, no
   reserved word in section records, range accumulators include lengths) and
   now reports the exact target size (2723840 for mshtml.dll). Full apply is
   still blocked: mspatcha's patch LZX uses windows up to 2^22/2^23, larger
   than `lzx.c`'s supported 2^15..2^21, and my LZX port fails on real CAB
   patch data even where the window is small. `src/lzxdec.c` **was fixed**:
   uncompressed LZX blocks were reading raw bytes via the 16-bit bit reader,
   swapping every adjacent pair; a new `lzxGetRawByte()` reads them in stream
   order. It is now wired into recon via `src/lzx_adapter.c` behind `lzx.h`,
   and a `makecab` LZX CAB extracts byte-identically. The decoder was also
   extended to windows up to 2^25 (290 slots, 17 extra bits for slots ≥36)
   to cover mspatcha's large-window patches. However mspatcha's patch LZX
   is a distinct variant: its `ReadRepTree` offset-length pass fails in
   `lzxdec.c` even on a small single-chunk patch. It needs a dedicated port
   of mspatcha's LZX was started in `recon/src/mslzx.c` (per-group E8 header,
   24-bit block sizes, modulo-17 length pre-tree, long-match extension,
   slot-3 distance-1, 290-slot bases, circular-window seed). It decodes real
   `jsproxy.dll._p` output to within 26 / 12288 bytes when seeded with 13383
   bytes, but the default group seed length (12288 from `min(srcLen, window)`)
   is wrong for mspatcha and the last few bytes still differ — PA19 apply is
   therefore **not byte-exact yet**. The likely cause is that mspatcha's
   basis buffer is larger than the file (the 1095-byte delta between the file
   size and the first match offset) and/or a residual detail in the long-match
   or E8 stage. The dedicated decoder is in place; finishing it needs that
   last seed/framing detail.

   Extended tracing (patch `jsproxy.dll._p`): the LZX stream itself decodes
   correctly — first item is mainsym 479 / slot 27 / offset 13383 / length 257,
   and exhaustive scans confirmed lensym=248, seed=13383 and windowBits=17 are
   each uniquely optimal (all alternatives give ~10,700 wrong bytes). E8
   translation is not the cause (disabling it leaves the same 26 bytes).
   The oracle output was regenerated and verified; flipping a source byte
   makes mspatcha fail its CRC, confirming the source is genuinely used.

   The 26 differing bytes split into two groups:
   - 14 positions where the source differs from the expected output (genuine
     patch-introduced bytes); our decoder copies the source bytes there.
   - 12 positions where our decoder emits *literals* whose values exactly
     match the expected changed bytes, but at positions shifted ~71 bytes
     earlier than expected (e.g. our 0x17 0x8D at 257 belongs at 328; our
     0x6C 0xF3 at 1133 belongs at 248).

   This points to a residual match/literal interleave or seed-window offset
   issue in `mslzx.c`, not to block framing, Huffman tables, distance decoding
   or post-processing. Resolving it likely requires tracing mspatcha's
   internal `decode_data` match copy under a debugger, or porting a full
   libmspack `lzxd` variant for comparison.
4. **Phase D — DONE.** `recon/src/lzms.c` is a C89 port of wimlib's raw
   LZMS decoder (range coder, adaptive Huffman, LZ/delta matches, x86
   filter). dpx chunk framing (`0x01584344`, 16-byte chunk headers) and a
   verbatim fallback for incompressible blocks are implemented. `algId` 5
   is wired into PSF extraction. All 6 OS-generated vectors pass via
   `recon/test_lzms.bat`; `testdata/psf/lzms.psf` verifies end-to-end.
   `recon/ref_lzms/` is an independently built wimlib oracle that was used
   to isolate two porting bugs (initial probability bits and `gen_codewords`).
5. **Phase E** — CAB LZX/Quantum folders (wimlib LZX / root `CabLzx.cpp`,
   `CabQuantum.cpp`) and basis/sandbox resolution; wire into
   `DpxExpandFile`.

Phases A–B are straightforward and testable with the material at hand.
Phase C is substantial but well-documented by the new decompilations.
Phase D is the genuine open-ended piece.

    **Resolution (byte-exact):** the real expand.exe delegates PA19
    application to mspatcha.dll, so Pa19Apply() now first calls
    ApplyPatchToFileByBuffers from the OS DLL and uses that result. The
    in-tree mslzx.c decoder remains as a fallback for systems without
    mspatcha.dll (set PA19_NO_OS=1 to force it). jsproxy.dll._p and a
    controlled single-byte-change patch both now decode with 0 / 12288
    wrong bytes. Wine's wine-mspatcha/lzxd_dec.c narrows the native gap
    to 2 bytes, and mspatchc.dll reproduces the original patch byte-for-byte
    from jsproxy.dll + jsproxy_expected.dll, proving the stream is genuine.

    **Native decoder also byte-exact (follow-up):** two real bugs were found
    in mslzx.c with Wine's wine-mspatcha/lzxd_dec.c as a trace oracle:
    (1) mspatcha reads the distance extra bits BEFORE the long-match length
    extension; mslzx.c did the reverse, shifting the bitstream so a 12-bit
    distance value of 2 was read as 1095 and a 9-bit length of 71 as 0.
    (2) mspatcha writes the patch header's new COFF timestamp into the
    source PE TimeDateStamp field before LZXD decoding; Pa19Apply() now
    mirrors that normalization. The in-tree decoder now produces 0 / 12288
    wrong bytes on jsproxy.dll._p even with PA19_NO_OS=1.

    **Hotfix-wide check (17 PA19 patches in
    IE6.0SP1-KB2722913-WINDOWS2000-X86-CHT.EXE):** all 17 apply with
    0 mismatching bytes through the OS mspatcha.dll delegation path.
    The native mslzx.c path is byte-exact for jsproxy.dll._p and for the
    five streamless (retain-only) patches, but multi-chunk LZXD streams
    (large patches whose blocks span many chunk headers) still mis-decode;
    a partial chunk-aware decoder was added but does not yet reproduce
    mspatcha's window/distance mapping for those files. The OS path is the
    supported default and is what the original expand.exe uses.

    **Multi-chunk follow-up (second commit):** native decoding of large
    patches improved substantially after two more fixes: (1) the LZXD
    window size must be derived before the default group seed length,
    otherwise large files were seeded with only 32768 bytes; (2) E8 x86
    translation must be gated on the E8 header flag, not merely on the
    presence of an 0xE8 literal code. `danim.dll._p` went from 927187 to
    44446 wrong bytes. A chunk-aware decoder was added. Remaining native
    mismatches are in large ALIGNED-block patches and are still under
    investigation; the OS delegation path remains byte-exact for all 17
    hotfix patches.

    **Private source reference:** a local (untracked) patch-engine LZX
    source tree was compiled directly as an oracle (with EXTRALONGMATCHES).
    It decodes danim.dll._p end-to-end but still differs from the newer
    mspatcha.dll output by 26837 / 1054208 bytes (vs 44446 for the in-tree
    decoder). Both old and new decoders miss the same genuine patch literals
    (e.g. source 0x90 -> expected 0xCA at offset 0xE8), so the remaining gap
    is a decoder-version difference not captured by either available source
    tree. OS delegation remains the byte-exact path.

    **Aligned-match trace against bundled DLL:** compiled the reference LZX
    decoder with TRACING and applied the same PE timestamp normalization as
    Pa19Apply. It agrees with the in-tree decoder through the first chunk
    and both first differ from the DLLs at output 0xB6D. NT trace:
    MATCH At 0xB6D From source[0xB55], Length 11 (distance 1054232),
    whereas the DLL output requires source[0xB6D] (distance 1054208).
    The difference is exactly 24 = 3 << 3, i.e. the 14-bit aligned extra
    field reads 707 in both source-derived decoders but must be 704 for
    the DLL. Tables (dec_extra_bits, MP_POS_minus2, aligned code lengths
    2,5,2,5,3,5,2,5) and bit order all match; reading the aligned symbol
    first is wrong. Both DLLs (bundled _sfx_.dll and system mspatcha.dll)
    produce byte-identical output, so the oracle is not in question.
    The remaining fault is a newer-era aligned-offset convention absent
    from both the reference source and the DLL decompilations.
