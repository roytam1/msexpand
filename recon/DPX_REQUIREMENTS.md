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

    **2026-11-19 follow-up — isolated the exact stream state.** Built a
    standalone harness around `wine-mspatcha/lzxd_dec.c` (shims under
    `diag/shim/`, `diag/wine_probe.c`) and added guarded tracing to mslzx.c
    (both since reverted in the core sources; the harnesses remain in
    `diag/`). With PA19_NO_OS=1 the native decoder is exact on
    `jsproxy.dll._p` (0/12288) and first diverges on `danim.dll._p` at
    output 2925 (0xB6D) — exactly the NT-trace location:

        PRE pos=2925 slot=42 ebits=14 bitsleft=24 bitbuf=0B0D7700
        M   2925 blk=2 sym=599 slot=42 ebits=14 extra=707 alsym=2
                  len=11 off=1054232        (oracle needs 1054208)

    The whole patch is a single ALIGNED block (type 2, size 1054208) split
    into 29+ LZXD chunks of ~0x8000 output bytes each; the first mismatch is
    in chunk 0, so it is not a chunk-boundary problem. Oracle/source bytes
    confirm the DLL copies source[2925] (distance == seed length ==
    old-file-size 1054208, a retained-range-style identity copy), while we
    copy source[2901].

    Verified from `mspatcha.dll.lst` that the DLL's tables are identical to
    ours: `dec_extra_bits[42]=17` (table at 0x401F18DC onwards, `0x11` from
    slot 33), `MP_POS_minus2[42]=0xFFFFE=1048574` (table at 0x401F7560),
    aligned code lengths (2,5,2,5,3,5,2,5). The aligned decode assembly at
    `401F721D..401F72E3` reads `bitbuf >> (35-17)` = 14 extra bits and then
    adds the Huffman-decoded aligned symbol — the same formula mslzx.c uses.
    No retain/ignore ranges exist in this patch (extraCount=732 is parsed but
    not the cause). Other slot-42 matches in the same stream read extra=704
    (bitbuf `0x0B01...`) and decode correctly, so the stream genuinely holds
    `0x0B0D...`/707 at this point and the DLL still yields 704.

    Tested (via an `MSLZX_ALIGN_VARIANT` switch, since reverted): clearing
    the low 2 bits of the 14-bit extra gives 29823/1054208 (down from
    44446) but breaks earlier slot-14 matches; clearing low 3 bits gives
    29047; clamping any distance > seedLen to seedLen gives 20786. None is
    byte-exact, so the true convention is still unresolved. The authoritative
    OS-delegation path is covered by `test_pa19.bat` (0 mismatches on both
    jsproxy and danim).

    `diag/` also contains `wine_probe.c`/`build_diag.bat` (standalone Wine
    LZXD oracle — note it is itself only approx. 26837/1054208 correct on
    danim, so the OS DLL output remains the only trusted oracle) and
    `dumpbytes.c` for byte-range dumps.

    **2026-11-19, part 2 — the aligned-extra lead was a red herring; the real
    bug is in the Huffman reader.** Re-located the exact patch byte for the
    2925 match (dataOff=2282, chunk 0 at +2, chunkoff=682 → byte 2965 holds
    the low 6 bits of the 14-bit extra). Flipping it 0x0D→0x01 (extra 707→
    704, aligned-sym bits unchanged) made the OS DLL reject the patch, so
    the stream really does contain 707 there. No aligned-distance convention
    change can be correct in isolation.

    The productive experiment was `diag/mslzx_hybrid.c` (built by
    `diag/build_hybrid.bat`): replace the wimlib subtable decoder for the
    MAIN (and LEN) code with a single full 16-bit canonical table and,
    crucially, drop `bitstream_ensure_bits(max_codeword_len)` from the symbol
    read, as the DLL's decompiled `decode_aligned_or_verbatim_block` peeks
    directly from its 32-bit bit cache. Result on `danim.dll._p`:

        baseline (wimlib subtables + ensure(16)) : 44446 / 1054208 wrong
        full main table, no pre-load             :    89 / 1054208 wrong
        full len table alone (main unchanged)    : 916712 / 1054208 wrong

    so the MAIN symbol decode is the critical path; the same change makes
    `jsproxy.dll._p` go from 0 to 12 wrong bytes. A Wine-style 32-live-bit
    reader made no further difference (90 wrong), and changing table_bits
    to the DLL's 10/8 made none either. With `MSLZX_HYBRID=2` (full main
    only) the 12 jsproxy errors persist.

    Crucially, 90 of the 91 remaining danim errors are at offsets where the
    oracle differs from the source (genuine patch-introduced bytes), while
    the subtable decoder happens to reproduce those but gets ~44k other
    bytes wrong. So the two decoders are complementary, not one strictly
    better: each resolves a different subset of the symbol stream. A true
    byte-exact native fix needs to explain why the two main-code decoders
    disagree at those specific symbols — likely a bit-drift at the exact
    Huffman codeword boundary that the full table absorbs differently.

    Because the full-table change regresses the byte-exact jsproxy case, it
    was NOT merged into `src/mslzx.c`. The authoritative OS path remains
    byte-exact (verified by `test_pa19.bat`). Next concrete step: use the
    hybrid build to dump the main-code lens array and the exact (len,code)
    pair at output 313 / 328, then compare the two decoders' codeword-length
    consumption symbol by symbol.

    **2026-11-19, part 3 — ported the original patch-engine LZXD decoder.**
    A private, untracked reference source tree for the patch engine's LZXD
    decoder was available locally. Previous sessions only compiled it as a
    black-box oracle; comparing it directly to our port settled the table
    question:

    * the bit-buffer initialiser preloads TWO words into the 32-bit cache
      (`bitbuf = word0<<16 | word1`, `bitcount = 16`), confirming that peeks
      past `bitcount` still see correct stream data;
    * the main/length Huffman decoders peek the top 10/8 bits with NO
      pre-fill, walk negative subtable references, then refill only AFTER
      the codeword is consumed;
    * the code-length reader is a 20-symbol precode with 17/18/19 run codes;
    * the aligned-offset decode is byte-for-byte our existing formula
      (`extra = getbits(extra_bits-3); base + (extra<<3) + aligned_sym`).
      The 707/704 mystery is therefore NOT a convention difference.

    I ported these semantics verbatim into `src/mslzx.c` (32-live-bit cache,
    canonical table builder, post-consumption refill, separate
    verbatim/aligned extra-bit paths). Result:

        native mslzx path, danim.dll._p : 95 / 1054208 wrong  (was 44446)
        native mslzx path, jsproxy._p   :  0 / 12288    wrong  (unchanged)
        OS delegation path              :  0 / both             (unchanged)

    All other suites (XPRESS 40/40, LZX, LZMS 6/6) still pass. The faithful
    port still reads extra=707 at output 2925 and produces distance 1054232,
    while the 2009 system mspatcha.dll produces 1054208 — so the last 95 bytes
    are a genuine version difference between the older reference engine and
    the newer DLL, not a porting error. A heuristic clamp of aligned distances
    to the seed size reduces 95 to 86 (all remaining errors then fall at
    patch-literal offsets >= 73980), but was not kept: it is not grounded in
    either source. The OS-delegation path remains the byte-exact default.

    **Full 17-patch ground truth (2026-11-19, part 4).** The SFX hotfix was
    extracted twice: once by running it (patch engine active) and once by
    direct extraction. The `_sfx_manifest_` in the direct extraction maps each
    `*.dll._p` patch + `RTMGDR\` source to its `RTMQFE\` output, and the SFX run
    produces those RTMQFE files. Verified with `_sfx_.dll` and `mspatcha.dll`
    via `ApplyPatchToFileA`: both produce byte-identical output for danim, and
    the OS-delegation path matches the SFX RTMQFE files byte-for-byte on all
    17 patches.

    Testing the native decoder against all 17 real RTMQFE outputs
    (`diag/allpatches.bat`) showed the earlier "95-byte gap" was only the
    visible tip:

        exact (0 wrong) : browseui, cdfview, jsproxy, msrating, shdocvw, shlwapi
        small gap       : inseng 9, mshtmled 17, mstime 18, danim 95
        large gap       : pngfilt 6961, dxtmsft 157681, dxtrans 138072,
                          iepeers 177644, mshtml 2522999, urlmon 397373,
                          wininet 513721

    The six exact cases are header-only patches (38-byte `_p` files, no LZXD
    stream) plus jsproxy (single LZXD chunk). Every patch with a multi-chunk
    LZXD stream is broken. The aligned-offset 2925 discrepancy is therefore a
    symptom of multi-chunk handling, not an isolated convention difference —
    the native decoder zero-fills after the first chunk's input runs out
    instead of continuing into the next chunk as the DLL does. Attempts to
    reset the bit cache at 32K output boundaries made results worse; the real
    chunk-framing contract is still unresolved. The OS-delegation path remains
    the only byte-exact one (all 17 patches).

    **Chunk-boundary trace (2026-11-19, part 5).** Read the chunk loop from
    the reference source (`patchlzx.c`): each chunk reads a 2-byte size,
    calls `LZX_Decode` with `request = min(remaining, 0x8000)`, and that call
    resets the bit cache from the chunk payload with 4 bytes of padding
    (`end_input_pos = src + size + 4`). `ActualSize` advances the output
    pointer and reduces `remaining`. danim has 33 chunks (sizes
    758,16,488,...,4); chunk 0..31 request 32768 bytes, chunk 32 requests
    5632. Traced the native decoder against the SFX oracle:

    * first divergence is at output 2925, inside chunk 0 (aligned match,
      extra 707 -> distance 1054232 instead of 1054208);
    * first divergence at/after the chunk 0 boundary is output 32768, the
      very first byte of chunk 1: oracle = A4, native = 5A.
    * oracle[32768..] = A4 E9 35 5A 44 matches source[32768..] exactly —
      an identity copy (distance == seed length), the same pattern as 2925.
    * native chunk 1 decodes main symbol 263 (slot 0, length header 7) as a
      distance-1 long match, i.e. a run of chunk 0's last byte (5A) — so the
      first symbol of chunk 1 is decoded differently by the DLL.

    Tested every plausible bit-cache model against the RTMQFE oracle:
    per-chunk reset with zero padding, per-chunk reset with the real next-4
    stream bytes as padding, continuous cache with repointed input, fully
    continuous cache over concatenated payloads, and chunk-start offsets
    -2/0/+1/+2. All either fail outright or are worse than the simple
    "chunk 0 with zero-fill" model (95 bytes wrong on danim). Notably the
    oracle's identity copies at 2925 and 32768 suggest the DLL may apply a
    post-decode retain/copy pass, but no retain ranges were found in the
    header. The exact chunk-boundary contract remains unresolved; OS
    delegation is still the only byte-exact path (all 17 patches).

    **Instrumented bit-buffer / match trace (2026-11-19, part 6).** Added
    symbol-level tracing (`diag/mslzx_trace.c`) that logs, for every symbol,
    the output position, main-table index, bitbuf/bitcount before and after,
    and for matches the slot, length, distance and repeat-offset history.
    Compared against the SFX RTMQFE oracle with `TRACE_LO/HI` windows:

    * zero-fill model (best, 95 wrong on danim): 9 errors in chunk 0,
      **0 errors in chunk 1**, 86 in later chunks. The first chunk-boundary
      symbol (output 32768) decodes with an exhausted cache
      (`bb=00000000 cnt=-16`) to main symbol 263 -> an identity match
      (`dist=1054208, len=35`), which reproduces the oracle exactly.
    * per-chunk-reset model: chunk 1 starts with `bb=0F71674B cnt=16`;
      main-table index 61 yields symbol 263 -> a distance-1 long match
      (`len=14772`), i.e. a run of chunk 0's last byte (5A) — wrong.
    * by output 73963 the zero-fill model's bitcount has drifted to
      **-5901**; it still emits identity matches (dist=1054208) because
      `main_table[0]` maps to one. These match the source but miss the
      patch-introduced literals the DLL emits there.

    So the DLL's chunk-1 output is an identity copy, which our exhausted-cache
    path happens to reproduce, but its later chunks contain real decoded
    patch literals our zero-fill cannot produce. The per-chunk reset reads
    different bits and gets chunk 1 wrong outright. This narrows the gap to
    how the DLL refills the bit cache from the remaining compressed stream
    after chunk 0 — not the symbol tables or the aligned-distance formula.
    OS delegation remains the only byte-exact path (all 17 patches).

    **Root cause identified — PE source transformation (2026-11-19, part 7).**
    The "extraCount = 732" field parsed in `Pa19Apply` is not extra blocks: it
    is `RiftTable.RiftEntryCount`. The apply path in the reference source
    (`patchapi.c:3453-3466`) does:

        if (OldFileInfo->RiftTable.RiftEntryCount != 0)
            TransformOldFileImageForPatching(ExtendedOptionFlags,
                                             OldFileMapped,   // MODIFIED IN PLACE
                                             OldFileSize, NewFileResTime,
                                             &RiftTable);
        CreateNewFileFromPatchData(OldFileMapped, ...);  // LZXD seeds from this

    `TransformCoffImage` applies seven in-place PE transforms
    to the source before LZXD: MarkNonExe, Relocations, Imports, Exports,
    RelativeJmps, RelativeCalls, Resources. The patch stream was generated
    against that transformed source, so the DLL's LZXD window is seeded with
    transformed bytes. Our native decoder seeds with the raw `rtmgdr` file and
    skips every one of these transforms — which is why its distance mapping
    diverges and why it misses the patch-introduced literals. Wine's mspatcha
    has the same gap (`FIXME: special processing of 32-bit executables not
    implemented`), which explains why it fails identically.

    RIFT counts measured per patch (`diag/riftall.bat`): jsproxy 1, pngfilt 44,
    inseng 70, mshtmled 184, dxtmsft 196, wininet 381, urlmon 443, mstime 450,
    danim 732, mshtml 1951. Error counts do not track RIFT count alone (mstime
    has 450 entries but only 18 wrong bytes), so the transform's *content*,
    not just its size, drives the divergence. Implementing the PE transforms
    (a ~220 KB reference module) is the remaining work for a byte-exact native
    path. OS delegation remains byte-exact on all 17 patches.

    **PE-transform port attempt (2026-11-19, part 8).** Built
    `diag/rifttransform.c`: parses the RiftTable (uvli delta-old + svli
    delta-new, accumulated), maps old RVA -> new RVA by binary search with
    nearest-preceding fallback, and applies the i386 E8/E9 relative
    call/jump adjustment across the executable section. For danim the patch's
    ExtendedOptionFlags are 0x300 (no NO_* transform bits set, so all
    transforms are enabled); the RIFT table has 732 entries with non-zero
    displacements (e.g. old 0x14E4 -> new 0x1770, +652). The transform rewrote
    4195 source bytes (1842 E8/E9 instructions).

    Testing against the SFX RTMQFE oracle made the native decode **worse**:
    95 -> 4284 wrong bytes on danim. Bytes around output 2925 are unchanged
    by the transform, and the raw source already reproduces 99.99% of the LZXD
    output — so the LZXD stream is clearly generated against a source that is
    very close to the *raw* file, not one with thousands of rewritten E8/E9
    targets. Either the port is incomplete (the hint map that suppresses
    transforms at relocation targets / non-exe regions is not implemented),
    or these transforms are not what drives the remaining 95 bytes.

    Conclusion: the PE-transform lead is real at the API level but the
    minimal E8/E9 port does not close the gap. The remaining work is either a
    faithful port of all seven transforms including the hint map, or a
    different explanation for the 95 bytes. OS delegation remains byte-exact
    on all 17 patches.

    **Full PE-transform attempt with hint map (2026-11-19, part 9).** Extended
    the port to `diag/rifttransform2.c`: builds the hint map (PE header, all
    16 data directories, all non-exec sections, and HIGHLOW relocation
    targets), applies the relocation HIGHLOW VA adjustments and rebuilds the
    suppression, then applies E8/E9 relative call/jump transforms with hint
    suppression. danim: extflags 0x300, 732 RIFT entries, 3961 bytes changed.
    Result against the RTMQFE oracle: **7101 wrong bytes**, worse than both
    the E8/E9-only port (4284) and the untouched raw source (95).

    This is a decisive negative result for the PE-transform hypothesis as the
    driver of the remaining 95 bytes: the LZXD stream is demonstrably encoded
    against a source nearly identical to the raw file, and applying the
    documented transforms moves it further away. The remaining explanation is
    a detail of the bit-cache / chunk-framing that has so far resisted the
    source-level ports. OS delegation remains byte-exact on all 17 patches.

    **Precise bit-state trace at output 2925 (2026-11-19, part 10).** Using
    `diag/mslzx_trace.c` with `TRACE_LO=2920 TRACE_HI=2935`, the exact decode
    state on the native path is:

        SYM pos=2925 raw=599 mainidx=412 bb=67085800 cnt=5 -> c=343 bb2=842C35DC cnt2=14
        LENHDR hdr=7 bb=842C35DC cnt=14
        LENSYM 2 bb=0B0D7700 cnt=8
        MATCH m=42 len=11 dist=1054232 bb2=7763C000 cnt2=8

    So the main symbol (599 -> slot 42) and the length symbol (2 -> total
    length 11) are identical to the DLL's requirements; the divergence is
    purely in the 14-bit extra-field read that follows `LENSYM`. With
    `bb=0x0B0D7700`, `getbits(14)` returns 707, giving distance 1054232; the
    DLL must read 704 for distance 1054208. Both the reference decoder source
    and both DLL decompilations specify `extra = bitbuf >> (35-17)` (14 bits)
    followed by `fillbuf(14)`, so there is no source-visible convention that
    yields 704. The bit count at the read is only 8, meaning 6 of the 14 bits
    come from below the "valid" region — in the reference design those are live
    stream bits from the preloaded word, and they are what produce 707.

    This is the most tightly localized statement of the remaining gap: the
    DLL extracts a different 14-bit value from the same bit-cache window than
    every source-derived decoder. OS delegation remains byte-exact on all 17
    patches.

    **DEFINITIVE: direct debugger trace of the reference DLL (2026-11-19,
    part 11).** Built `diag/dbgprobe.c`, a Win32 debugger that loads the
    workarea-root `mspatcha.dll` via `ApplyPatchToFileByBuffers` and sets
    breakpoints at the extra-bits read (RVA 0x7248, `shr edi,cl`) and at
    the final distance computation (RVA 0x72E6, `add [ebp-8],edi`). This
    observes the DLL's true internal state rather than inferring it:

        hit 0 (output 0):    EDI(bitbuf)=0B011800 CL=18 -> dist=1054208 edi=2
        hit 3 (output 2925): EDI(bitbuf)=0B0D7700 CL=18 -> dist=1054232 edi=2

    This OVERTURNS the central assumption of parts 1-10: the DLL reads the
    SAME bitbuf (0x0B0D7700), the SAME 14 bits (707 -> CL=18 shift), the SAME
    aligned symbol (edi=2), and computes the SAME distance (1054232) as our
    decoder. There is NO different "704" convention — the extra bits are
    identical in both engines. The earlier "704" inference was wrong.

    Additional confirmations from the debugger:
    * the DLL's source buffer is NOT modified during apply (0 bytes changed),
      ruling out the PE-transform hypothesis conclusively;
    * the debugger-driven run's output is byte-identical to the SFX RTMQFE
      oracle (0 differences), so the trace is of the correct decode.

    Since dist=1054232 with a 1054208-byte seed and output pos 2925 maps to
    source[2901] (=0x0D), yet the DLL emits 0x0E (=source[2925]), the
    divergence is in the MATCH COPY / window positioning stage, not the bit
    cache or distance read. Either the DLL's dictionary window is seeded /
    indexed differently than `window[W-seedLen .. W-1]` + wraparound, or a
    later stage rewrites those bytes. This is now the precise place to look.

    **FINAL: DLL window trace solves it (2026-11-19, part 12).** Built
    `diag/dbgwin.c` / `diag/dbgseed.c`: a Win32 debugger that breaks inside
    the DLL's match-copy loop (RVA 0x7514, `mov bl,[edi]`) and reads the actual
    window byte, then dumps the dictionary seed region. Results:

        wbase = 0x02...9B8; seed at wbase + 3140096 (= W 4194304 - seedLen 1054208)
        seed[0..] = MZ... (source[0])                     -- seed start correct
        output 2901: srcoff=2897 byte=0D (= source[2897])
        output 2925: srcoff=3142997 byte=0E               -- DLL reads 0x0E here
        raw source[2901] = 0x0D

    The DLL's source index (3142997 = (2925-1054232) & 0x3FFFFF) is IDENTICAL
    to our port's. The difference is the WINDOW CONTENT: at seed index 2901
    the DLL holds 0x0E, while the raw file has 0x0D. Dumping seed[2880..2943]
    showed a repeating `D8 0E 3E 5A / 0B 0F 3E 5A` pattern where the raw file
    has `74 0C 3E 5A / A7 0C 3E 5A / ...` — i.e. the DLL's dictionary is a
    TRANSFORMED copy of the source (PE relocation / RiftTable normalization).

    This is consistent with the reference apply path: `patchapi.c:3453` calls
    `TransformOldFileImageForPatching` on a COPY of the old file before
    `CreateNewFileFromPatchData` seeds the LZXD dictionary. The earlier
    "source buffer unchanged" observation was on the caller's buffer, not the
    DLL's internal copy. The patch stream is encoded against that transformed
    seed. Our native decoder seeds with the raw `rtmgdr` file, so every match
    that references a transformed byte (notably the aligned identity-copies)
    is wrong — exactly the 95 bytes on danim.

    Therefore the fix is NOT in the bit cache, distance read, window layout,
    or copy formula (all confirmed identical) and NOT post-decode rewriting:
    it is the PRE-DECODE PE SOURCE TRANSFORM. Earlier transform ports failed
    because they implemented the wrong transform set / hint-map semantics.
    OS delegation remains byte-exact on all 17 patches.

    **Retained-range / growth-list investigation (2026-11-19, part 13).**
    Traced the complete DLL apply pipeline in `mspatcha.dll.c`:
    `SaveRetainRanges` (1134) packs raw old-file bytes into a buffer;
    `ApplyRawLzxPatchToBuffer` (2412) seeds LZXD from the growth list
    (`{oldOffset, insertSize, ...}` triples, one `LZX_DecodeNewGroup` per
    group); `CreateNewFileBufferFromPatchData` (1245) after decode does, for
    each retain range, `memcpy(output + OffsetInNewFile, saved, LengthInBytes)`.

    Hard finding: **danim has retainCount = 0** (verified by instrumenting
    `Pa19Apply`, and the header layout matches Wine's `pa19.c:362-407`). So the
    retained-range pipeline is a no-op for this patch and cannot explain the
    95 mismatches. Its groupCount is 1 with a full-file insert — also already
    matched by our decoder. The 732 field is the RIFT table (`unknown_count`
    in Wine, which Wine outright rejects), not extra blocks.

    Also tested decisively this round: feeding the DLL's dumped transformed
    seed into our decoder gives **36,676** wrong bytes (vs 95 with raw), and
    only 3 of the 95 raw-seed errors sit at seed-transform positions. So the
    seed transform is not a drop-in fix either. E8 on/off makes no difference.

    Conclusion: neither retained ranges, growth-list grouping, the PE seed
    transform, nor E8 explains the remaining 95 bytes. The bit cache, distance
    read, window layout and copy formula are all confirmed byte-identical to
    the DLL. OS delegation remains byte-exact on all 17 patches; the native
    fallback stays at 95/1054208. No source changes were made this round.

    Source-level details are intentionally kept out of the tracked tree.

    **EXTRALONGMATCHES + per-chunk reset breakthrough (2026-11-19, part 14).**
    The part 13 conclusion was wrong. The native decoder was NOT faithfully
    decoding the LZXD stream after 32K. Two modelling errors masked each other:

    1. **Extra-long matches.** PA19 streams carry `EXTRALONGMATCHES`: when a
       match length decodes to exactly MAX_MATCH (257), a 9-bit extension
       follows (with nested 9/6/3-bit continuations, see the reference
       decoder). The native port did not implement this, so any 257-byte
       match desynced the stream from that point onward.
    2. **Per-chunk bit-cache reset.** Each 32K output chunk is its own
       `[u16 size][payload]` unit, and the decoder re-initialises the 32-bit
       bit cache (2 preloaded words, `bitcount = 16`) at the start of every
       chunk. Huffman trees and the LRU repeat offsets persist across chunks;
       only the bit cache resets. The native port had been decoding the whole
       file from chunk 0 and zero-filling on exhaustion (the "95 errors"
       state), which coincidentally copies source bytes for the ~99.99% of
       the target that is unchanged.

    With both corrected, the decoder consumes a real, byte-exact stream. A
    reference build of the full LZX decoder source, driven by the same
    per-chunk model, reproduces the ground truth
    **bit-for-bit (0 / 1,054,208)** when given:
      - the per-chunk driver above,
      - `EXTRALONGMATCHES`, and
      - the DLL's pre-decode transformed seed.

    Error progression on danim makes the diagnosis unambiguous:
      - zero-fill from chunk 0 (old native state): 95 wrong
      - per-chunk, no extra-long matches: 934,203 wrong (desync at 32K)
      - raw-seed, per-chunk + extra-long: 26,837 wrong
      - transformed-seed, per-chunk + extra-long: **0 wrong**

    So the remaining gap is entirely the **pre-decode PE source transform**,
    now confirmed necessary and, with a correct decoder, sufficient to reach
    exactness. The transform is deterministic but large: on danim it rewrites
    37,053 bytes in 17,556 regions, distributed as
      - header: 4 bytes (COFF TimeDateStamp + recomputed PE checksum),
      - `.text`: 7,405 bytes (relative jmp/call canonicalisation etc.),
      - `.reloc`: 29,644 bytes (relocation-table canonicalisation),
      - `.data` / `.rsrc`: 0 bytes.
    Imports/exports live in `.text` here; resources are untouched for danim.
    Porting this pipeline (normalize + relocations + relative jmps/calls +
    imports/exports + checksum, driven by the patch's transform options and
    RIFT table) is the only path to a byte-exact native decoder.

    **Seed transform reproduced exactly (2026-11-19, part 15).** Built a
    standalone reference harness from the private PE-transform source and
    confirmed it reproduces the DLL's pre-decode seed **bit-for-bit
    (0 / 1,054,208 bytes differ)** for danim. Inputs, all parsed from the
    PA19 header we already read:
      - `TransformOptions = ExtendedOptionFlags` (0x00000300 for danim),
      - `NewFileCoffBase = 0x5A320000`,
      - `NewFileCoffTime = NewFileTime - delta = 0x4ABC59CA`,
      - RIFT table = the per-file `extraCount` field (732 entries of
        `{OldFileRva, NewFileRva}`, decoded as uvar `DeltaPos` then svar
        `DeltaNew`), which `delta.c` already walks but discards.
    The transform runs `NormalizeCoffImage` (timestamp + checksum) then
    `TransformCoffImage` (MarkNonExe, relocations, imports, exports,
    relative jmps/calls, resources; new-style branch because
    `TransformOptions & 0x300`), driven by the RIFT table.

    So the full native pipeline is now fully characterised and provably
    exact:
        raw source -> [PE transform + RIFT] -> seed
                   -> [per-chunk LZXD + EXTRALONGMATCHES] -> target.
    Port order: (1) decoder model in `mslzx.c`, validated with the
    reference seed; (2) the PE transform as a new tracked module,
    validated against the captured seed; (3) wire `delta.c` to parse the
    RIFT/options and call the transform.

    **Native PA19 is byte-exact on all 17 patches (2026-11-19, part 16).**
    Landed the full pipeline in tracked code:

      - `src/mslzx.c`: per-32K-chunk bit-cache reset with persistent Huffman
        trees / LRU repeat offsets, and extra-long-match extension.  This is
        the decoder model the reference patcher actually uses.
      - `src/pefix.c` + `src/pefix.h`: the pre-decode PE seed transform
        (NormalizeCoffImage timestamp/checksum/rebase plus TransformCoffImage
        relocations, relative branches, imports, exports and resources,
        driven by the patch RIFT map).  Validated bit-for-bit against the
        captured reference seed (0 / 1,054,208 differ).
      - `src/delta.c`: parses the RIFT map, `NewFileCoffBase`,
        `NewFileCoffTime` and `ExtendedOptionFlags`, prepares a transformed
        copy of the source, and seeds LZXD from it.

    Results with OS delegation disabled (`PA19_NO_OS=1`), native path only,
    versus the SFX-generated RTMQFE ground truth:
        browseui 0, cdfview 0, danim 0, dxtmsft 0, dxtrans 0, iepeers 0,
        inseng 0, jsproxy 0, mshtml 0, mshtmled 0, msrating 0, mstime 0,
        pngfilt 0, shdocvw 0, shlwapi 0, urlmon 0, wininet 0.
    The OS-delegation path is unchanged and still exact.  XPRESS (40/40),
    LZX and LZMS (6/6) suites all pass.

    Lesson: the old "95 residual bytes" were an artifact of decoding the whole
    file from chunk 0 with zero-fill; the real defects were the missing
    per-chunk reset, missing extra-long matches, and the unapplied seed
    transform, all three now addressed.

    **Native SFX unpacking (part 17).**  `expand_recon.exe` now handles the
    whole Windows Update SFX package without any OS helper.  Two gaps had to
    be closed:

      1. `src/cab.c` decoded LZX folders one CFDATA block at a time and
         discarded the seed (`LzxDecompressSeeded` ignored its `seed`
         argument).  Block 0 decoded, block 1 failed: Huffman trees, repeat
         offsets and E8 translation all carry across CFDATA boundaries.  The
         folder's payloads are now concatenated and passed to
         `LzxRawDecompress()` in one pass.  Verified against an independent
         `extrac32.exe` extraction of the hotfix CAB: 50/50 files identical.
         `EnsureParentDir()` was also added to the DPX extraction loop so
         nested CAB paths (`rtmgdr\`, `update\`) can be created.
      2. New `src/sfx.c` detects an embedded CAB carrying `_sfx_manifest_`
         and/or `_sfx_.dll`, carves it to a temporary file, parses the
         manifest `[Deltas]` / `[Copy]` sections, and applies each delta with
         `DeltaApply()` before writing the output to its manifest target.
         `-F:` selection covers both CAB entries and delta targets; a
         selected target pulls in its patch and source automatically.

    End-to-end check: `expand_recon.exe IE6.0SP1-KB2722913-...EXE -F:* <dir>`
    with `PA19_NO_OS=1` produces 18 patched binaries, all 0 differing bytes
    versus the SFX-run `RTMQFE` ground truth; the OS-delegation default is
    also 18/18 exact.  Regression suites (XPRESS 40/40, LZX, LZMS 6/6,
    PA19 OS + native) still pass.

    **MSU / nested CAB / CIX (part 18).**  Extracting
    `windows8.1-kb2959977-x86_5ccf...msu` exposed three more gaps, all now
    closed in `expand_recon.exe`:

      1. `src/cab.c` computed the first CFFOLDER offset as `38 + cbCFHeader`
         when CFHEADER flag 0x0004 was set; it must be `40 + cbCFHeader`
         (cbCFHeader[2] + cbCFFolder[1] + cbCFData[1]).  CFFILE reserve bytes
         are now honoured too, and CFDATA walking is bounded by
         `cfhead.cbCabinet` instead of the whole file, so trailing bytes
         after the cabinet are ignored.
      2. `src/lzx.c` rejected incomplete canonical trees (legal for the LZX
         aligned-offset tree) and dropped only one bit after an odd-length
         uncompressed block instead of a whole padding byte.  With both
         fixed, the inner LZX:21 CAB decodes: 514/514 files byte-identical
         to an independent extraction.
      3. New `src/cixapply.c` parses `_manifest_.cix.xml` (via `cix.c` /
         `xml.c`), copies RAW targets, and applies the 181 PA30 deltas by
         CIX id basis chain.  `dpx.c` expands nested CABs into a directory
         named after the inner CAB and then applies its CIX manifest.

    Real PA30 blobs use explicit per-segment `CompressionLengths`, which the
    native compo port does not implement.  `delta.c` now delegates them to
    the OS `msdelta.dll` `ApplyDeltaA` (disabled by `PA30_NO_OS=1`), exactly
    as PA19 delegates to `mspatcha.dll`.

    Verification: the full MSU extraction produces 513 CIX targets; every
    one matches the SHA256 hash and declared length in the manifest.  The
    IE6 SFX, XPRESS (40/40), LZX, LZMS (6/6) and PA19 regression suites
    still pass.

    **Compo port, part 19 (in progress).**  The native PA30 path now reads
    explicit per-segment `CompressionLengths` instead of always using the
    default fixed code: `compfmt_read()` builds the 39-symbol meta Huffman
    code, `cl_read()` is wired up for each segment with the previous segment
    as baseline (the encoder starts from an all-zero baseline), and
    `compo_decompress()` switches length sets at segment boundaries.

    The meta-code stream is consumed MSB-first (`huff_decode_msb`), matching
    `statichuffman::DecoderTable::Decode` + `Consume`.  With that, the decoded
    length sets for the KB2959977 blob 0 are complete Huffman codes (Kraft
    sum exactly 1 for main, len and dist in both segments), and the first
    decoded symbols are the expected PE header bytes.  Generated PA30 vectors
    and all other regression suites still pass with `PA30_NO_OS=1`.

    Still unresolved: decoding diverges partway through real deltas.  The
    first bad long-distance symbol decodes to a distance larger than any
    valid window position (e.g. 24741 at output position 5230), so a match
    length or distance field is misread after the early literals.  Real
    deltas therefore still require the OS `msdelta.dll` delegation, which
    remains the default.

    **Compo port, part 20 (match distance).**  Comparing a partial native
    decode against the OS-produced target located the first divergence at
    output offset 592 (previously offset 9).  The cause was in
    `cf_read_symbol()`: for long-distance symbols the DLL decodes a Huffman
    distance symbol only when `v21 >= 4`; for smaller values it uses
    `(v22 << v21) | Read(v21)` directly, and for `v15 == 0` it first expands
    the code with a nested 1/1/3/4-bit prefix.  Our port always decoded a
    distance symbol, turning a distance of 4 into 37 at offset 9.  Both cases
    are now implemented per the `ReadSymbol` decompilation.

    The remaining divergence is a single byte at offset 592: the repeat-match
    symbol `0x54003` selects history slot 2 (distance 127), which copies
    `00 00 b0` from output positions 463..465, while the OS result has
    `00 00 00` there (consistent with a distance near 6).  History values
    and the update rule match the `InternalProcess` assembly, so the repeat
    index mapping or an earlier rift/source-window distance remains suspect.
    Real deltas therefore still need `msdelta.dll` delegation; all regression
    suites pass with the native path for the generated vectors.

    **Compo port, part 21 (repeat history / E8).**  Tracing the byte-592
    mismatch against `InternalProcess` (`msdelta.dll.lst:61468`) showed the
    history update was incomplete: the DLL does not shift the third slot when
    the *old second* slot already equals the new distance.  `compo_decompress`
    now checks both slots, which moves the first divergence from offset 592
    to offset 9655 and keeps the decoder alive to position 11696.

    All remaining differences are x86 `E8` CALL displacements.  The encoded
    rel32 equals the OS value plus the byte position of the `E8` opcode
    (e.g. `0x470a` at position 9654 becomes `0x2154`); displacements that are
    large data values (`0x2a004022`, `0x8b0b0000`) are deliberately left
    alone.  An incremental translation pass was attempted but match copies
    re-translate already-translated bytes and made the first divergence move
    backwards, so it was backed out.  Real deltas still use `msdelta.dll`
    delegation; all regression suites pass natively for generated vectors.

    **Compo port, part 22 (header split / rift window / E8).**  Verified the
    PA30 header against the DLL's `writeVersion/writeCode/writeFlagsInt/
    writeTargetSize/writeHashAlgId/writeHash` sequence: the first integer is
    `FileTypeSet` (117 for the real KB2959977 blob), not a version.  The
    `pre`/`patch` blob split is also correct (`preLen=0`, `patchLen=20529`,
    patch starts at byte 44), and the patch stream's rift flag is genuinely 0:
    no alternative leader/bit order yields valid `IntFormat` parameters.

    Two improvements to the native decoder:
      - A rift match with an empty table uses the identity map over the
        combined source+output window (source below `srcLen`, already
        decoded output above it).  This lets the real delta decode to
        completion instead of failing at position 11696.
      - DELTA_FLAG_E8 CALL displacements are untranslated in one final pass,
        subtracting the E8 byte position from small rel32 values only.

    The real delta now produces 49544 bytes but still has 11329 differing
    bytes, starting at offset 37922 (a long-distance match whose bytes are
    not present in either the source or earlier output).  Real deltas remain
    on the byte-exact `msdelta.dll` path; generated vectors and all other
    regression suites pass natively.

    **Compo port, part 23 (segment boundaries).**  Following the boundary
    delta 37922 back to the patch stream showed the `CompositeFormat`
    boundaries are stored as absolute output offsets in this container, not
    cumulative deltas.  Reading them cumulatively produced a second boundary
    of 49054 and switched code sets 37922 bytes too late, which desynced the
    main-tree Huffman decode exactly at output position 37922.  `compfmt_read`
    now stores the integers verbatim.  Match distances and the repeat history
    are also kept signed so source-relative negative distances stay valid.

    With these changes the first real KB2959977 PA30 blob decodes natively
    to 49544 bytes, byte-identical to `msdelta.dll` (SHA256 628d60...) and
    matches the CIX manifest hash for wuauclt.exe.  Generated PA30 vectors,
    PA19, XPRESS, LZX and LZMS suites still pass.  Later blobs in the chain
    (e.g. wusettingsprovider.dll) still need the OS path; their rift tables
    are not yet parsed correctly.

    **Compo port, part 24 (pre-blob target info).**  The next chained delta
    (wusettingsprovider.dll) has header flags 0x6621FF (E8, MARK, IMPORTS,
    EXPORTS, RESOURCES, RELOCS, I386 JMPS/CALLS, UNBIND) and a 328-byte
    `pre` blob, so the encoder normalized the old PE image before patching.
    `PortableExecutableInfo::InternalFromBitReader` (`msdelta.dll.c:19685`)
    shows the pre blob starts with a 64-bit target ImageBase, a 32-bit
    GlobalPointer and a 32-bit TimeStamp, followed by a RiftTable and CLI
    metadata, then the compression RiftTable and CliMap.  For this blob the
    values are ImageBase 0x80000000, GlobalPointer 0, TimeStamp 0x9A25E508
    (a stub-PE target, not the real DLL's 0x10000000 / 0x5344BCA1).

    Applying our PA19 `PeFixPrepareSeed()` to the source with either base and
    timestamp pair still does not make the delta decode: the pre-blob RiftTable
    must also drive the transform, and our PA19 transform module expects a
    different option-flag mapping.  The committed state is unchanged; real
    deltas beyond the first continue to use `msdelta.dll`.

    **Compo port, part 25 (pre-blob RIFT table).**  The pre blob is a
    bit-packed `PortableExecutableInfo`: 64-bit ImageBase, 32-bit
    GlobalPointer, 32-bit TimeStamp, a RiftTable, optional CliMetadata,
    then a second RiftTable (the compression map) and optional CliMap.
    For the wusettingsprovider delta the first table is empty, CliMetadata
    is present (15 dwords, 3 bits, a 64-bit presence mask, then one dword
    per set bit), and the second table starts with a non-empty flag.  A
    bounded scan found a plausible table at bit 1644 of the pre blob
    (IntFormat params 95/3/43, 112 entries).

    `if_decode()` also double-consumes Huffman bits: the DLL's
    `IntFormat::ReadNumber` peeks with `DecoderTable::Decode` and then
    consumes `len[s]`, while ours did both in `if_decode` and again in
    `if_read_number`.  Fixing that and parsing the pre blob were attempted
    together; the chained delta then crashed inside the native path, so
    both changes were reverted.  The committed state remains byte-exact for
    the first delta, and real chained deltas still use `msdelta.dll`.

    **Compo port, part 26 (IntFormat consumption fixed).**  `if_decode()`
    consumed one bit per tree level and `if_read_number()` then consumed
    `len[s]` more, so every IntFormat number ate its code twice.  An
    isolated model of the corrected reader (peek the code in `if_decode`,
    consume `len[s]` in `if_read_number`) was run against the 328-byte pre
    blob from the wusettingsprovider delta: it parses a plausible 202-entry
    RIFT table whose offsets stay inside the image.  The one-line fix is
    now in `src/delta.c`.  It leaves the first real delta byte-exact and
    all PA30/PA19/XPRESS/LZX/LZMS regression suites green; pre-blob parsing
    itself is still not enabled in the native decoder.

    **Compo port, part 27 (pre blob leader).**  The pre blob carries the
    same 3-bit zero leader as the PA30 header: reading its target info from
    bit 3 yields ImageBase 0x10000000, GlobalPointer 0 and TimeStamp
    0x5344BCA1 for the wusettingsprovider delta, matching the real target
    PE header.  `DeltaApply` now skips that leader and walks the target
    info, the first RiftTable and optional CliMetadata before reading the
    compression map; rift matches record a signed distance and the repeat
    history starts at {1,1,1}.

    The first RiftTable after the target info still parses as empty with
    the current IntFormat reader, so the compression map is not yet
    recovered and the chained delta still fails.  All existing suites
    remain green and the first real delta stays byte-exact; chained deltas
    continue to use `msdelta.dll`.

    **Compo port, part 28 (chained-delta reproduction).**  Rebuilt a focused
    harness from KB2959977: CIX id 158 (`wuauclt.exe`) is blob 0 applied to
    basis id 27, and id 236 (`wusettingsprovider.dll`) is blob 1 applied to
    basis id 158.  With the OS path disabled, blob 1 fails (`DeltaApply`
    returns -1); the OS path is byte-exact (0 / 307200), confirming the
    oracle and basis are correct.  Added `PA30_DEBUG` tracing in `delta.c`.

    The trace shows the 3-bit pre-blob leader IS correct (ImageBase
    0x10000000, TimeStamp 0x5344BCA1 at bit 3; bit 0 holds the stub-PE
    0x80000000 / 0x9A25E508).  The first RiftTable at bit 131 does parse as
    non-empty, but with params 37/0/206 it yields six entries whose `left`
    values are -2^32 and below, consuming 5289 bits and running past the
    328-byte pre blob; the CliMetadata flag after it is therefore bogus and
    the compression map is read as empty.  A bounded scan confirms the real
    compression RiftTable starts at bit 1644 with IntFormat params 95/3/43,
    but our `rift_read` rejects its second IntFormat (n1=194 > 0x7E) — the
    420-bit first IntFormat leaves the next reader at bit 2065, so either a
    field between the two IntFormats or the first IntFormat's length model
    is still wrong.

    Grounded fix applied: `IntFormat::InternalFromBitReader`
    (`msdelta.dll.c:44594`) reads the `n2` large-symbol lengths BEFORE the
    fill `base` value; `if_read()` had them swapped.  This matters for
    n2 > 0 (the compression map uses n2 = 3).  Generated PA30 vectors and
    the first real delta stay byte-exact; chained deltas still need
    `msdelta.dll`.  Next step: use a debugger oracle on the DLL's pre-blob
    reader to recover the exact bit layout between bit 131 and bit 1644.

    **gdb oracle attempt (part 29).**  Set up MinGW gdb (`diag/msdelta_trace.gdb`)
    with `break ApplyDeltaA` + Python breakpoints at the Win7 DLL's
    `PortableExecutableInfo` / `RiftTable` / `CliMetadata` / `IntFormat`
    `InternalFromBitReader` RVAs (base derived from `$pc` at the export, since
    ASLR rebases the DLL).  Two findings:

      - The bundled `msdelta.dll` is Win7 6.1.7600; the byte-exact OS path on
        KB2959977 actually uses `C:\Windows\SysWOW64\msdelta.dll` (a newer
        build).  The Win7 DLL applies the generated vectors but **rejects the
        Win8.1 blob 1 before PEInfo is read** — none of the four reader
        breakpoints are hit.  So it cannot serve as the oracle for this delta.
      - The system DLL applies the delta correctly, but its code is a
        different build: the Win7 byte signatures do not occur in it, so the
        decompiled RVAs cannot be reused and it has no symbols for its
        internal readers.

    The oracle path therefore needs either (a) a Win7-generated PE delta with
    a pre blob, traceable with the decompiled DLL, to nail the reader layout,
    or (b) a signature/code search in the system DLL to relocate the reader
    functions.  `diag/msdelta_trace.gdb` and `diag/msdelta_apply.gdb` are kept
    as the reusable starting point.  No tracked source changed this round.

    **Compo port, part 30 (gdb oracle delivered the root cause).**  With the
    decompilation regenerated from the *current system* `msdelta.dll`, the gdb
    scripts worked directly: `msdelta_trace.gdb` logged the real reader entry
    points and `msdelta_rn.gdb` dumped every `IntFormat::ReadNumber` value,
    `msdelta_lens.gdb` the Huffman length/code tables.  Findings and fixes:

      - The real DLL's first RIFT table entries are `(left,rift)` =
        `(0,0),(4096,-3072),(278528,-5120),...` — PE RVA -> file-offset maps.
        Our decoder produced `-2^32` garbage.  Root cause: `if_decode()` used
        the textbook bottom-up canonical first-code recurrence, while the
        DLL's `statichuffman::Codes::CalculateCodes` computes first codes
        **top-down** (`first[maxLen]=0; first[L]=(first[L+1]+count[L+1])>>1`),
        giving e.g. first[2]=2, first[3]=1 (dumped `codes[]` confirms this).
        `if_build()`/`if_decode()` now use the DLL recurrence.  A second bug,
        `code - count < first` false-matching when count==0, was also fixed
        (`code >= first && code - first < count`).
      - The pre-blob's compression RIFT map (88 entries) now decodes with
        exactly the same bit positions as the DLL: first RIFT ends at relative
        bit 459, CliMetadata flag at 460, compression map starts at 461.
      - The patch blob's own leading RiftTable must still be consumed before
        `CompositeFormat`; it is now skipped without replacing the pre-blob
        map.  CompositeFormat then parses correctly (5 segments).

    The decoder now runs to output position ~1084 with 67/1084 wrong bytes;
    the remaining defect is the RIFT distance mapping for long-distance
    matches (our entry-selection/distance formula is still heuristic).  The
    first real delta (blob 0), generated vectors, PA19, XPRESS, LZX and LZMS
    all remain byte-exact.  `PA30_DEBUG`, `PA30_SYMDBG`, `PA30_PARTIAL` guard
    the new tracing.  Next step: use `msdelta_rn.gdb` at a failing match to
    recover the exact RIFT-adjusted distance formula.

    **Compo port, part 31 (seed normalization).**  `msdelta_sym.gdb` compares
    our symbol stream with the DLL's at matching combined-buffer positions:
    they are identical (same 0x54000 rift match at output 255, same literals),
    so the divergence is not in the symbol decode.  Dumping the basis bytes
    showed the DLL writes the pre-blob target COFF TimeStamp (0x5344BCA1) at
    PE+8 and rebases the optional-header ImageBase (0x00400000 -> 0x10000000)
    in a *copy* of the source before decoding.  `DeltaApply` now parses those
    two fields from the pre blob, makes a normalized source copy (also via
    `PeFixPrepareSeed` with the pre-blob RVA map), and feeds it to the
    decompressor.  Raw-distance (k<3) matches now always add srcLen (the
    implicit rift), not just when the table is empty; zero distances are
    allowed as identity repeats.  RIFT entries are selected by nearest
    preceding `left`, not by `right >= pos`.

    Result: blob 1 now decodes to position 83512 (was 1084) with 10168/83512
    wrong bytes; the first divergence moved 224 -> 256 -> 302 -> 1026 as each
    fix landed (a history experiment that moved it to 298 was reverted
    because it broke blob 0).  The remaining differences are PE-transform
    fields (relocations / relative branches) at output offsets >= 298, plus
    one out-of-range RIFT match at 83512.  Blob 0, generated vectors, PA19,
    XPRESS, LZX and LZMS all remain byte-exact.

    **Seed-transform trace (part 32).**  `msdelta_sym.gdb` shows the DLL's
    symbol stream is byte-for-byte identical to ours at matching combined
    positions (e.g. output 255: a 16-byte 0x54000 rift match; output 1026:
    another rift match), so the remaining divergence is entirely the
    transformed seed bytes.  Reconstructed transformed source from the DLL's
    output at identity-rift regions:

      - file 0x100 (COFF TimeDateStamp): 0x5344BCA1 (pre-blob target TS),
      - file 0x12C (PE32 ImageBase): 0x10000000 (pre-blob target base),
      - file 0x400..0x43F (start of .text, RVA 0x1000): a jump table of
        absolute addresses rewritten from old-base 0x00408xxx to new-base
        0x10015xxx, e.g. 0x0040809B -> 0x10017348, 0x004078ED ->
        0x100152ED.  The new RVAs (0x15xxx) are not a constant rebase or a
        simple RIFT displacement of the old RVAs (0x8xxx), so this is a
        semantic rewrite (import/export or relative-branch canonicalisation)
        driven by the pre-blob RVA map and the delta flags (0x6621FF).

    Calling the PA19 `PeFixPrepareSeed` with the pre-blob RVA map changes
    only part of a table word (0x80 -> 0x40 at file 0x401) and is not the
    PA30 transform.  Implementing the remaining rewrite needs a dedicated
    port of the DLL's `TransformCoffImage` variant for PA30.  `msdelta_src.gdb`
    is kept as the seed-buffer trace starting point (GetChars is only called
    at buffer boundaries, so it needs a different hook to dump every seed
    byte).  No further source change this round.

    **PA30 TransformCoffImage implemented (part 33).**  `msdelta_rift.gdb`
    extracted the DLL's `AbstractRiftHintTransformComponent::MapRva` table —
    it is the 88-entry compression RIFT map, and `RiftTable::Map` is
    `rva + (right-left)` of the nearest preceding entry.  `msdelta_seed.gdb`
    dumped the DLL's *fully transformed* seed and revealed the exact
    `RiftTransformRelocationsI386Component::TransformInferredRelocations`
    algorithm: scan from PE SizeOfHeaders, and rewrite every dword that is a
    VA within `[oldImageBase, oldImageBase+SizeOfImage)` to
    `MapRva(va-oldBase) + newBase`, using a packed per-byte hint array to
    avoid overlapping rewrites (advance 4 bytes on a hit, 1 otherwise).

    `delta.c` now implements this as `pa30_transform_pointers()` (plus the
    timestamp / ImageBase header patches) and applies it to a copy of the
    source.  Verified byte-exact against the DLL's seed: file 0x400 =
    `13 A2 01 10` (was `9B 80 40 00`), 0x45C = `90 40 04 10` (was
    `90 A0 40 00`).  Blob 1 improves to 83512 bytes decoded with 7815 wrong
    (was 10168); first divergence moved 1026 -> 1116.  At the new divergence
    our seed byte *equals* the DLL's, so the remaining error is RIFT match
    source positioning, not the seed transform.  Blob 0, generated vectors,
    PA19, XPRESS, LZX and LZMS remain byte-exact.

    **RIFT match source = OffsetRiftTable (part 34).**  `msdelta_riftpos.gdb`
    logs the argument to `BufferList::GetCharsConst` at the 0x54000 copy and
    `msdelta_offsetrift.gdb` / `msdelta_orift_init.gdb` dump the tables.  The
    DLL does NOT use `pos + rift` directly: it builds an `OffsetRiftTable`
    from a 77-entry RiftTable whose entries are already in combined-buffer
    coordinates, e.g. `(left,right)` = `(49544,0), (50600,-264672),
    (50648,1056), (59000,-253200), ...`.  `OffsetRiftTable::Init` turns each
    into `(left, right-left)`, giving `[0]=(0,-298888), (49544,-49544),
    (50600,-315272), (50648,-49592), ...`; a rift match at combined position
    P uses `src = P + off` of the entry with the largest `left <= P` and is
    limited by the next entry's `left`.  Ground truth: output 0..1034 read
    `src = out` (off -49544), output >=1116 reads `src = out-48` (off
    -49592).  Our decoder currently uses `src = pos` for all rift matches,
    which explains the divergence starting at output 1116 despite an exact
    seed.  The remaining task is to derive that 77-entry RiftTable from the
    pre-blob / delta inputs (it is not the 88-entry compression map) and use
    it for rift matches.

    **OffsetRiftTable derived and wired (part 35).**  Traced
    `RiftTable::Multiply` (gdb: `msdelta_multiply.gdb`) and the decompiled
    pipeline string: the DLL builds the decompressor's table as
    `t0 = sourceOffsetToRva` (from the source PE sections: file offset -> RVA),
    `t1 = t0 * compressionMap`, `t2 = t1 * targetRvaToOffset` (the first
    pre-blob RiftTable), then **`ReverseRiftTable(t2)`** and shift every left
    by `srcLen`.  `delta.c` now implements `rift_multiply`, `rift_reverse` and
    this pipeline.  `msdelta_buildrift.gdb` confirmed the 77-entry input table
    and its Add calls.

    Also fixed the rift semantics from ground truth (`msdelta_riftpos.gdb`):
    the OffsetRiftTable is keyed by the **combined** position `srcLen+out`;
    a 0x54000 match copies from `MapRift(cpos)`, while a k<3 distance D reads
    `MapRift(cpos) - D` (the DLL rebases normal matches through the same map).
    An empty table implies `off = -srcLen`.

    Verified: our derived ORIFT entries now match the DLL's dumped table
    (`(49544,0), (50648,1056), (133056,9408), ...`).  Blob 1 improves to
    **44338/307200 wrong, first divergence 6948** (was 85709).  At 6948 the
    symbol stream is identical and the divergence is a seed byte at file
    0x7AE0 (import-table region): our seed still differs from the DLL's in
    2021 bytes, so the remaining work is the import/export PE transforms.
    Blob 0, generated vectors, PA19, XPRESS, LZX and LZMS remain byte-exact.

    **Import RVA rewrite (part 36).**  The DLL rewrites import-table RVAs by
    `MapRva` (e.g. 0x0000B99E -> 0x000474C6) and sets IMAGE_SCN_MEM_WRITE on
    the section holding the import directory (here .idata: 0x40000040 ->
    0xC0000040).  `delta.c` now has `pa30_mark_import_section()` and
    `pa30_transform_rvas()` (guarded by PA30_RVAREWRITE); restricted to the
    import section they reproduce the DLL's bytes at 0x7AD0-0x7AF0 exactly.
    Seed diff drops 2021 -> 1292 and blob 1 to 43590/307200 wrong (first
    divergence 6948 -> 4878).  Remaining problem: the scan still rewrites
    ASCII data that merely looks like an RVA (e.g. 0x83FC `"StringW"` `0x5767`
    was changed to 0x178DF though the DLL left it), because the DLL uses a
    per-byte usage/hint map produced by its transform pipeline rather than a
    blind RVA scan.  Reproducing that hint/usage map is the last step.

    **Precise import rewrite (part 37).**  Instead of guessing which DWORDs
    are pointers, `pa30_rewrite_imports()` now parses the PE import directory:
    it walks the 20-byte descriptors and both thunk arrays, rewriting only
    the OriginalFirstThunk / Name / FirstThunk fields and the thunk entries
    through `MapRva`.  This avoids the ASCII false positives of the blind
    scan (file 0x83FC `"StringW"` is now left untouched, matching the DLL).

    Result: seed diff 1292 -> 1216, blob 1 **43454/307200 wrong with the first
    83630 bytes byte-exact** (first divergence 4878 -> 83630).  The remaining
    seed diff starts at file 0x2F40 (a `TransformInferredRelocations`
    over-rewrite in .text) and the remaining decode divergence at output 83630
    is a repeat-match (0x54002) whose history distance differs from the DLL's.
    Blob 0, generated vectors, PA19, XPRESS, LZX and LZMS stay byte-exact.

    **Two remaining gaps isolated (part 38).**  Added `PA30_SEEDFILE` to feed
    the DLL's dumped transformed seed into our decoder.  With the exact seed
    blob 1 improves to **4203/307200 wrong, first divergence 262695** (vs
    5858/86120 with our computed seed).  This cleanly separates two bugs:

    1. **Seed transform** (~1655 bytes of error): our `TransformInferredRelocations`
       over-rewrites instruction immediates (e.g. file 0x5CAC `B8 03 40 00`)
       that the DLL's hint map excludes.  `CreateHintBuffer` only allocates a
       zero buffer; earlier transform stages populate it, which we do not port.
    2. **ORIFT composition** (~4203 bytes of error): at combined position
       312239 (output 262695) the DLL uses offset -312200 from table entry
       `(153856, -158344)`, while our composed table has no such entry and
       falls back to -123648.  `msdelta_multiply.gdb` showed the DLL's t1 has
       negative-preimage entries `(-15872,0),(-11744,4176),(-3392,86584),...`
       that our `rift_multiply` sentinel handling does not generate, so the
       reverse/shift pipeline omits that interval.

    Both need faithful ports of DLL internals (`RiftTable::Multiply` sentinel
    handling and the hint-populating transform stages), not decoder changes.
    The decoder matches the DLL symbol-for-symbol wherever the seed and ORIFT
    are correct.

    **Multiply sentinel investigation (part 39).**  `msdelta_mulout.gdb`
    dumps every RiftTable passed to `RiftTable::Sort` (the output of Multiply).
    The DLL's intermediate tables are t1=95, t2=82, t3=77 entries; ours are
    91/91/91.  The critical missing entry was traced exactly:
    `msdelta_buildrift.gdb` logged `ADD caller=0x2F1C0 104312 -> -158344`
    producing t2[81] = `(104312, -158344)`; after Reverse + shift this becomes
    the DLL's ORIFT `(153856, -158344)` with rift -312200, used at output
    262695.  The DLL generates it from a sentinel branch at VA 0x1002F1AB
    (`sub ecx,[var_3C]; sbb eax,[var_40]`), not from B.left - lastRift(A).
    An empirical negative-preimage rule `B.left - lastRift(A)` added 6 entries
    but NOT this one (missing count stayed 15), so it was reverted; blob 1
    returned to 5858/86120.  A faithful port must reproduce the 32-bit
    half-word arithmetic of the decompiled sentinel block
    (`msdelta.dll.c:24042-24086`), which is the remaining work.

    **Sentinel block ported (part 40).**  `rift_multiply_sentinel()` now
    faithfully implements the decompiled 32-bit half-word branch: GetRift at
    `INT64_MIN + lastRift(A)`, the sentinel `Add`, and the nested loop that
    advances `pos` by `v15+1` and forms `(v47<<32)|pos` entries.  Enabled via
    PA30_SENTINEL.  Result: ORIFT grows 91 -> 93 entries, but the critical
    `(153856, -158344)` is **still missing** (missing count stays 15), and
    decode fails outright with it enabled.  Tracing showed that entry comes
    from `t2[81] = (104312,-158344)` produced by the Multiply **main loop**
    (`msdelta.dll.c:24088-24151`, caller 0x2F1C0), not the sentinel block.
    A faithful port must replace our simplified `rift_multiply` wholesale
    with the decompiled main-loop arithmetic — the sentinel alone is not
    sufficient.  Default remains 5858/307200 wrong with all regressions green.

    **Main-loop port attempted (part 41).**  Translated the decompiled main
    loop (`msdelta.dll.c:24088-24151`) with explicit 32-bit half-word
    arithmetic (GetRift upper bound, carry/borrow tracking, nested entry
    generation), gated by PA30_MULLOOP.  It produces 483 ORIFT entries that
    share none of the DLL's 77 (the critical `(153856,-158344)` is absent),
    so the translation is not faithful — the decompiler's reuse of `v45`,
    `v49[0]` and `v41` across the half-word comparisons makes a mechanical
    port unreliable without instruction-level tracing of each intermediate.
    Reverted to the simplified composition by default; blob 1 stays at
    5858/307200 with all regressions green.  Closing this needs either a
    debugger-driven line-by-line semantic reconstruction of the Multiply
    loop, or a from-scratch derivation of its interval-extension rule from
    the dumped intermediate tables (`msdelta_mulout.gdb`).

    **ORIFT = t2 shifted, no reverse (part 42).**  Comparing the DLL's dumped
    t2 (`mulout6.bin`) with its final ORIFT (`orift_table.bin`) entry by entry
    shows the final table is simply t2's left values + srcLen (no reverse):
    t2 (1056,-264672) -> ORIFT (50600,-264672), (1104,1056) -> (50648,1056),
    (9456,-253200) -> (59000,-253200), (83512,9408) -> (133056,9408),
    (104312,-158344) -> (153856,-158344).  Added a PA30_NOREVERSE switch to
    skip our `rift_reverse`; it produced 91 entries with 76 still missing,
    confirming the gap is in t2 itself: our simplified Multiply omits t2's
    negative-right entries (1056,-264672), (9456,-253200), (104312,-158344),
    which the DLL's main loop generates.  Default path unchanged at
    5858/307200; all regressions green.

    **Multiply combination rule derived (part 43).**  Comparing t1
    (`mulout4.bin`) with t2 (`mulout6.bin`) entry by entry reveals the main
    rule: for each A entry `(l,r)`, Multiply emits `(B.Map(r), l)` — e.g.
    t1 (1024,4096) -> t2 (1024,1024), t1 (1056,4176) -> t2 (1104,1056),
    t1 (9408,86584) -> t2 (83512,9408), t1 (30208,278528) ->
    t2 (273408,30208).  This is the inverse map, consistent with the later
    Reverse step.  `msdelta_buildrift.gdb` shows two distinct Add sites for
    t2 (`this=01063598`): caller 0x2F4F1/0x2F55C emits the normal
    `(B.Map(r), l)` entries, while caller 0x2F164/0x2F1C0 emits the three
    anomalous negative-right entries and the sentinels.  At 0x2F164 the
    assembly computes `right = left - [var_3C:var_40]`, i.e. the anomalous
    right values are A-derived lefts minus a running 64-bit offset — the
    exact offset source is the last untraced piece.  Default stays
    5858/307200 with all regressions green.

    **Offset source traced (part 44).**  The Add site at 0x2F15F belongs to
    `RiftTable::Reverse` (`0x1002EE6C`), not Multiply.  `msdelta_revadd.gdb`
    logged the Add arguments directly: e.g. `left=1056, right=-264672`,
    `left=9456, right=-253200`.  The decompiled `Reverse` shows the rule at
    `msdelta.dll.c:23840`: `Add(out, *entry, *entry - rift)` where `rift` comes
    from `v19 = A[j].right - A[j].left` (line 23754) — i.e. the running offset
    is the **rift of an A (t1) entry**, with the largest value 265728 present
    in t1's last real entry `(37376,303104)`.  So Reverse emits negative-right
    entries `(left, left - rift)` on top of the swapped map, which our
    `rift_reverse()` (plain left/right swap) does not produce.  The precise
    selection of which entries get this treatment is the remaining piece;
    default stays 5858/307200 with all regressions green.

    **Selection rule derived (part 45).**  `msdelta_revsel.gdb` logged all six
    extra adds in this delta: `(left, right, offset)` =
    `(279034,32732,246302)`, `(278768,33562,245206)`,
    `(279348,34334,245014)`, `(279708,34428,245280)`,
    `(1056,-264672,265728)`, `(9456,-253200,262656)` — each satisfies
    `right = left - offset` with offset = a per-entry rift.  The decompiled
    `Reverse` shows the selection via two binary searches over its temp array:
    `v22` = first index with `left >= key` (key = a2 + rift, a2=0 so key=rft),
    `v63` = first index with `left > key2`; then for every entry in
    `[v22+1, v63-1]` it emits `(entry.left, entry.left - rift)`
    (`msdelta.dll.c:23838-23844`).  So an entry gets an extra negative-right
    add exactly when its `left` falls strictly inside a rift interval being
    reversed.  Implementing this range-selection in `rift_reverse()` is the
    last step; default stays 5858/307200 with all regressions green.

    **Pipeline fully traced and ported (part 46).**  msdelta_pipeline.gdb
    broke on every RiftTable::Multiply, Reverse, Sort and
    OffsetRiftTable::Init and dumped each table.  The decompress path is
    **three Multiply calls plus one Reverse**, not the shift we assumed:

      1. `t1  = Multiply(sourceOffsetToRva(6), compressionRiftTable(88))`  -> 95
      2. `t2  = Multiply(t1(95), targetRvaToOffset(6))`                     -> 99
      3. `t2r = Reverse(t2)`                                                -> 82
      4. `t3  = Multiply({srcLen -> 0}(1), Sort(t2r)(82))`                  -> 83
      5. `OffsetRiftTable` input = t3 with `left > 0`, dropping an entry
         whose rift equals the previous entry's                      -> 77

    (The earlier "t2 = 82" label was wrong: 82 is the Reverse output.  The
    `Sort` between Reverse and Multiply #3 matters; feeding the unsorted
    Reverse output collapses the result to one entry.)

    **Multiply port.**  `rift_get_rift` now matches the DLL exactly (when
    `pos` precedes every entry it returns the *last* entry's rift and
    `end = t[0].left - 1`).  The main loop walks each A interval, emitting
    `(left_i, right_i + rift_B)` and then, while
    `(end_i - left) > (endB - pos)`, `(left + (endB-pos) + 1,
    (endB+1) + rift_B(endB+1))`.  The key detail that cost a rewrite: the
    comparison advances from the *previous B position* (`endB+1`), not from
    the previous mapped right.  The sentinel block mirrors the main loop
    downward from `INT64_MIN` using `x = lastRift + INT64_MIN`.

    **Reverse port.**  Literal translation of `msdelta.dll.c:23595-23950`
    with a 4-dword-per-entry pending work list.  Two traps: the second binary
    search advances a `_QWORD*` by 2 (16 bytes, not 8), and the v30/v31
    branch skips the Add when `temp[v63-1].left >= rcursor` (`>=`, not
    `>`).  With both fixed it reproduces the DLL's 82-entry Reverse output
    exactly (verified offline against `tr_srt6`).

    **Result.**  Offline harnesses `diag/multest.c` and
    `diag/reversetest.c` reproduce every intermediate table byte-for-byte
    (95/99/82/83 entries), and the native decoder's ORIFT now matches the
    DLL's `OffsetRiftTable` input exactly (77 entries, including
    `(153856,-158344)`).  blob 1 drops from 5858 to **4379/307200** wrong
    (first divergence 6948); with the DLL's exact seed the residual is the
    known **915/307200** seed-hint-map gap (first divergence 277460).  blob 0,
    d0, d1, PA19, XPRESS, LZX and LZMS all remain byte-exact.

    **Byte-exact blob 1 (part 47).**  With the ORIFT now exact, two decoder
    gaps remained.  (a) A RIFT symbol can span several OffsetRiftTable
    entries: msdelta.dll.c:48253-48311 reselects the entry at every
    boundary (87 = next.left - cpos) and switches source mapping there.
    Freezing the first rift for the whole copy produced 915 wrong bytes;
    chunking the copy at ift[ri].left - cpos reduced that to one.  (b) A
    RIFT symbol stores `-rift` into the distance-history slots
    (`msdelta.dll.c:48252,48392`); leaving `dist = 0` cost the final byte
    (a k=1 history match at output 283783).  With both fixes the decoder is
    byte-exact given the DLL's seed.

    **Seed transform.**  The DLL's per-byte hint map (dumped via
    `diag/msdelta_hint4.gdb` at `MapRva` = RVA `0x35E39`) marks the
    fields that `RiftTransformRelocationsI386Component::TransformInferredRelocations`
    (RVA `0x3B681`, `msdelta.dll.c:36296`) is allowed to rewrite.  Those
    fields are exactly the type-3/type-10 entries of the **source PE's
    relocation directory**; a free-running VA scan rewrites incidental
    4-byte windows (e.g. dwords starting at an `E8` opcode) that the DLL
    leaves alone.  `pa30_reloc_mask` now pins the inferred scan to those
    sites.  The remaining seed stages:

      - `pa30_transform_relocs` rebuilds .reloc: map every entry's RVA
        through the rift table, radix-sort by mapped RVA, regroup blocks by
        mapped page (`msdelta.dll.c:35127-35535`).
      - `pa30_transform_resources` remaps resource-directory OffsetToData
        fields through the same table, keeping `mapped & 0xFFF`.
      - Import-by-ordinal thunks (high bit set) are RVAs-with-flag and must
        not be MapRva'd; the DLL leaves their ordinals alone.

    Result: our computed seed is now byte-identical to the DLL's (0/49544
    differing), and blob 1 decodes with **0/307200 wrong bytes** with no
    external seed.  blob 0, d0, d1, PA19, XPRESS, LZX and LZMS remain exact.

    **Full MSU verification (part 48).**  Extracted
    `windows8.1-kb2959977-x86_...msu` both ways and checked all 513 CIX
    manifest targets against their declared SHA256 and length:

      - default (OS `msdelta.dll` delegation): **513 OK, 0 bad, 0 missing**.
      - `PA30_NO_OS=1` (native only): **334 OK, 3 bad, 176 missing**.

    The three bad native targets are `wucltux.dll`, `wuaueng.dll` and
    `storewuauth.dll` (correct lengths, wrong hashes); all 176 missing ones
    are PA30 targets whose `DeltaApply` fails outright.  So blob 1 being
    byte-exact does **not** generalise to every delta in this MSU: there are
    further format variants in the native decoder.  Keep OS delegation as
    the default for MSU extraction.

    **Native MSU work, part 49 (in progress).**  Debugged the failing deltas
    from KB2959977.  Fixes applied to the native seed transform and decoder:

      - reloc entries are now collected into a dynamically sized array (this
        PE has 6690, the old cap was 4096), and type-3 VA fields are rebased
        explicitly like `ReadRelocationEntries` does instead of relying on
        the inferred scan;
      - relative CALL (E8), near JMP (E9) and 0F 8x conditional jump targets
        are mapped through the RiftTable (`RiftTransformRelativeCalls/
        JmpsI386`);
      - export-directory RVAs (Name, AddressOfFunctions/Names and their
        entries) are mapped;
      - resource directories are walked recursively; Unicode Name offsets
        and subdirectory offsets are remapped by
        `MapRva(base+off) - MapRva(base)`;
      - **nSeg=1 deltas use the explicit CompressionLengths**, not the fixed
        default code.  This was why the small MUI deltas failed at pos 112.

    Results: blob 1 and blob 0 stay byte-exact; `wucltux.dll` and
    `wuaueng.dll` went from 4488 / 535 wrong bytes to 0 / 4.  Full native
    MSU extraction improved from **334 to 362 / 513** byte-exact targets
    (7 bad, 144 missing).  The remaining failures cascade from a few bases
    that are still a handful of bytes off: the DLL's hint map marks more
    positions than our reloc-only mask, so a few false E8 ModRM bytes and
    MOV immediates are still rewritten.  OS delegation remains the default
    and is still 513/513.

    **Native MSU parity achieved (part 50).**  The last seed gaps were:

      - resource-data OffsetToData fields use the same rule as directory
        offsets: `MapRva(resourceBase + offset) - MapRva(resourceBase)`
        (`msdelta.dll.c:38418-38422`).  The used rift table still contains
        the needed rifts, so no unpruned table is required.
      - a COMPFMT with the "default format" bit must keep the fixed Huffman
        lengths even when nSeg=1; we now track `defaultFormat` explicitly
        instead of inferring it from the segment count.  This unblocked the
        chained MUI deltas that decoded to garbage.
      - the byte scans for E8/E9/0F8x must skip a 0xE8/0xE9 that is really
        the disp8 of `8B/8D 45 xx`; otherwise a few false calls inside
        ModRM bytes rewrite neighbouring data.

    Verification: the full KB2959977 MSU now extracts **513/513** byte-exact
    targets with `PA30_NO_OS=1` �X identical to OS delegation.  blob 0/1,
    d0/d1, PA19, XPRESS, LZX and LZMS remain byte-exact.

    **KB5131083 hint-map follow-up (part 51).**  The DLL's hint map marks the
    whole import section (and resource section) as handled; we now set the
    handled bit over .idata too.  The ModRM-disp8 guard was narrowed to
    apply only when the following byte is not itself a call/jump opcode:
    the DLL relies on hint bits rather than opcode guards, and the broad
    guard was skipping real rewrite sites.

    Result: KB2959977 stays 513/513, KB5131083 improves from 201 to
    **203/209** byte-exact targets with no crash.  Six targets remain wrong;
    their seeds differ at a few relative-operand positions where the DLL's
    hint bits come from stages we still haven't identified.


    **Full Windows 10 parity (part 52).**  Reading the DLL's hint pipeline
    directly closed the rest of the KB5131083 gap:

      - MarkNonExeComponent::Transform (msdelta.dll.c:42457) marks every
        non-executable section plus SizeOfHeaders as handled.  We added the
        matching pa30_mark_nonexe stage; this alone fixed poqexec.exe,
        cbscore.dll, tiworker.exe, wrpint.dll and cntrtextinstaller.dll.
        The DLL also memsets each data directory by RVA, but reproducing
        that regressed real deltas, so it is deliberately omitted.
      - the offset-rift table must be built even when the pre blob carries
        no rifts: ift_multiply treats an empty table as identity, so the
        source PE section map alone still yields the DLL's table.  The
        previous if (n0 && rt && rn) guard left globalinstallorder.xml
        with an identity map, so a 0x54000 match copied "alue\0\0\0\0"
        instead of "Component".  Removing the guard fixed the last target.

    Verification: KB5131083 **209/209** and KB2959977 **513/513** native,
    both byte-exact against OS delegation.  blob 0/1, d0/d1, PA19, XPRESS,
    LZX and LZMS all remain byte-exact.  OS delegation is still the default;
    the native path is opt-in via PA30_NO_OS=1.
