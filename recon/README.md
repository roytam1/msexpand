# C89 reconstruction of the modern `expand.exe`

This directory contains a from-scratch C89 reimplementation of the supplied
Windows 10-era `expand.exe`, built with **Microsoft Visual C++ 6.0**.

The reconstruction is driven by the IDA/Hex-Rays materials in the parent
directory (`expand.exe.c/.lst`, `cabinet.dll.c/.lst`, `dpx.dll.c/.lst`).
It is a *functional core* reconstruction: the original control flow,
messages, argument rules and exit codes are preserved, while the C++
template/COM/ETW/MUI machinery of the modern binary is folded into plain C.

## Build

```
cd \\roy-xp\c\devel\cabarc\recon
build.bat
```

`build.bat` calls `VCVARS32.BAT`, compiles all sources with `cl /ML /W3`
in C mode and links `expand_recon.exe`. No SDK `fdi.h`/`cabinet.lib` is
needed ??the CAB reader is compiled into the EXE.

## Source map

| File | Reconstructs |
|------|--------------|
| `src/expand.c` | `main`, `ParseArguments`, `CheckArguments`, `GetNextFileArg`, `ProcessNotification`, path helpers |
| `src/messages.c` | The RT_STRING message table (hardcoded English text) and `DisplayErrorMessage`/`PrintMsg` |
| `src/lz.c` | `InitGlobalBuffers`, `GetHdr`, `IsCompressed`, `Expand`/`ExpandOrCopyFile`, `LZDecode` (SZDD token stream) |
| `src/cab.c` | FDI/CAB path: `CabIsCabinet`, cabinet header/folder/file parsing, MSZIP and LZX folder decompression, selected-file extraction |
| `src/sfx.c` | Windows Update SFX detection, embedded-CAB carving and manifest-driven patch application |
| `src/dpx.c` | `DpxExpandFile`, `EnumerateFilesToExtract`, `AddFilesToExtract`, `ProcessDpxNotification` semantics |
| `src/util.c` | Wide/ANSI conversion, path joining, `PatternMatch`, parent-directory creation |
| `src/xml.c` | Minimal UTF-8 XML DOM parser for CIX manifests |
| `src/cix.c` | CIX target/source/hash model and CRC32 verification |
| `src/psf.c` | PSTREAM container reader (Phase A: RAW targets) |
| `src/hash.c` | CRC32 and hexadecimal blob decoding |
| `src/xpress.c` | XPRESS and XPRESS-HUFF raw decompression (ported from go-ntfs) |
| `src/lzms.c` | LZMS raw/chunk decompression (ported from wimlib, LGPL-2.1+) |
| `test_lzms.c` / `test_lzms.bat` | Generates vectors with the OS compressor and runs the LZMS tests |
| `test_xpress.c` / `test_xpress.bat` | Runs the 40 go-ntfs XPRESS vectors |
| `test_sfx.bat` | Unpacks the IE6 SP1 hotfix SFX natively and compares all patched binaries with the SFX-run outputs |

## What is implemented

* Exact banner, help, error and progress messages, recovered **verbatim**
  from the RT_STRING resources of the supplied `expand.exe` (IDs 1??0).
* Full `-R`, `-I`, `-?`, `-D`, `-F:` option handling plus the hidden
  `-K:` / `-E:` switches, with the original argument-count / target-directory
  rules and exit codes.
* Classic `SZDD` LZ expansion (14-byte header including the `88 F0 27 33`
  magic, 8-tokens-per-control-byte stream, 4096-byte ring dictionary) and
  raw file copying, including the expansion-name restoration and the
  `bytes expanded to ... % increase` summaries.
* Cabinet expansion: CFHEADER/CFFOLDER/CFFILE/CFDATA parsing, uncompressed,
  **MSZIP** (raw DEFLATE: stored, fixed and dynamic Huffman) and **LZX**
  folders, `-D` listing, `-F:` selective extraction, multi-file cabinets,
  and the original DPX-style progress messages.
* **Windows Update SFX packages:** when the input carries an embedded CAB
  with `_sfx_manifest_` and/or `_sfx_.dll`, the CAB is carved out, extracted
  and the manifest's `[Deltas]` are applied with `DeltaApply()`, so patched
  binaries are written directly. `PA19_NO_OS=1` forces the native decoder.
* **PSTREAM/PSF containers (Phase A):** 48-byte header parsing, UTF-8 CIX
  XML index, `-D` listing, `-F:` selection, RAW source ranges, CRC32
  verification, and creation of nested output directories. Tested with the
  hand-built `testdata/psf/sample.psf` fixture.
* **XPRESS / XPRESS-HUFF (Phase B):** complete C89 port of both MS-XCA
  decoders. All 40 vectors from `go-ntfs/parser/xpress_test_data.go` pass
  (`test_xpress.bat`). CIX `algId` values 3 (XPRESS) and 4 (XPRESS-HUFF)
  are honoured on PSF targets; verified with `testdata/psf/xpress_00.psf`
  and `xpress_39.psf`.
* **LZMS (Phase D):** C89 port of wimlib's raw LZMS decoder (range coder,
  adaptive Huffman codes, LZ/delta matches, x86 filter) plus dpx's chunk
  framing and a verbatim fallback for incompressible blocks. All 6
  OS-generated vectors pass (`test_lzms.bat`); `algId` 5 is verified with
  `testdata/psf/lzms.psf`. `ref_lzms/` holds an independent wimlib oracle.

## Known limitations (outside the agreed functional core)

* **PA30 deltas (Phase C):** C89 port of the compo decompressor ??IntFormat,
  RiftTable, CompositeFormat, CompressionLengths, ReadSymbol and the
  Decompress loop. Both generated vectors decode byte-identically and a
  PSF with a PA30 delta target extracts correctly. PA19 decoding is byte-exact both via the OS `mspatcha.dll` (the same delegation the original expand.exe uses) and natively in `src/mslzx.c`; set `PA19_NO_OS=1` to exercise the native path. See `DPX_REQUIREMENTS.md`.
* Remaining DPX features: CIX manifests
  inside CABs. Building a PSF requires the
  `job.xml` / CIX machinery of `dpx.dll`, which is far beyond the core.
* Cabinet compression types other than 0 (none), 1 (MSZIP) and 3 (LZX)
  ??Quantum, LZMS ??are reported as `Unrecognized compression scheme`.
* Split/spanned cabinets and the `-K:` / `-E:` encryption path are not
  implemented.
* MUI localisation, ETW tracing and the asynchronous progress thread are
  omitted (hardcoded English messages, synchronous extraction).

## Validation

`testdata/` contains fixtures and a differential harness was used to
compare the reconstruction against the original `expand.exe` on many
cases (help, argument errors, LZ expansion, raw copy, single/multi-file
CAB listing and extraction, large MSZIP cabinets, wildcard patterns).
All compared cases produced identical console output, exit codes, and
byte-identical extracted files.


