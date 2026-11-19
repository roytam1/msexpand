# PA30 compo patch-stream format (research notes)

These notes are the implementation map for finishing PA30 delta support in
`recon/src/delta.c`. They were derived from `msdelta.dll.c` / `.lst`.

## Container / header (IMPLEMENTED in delta.c)

```
PA30[4] | FILETIME[8] | bitstream(3-bit leader skipped):
  version   = read_int()
  code      = read_int()      # 1 = RAW, 2/4/8 = PE machine types
  flags     = read_int()
  targetSize= read_int()
  hashAlg   = read_int()
  hash      = read_blob()     # int length, byte-align, bytes
  preBlob   = read_blob()     # empty for RAW containers
  patchBlob = read_blob()
```

`read_int()` = nibble-coded unary: `n` zero bits, one 1 bit, then `4n+4`
payload bits (n<8), else 32 bits + discard `4n-28`.
`read_blob()` = `read_int()` length, byte-align, raw bytes.

Both generated vectors: version=1, code=1, flags=0, hash empty, pre empty,
patch 15 bytes (9000-byte target) / 301 bytes (4096-byte target).

## Patch blob bitstream (partially implemented)

Opened as a new bit reader (3-bit leader skipped), then:

1. **RiftTable** — `[1 bit empty flag]`, if 1:
   - `IntFormat` #1 (inline), `IntFormat` #2 (inline)
   - `n = read_int()` entries
   - for each: `left += if_read_number(fmt1)`, `rift += if_read_number(fmt2)`,
     entry = `(left, left + rift)`; **both accumulators persist across entries**.
   - sort by `left`.
2. **CompositeFormat** — `[1 bit default flag]`; if 0:
   - `nSeg = read_int()`, boundaries are cumulative `read_int()` deltas
   - 39 × 4-bit meta-code lengths, build 39-symbol canonical Huffman
   - per segment `CompressionLengths::Read()` (872 code lengths using
     meta-Huffman run-length symbols: 0..16 literal, 17..22 delta, ≥23 copy)
   - if flag is 1: default format = one segment, boundary 0, all lengths 0.
3. **Compressed data** — symbol stream decoded by `CompressionFormat::ReadSymbol`.

Both vectors parse as: empty rift table, default composite format.

## IntFormat (IMPLEMENTED in delta.c)

```
n1 = read_bits(8); n2 = read_bits(8); run = read_bits(8)
small_len[0..n1-1] = read_bits(4)+1
base = read_bits(4)+1
big_len[0..n2-1] = read_bits(4)+1
fill small_len[n1..125] and big_len[n2..125] with base,
decrementing base every `run` symbols (reload run per fill loop)
=> 252 canonical Huffman code lengths
```

`if_read_number`: canonical decode -> symbol s; consume len[s];
neg = (s >= 126); if neg s -= 126;
if s >= 4: `v = (((s&1)+2) << ((s>>1)-1)) | read_bits((s>>1)-1)` else `v = s`;
return `neg ? ~v : v`.

## Decompress (NOT IMPLEMENTED)

`Decompress::InternalProcess` (assembly `.lst:60824-61570`) loops:
- choose `CompressionFormat` for current output position (segment boundaries)
- `sym = ReadSymbol(format, bitreader)`
  - literal (`s < 0x100`): write byte
  - distance `0x54000`: rift-table match — map target pos to source via rift,
    copy bytes (bounded by rift interval/chunk/buffer end)
  - `0x54001..0x54003`: repeat matches using last-3 distance history
  - otherwise: `distance = sym - 0x54003`, LZ copy with overlap
- continue until targetSize bytes produced.

`CompressionFormat::ReadSymbol` (`msdelta.dll.c:25079-25240`): main Huffman
over 0x258 symbols; `k=(s-256)>>3`, low 3 bits pick length table;
k<3 => raw 14/16/18-bit distance with wrap; k>=3 => secondary Huffman length.

## Effort remaining

Roughly 1,500–2,500 more lines of careful C89: `CompressionLengths::Read`
(872 lengths, 39-symbol meta Huffman + run codes), canonical Huffman table
builder shared with `IntFormat`, `CompressionFormat::ReadSymbol`, `OffsetRiftTable`
lookup, and the decompress loop including repeat distances and the default-format
special case. This is the last blocker for PA30 apply.

For PA19 (`delta.c` has a spec-based but unvalidated applier) there is no
public patch-creation API in `mspatcha.dll`, so generating a test vector
requires either a real-world PA19 patch or writing a patch encoder.
