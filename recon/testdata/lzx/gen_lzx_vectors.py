#!/usr/bin/env python3
"""Generate synthetic RAW LZX block bitstreams for differential testing.

Bit order matches wimlib's input_bitstream: bytes are read as little-endian
16-bit units and bits are consumed MSB-first from each unit.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))


class BW:
    def __init__(self):
        self.bits = []

    def w(self, val, n):
        for i in range(n - 1, -1, -1):
            self.bits.append((val >> i) & 1)

    def bytes(self):
        n = (len(self.bits) + 15) // 16
        out = bytearray(2 * n)
        for i, bit in enumerate(self.bits):
            unit, pos = divmod(i, 16)
            if pos < 8:
                out[2 * unit + 1] |= bit << (7 - pos)
            else:
                out[2 * unit] |= bit << (15 - pos)
        return bytes(out)


def canonical(lens):
    """Return canonical code (codeword,length) for each symbol with lens[s]>0."""
    maxlen = max(lens) if lens else 0
    counts = [0] * (maxlen + 1)
    for l in lens:
        if l:
            counts[l] += 1
    codes = [None] * len(lens)
    nxt = [0] * (maxlen + 2)
    c = 0
    for l in range(1, maxlen + 1):
        c = (c + counts[l - 1]) << 1
        nxt[l] = c
    for s, l in enumerate(lens):
        if l:
            codes[s] = (nxt[l], l)
            nxt[l] += 1
    return codes


def build_precode(needed):
    """Build a complete precode covering the given presym set."""
    syms = sorted(needed)
    n = 2
    while n < len(syms):
        n <<= 1
    # Pad with unused presyms (not emitted) to reach a power of two.
    cand = list(range(20))
    for s in syms:
        cand.remove(s)
    syms = syms + cand[:n - len(syms)]
    length = n.bit_length() - 1
    lens = [0] * 20
    for s in syms:
        lens[s] = length
    codes = canonical(lens)
    return lens, codes


def encode_lens(lens, bw):
    """Emit codeword lengths using the precode built from emitted presyms."""
    needed = set()

    # First pass: find which presyms will be used.  The decoder computes
    # new_len = (old_len_at_this_index - presym) mod 17; the buffer starts
    # as all zeros, so presym = (-target) mod 17.
    i = 0
    seq = []
    while i < len(lens):
        t = lens[i]
        if t == 0:
            run = 0
            while i + run < len(lens) and lens[i + run] == 0:
                run += 1
            if run >= 20:
                take = min(run, 51)
                needed.add(18)
                seq.append(('rle', take - 20))
                i += take
                continue
        ps = (-t) % 17
        needed.add(ps)
        seq.append(('sym', ps, t))
        i += 1

    pre_lens, pre_codes = build_precode(needed)
    for v in pre_lens:
        bw.w(v, 4)               # PRECODE_ELEMENT_SIZE == 4
    for item in seq:
        if item[0] == 'rle':
            bw.w(*pre_codes[18])
            bw.w(item[1], 5)
        else:
            bw.w(*pre_codes[item[1]])
    return pre_lens


def emit_lens_call(bw, lens):
    return encode_lens(lens, bw)


def make_vector(block_type, block_size, main_lens, data_symbols,
                len_lens=None, aligned_lens=None, extra_after=None):
    bw = BW()
    bw.w(block_type, 3)
    bw.w(0, 1)                   # explicit block size
    bw.w(block_size, 16)         # windowBits == 15 => no extra 8 bits

    if block_type in (1, 2):
        if block_type == 2:
            for v in aligned_lens:
                bw.w(v, 3)       # ALIGNEDCODE_ELEMENT_SIZE == 3
        emit_lens_call(bw, main_lens[:256])
        emit_lens_call(bw, main_lens[256:496])   # windowBits 15 => 496 main syms
        emit_lens_call(bw, len_lens if len_lens is not None else [0] * 249)
        codes = canonical(main_lens)
        for sym, extra_bits in data_symbols:
            bw.w(*codes[sym])
            for val, nbits in extra_bits:
                bw.w(val, nbits)
    return bw.bytes()


def write(name, comp, expected):
    with open(os.path.join(HERE, name), 'wb') as f:
        f.write(comp)
    with open(os.path.join(HERE, name.replace('.bin', '_expected.bin')), 'wb') as f:
        f.write(expected)


# ---- Vector 1: literals only, 2-symbol main code -------------------------
main1 = [0] * 656
main1[0x41] = 1
main1[0x42] = 1
data1 = [(0x41, []), (0x42, []), (0x41, []), (0x42, []),
         (0x41, []), (0x42, []), (0x41, []), (0x42, [])]
write('v1_literals.bin', make_vector(1, 8, main1, data1), b'ABABABAB')

# ---- Vector 2: literals + one match (explicit offset slot 5, len hdr 6) --
main2 = [0] * 656
for s in (0x41, 0x42, 0x43, 0x44, 0x50, 0x51, 0x52):
    main2[s] = 3
match_sym = 256 + 6 + 5 * 8     # len header 6 (=> length 8), slot 5 (=> off 4)
main2[match_sym] = 3
data2 = [(0x41, []), (0x42, []), (0x43, []), (0x44, []),
         (match_sym, [(0, 1)])]  # 1 extra offset bit, value 0 => offset 4
write('v2_match.bin', make_vector(1, 12, main2, data2), b'ABCDABCDABCD')

# ---- Vector 3: uncompressed (verbatim-data) block, no E8 bytes -----------
def make_uncompressed(data):
    bw = BW()
    bw.w(3, 3)                   # block type 3
    bw.w(0, 1)                   # explicit size
    bw.w(len(data), 16)
    while len(bw.bits) % 16:     # align to 16-bit unit
        bw.w(0, 1)
    head = bytearray(bw.bytes())
    for off in (1, 1, 1):        # recent offsets, 32-bit little endian
        head += off.to_bytes(4, 'little')
    head += data
    if len(data) & 1:
        head += b'\x00'           # pad byte after odd-sized block
    return bytes(head)

data3 = b'Hello LZX world!'      # 16 bytes, no 0xE8 -> E8 filter is a no-op
write('v3_uncompressed.bin', make_uncompressed(data3), data3)

# ---- Vector 4: aligned block, explicit offset slot 8 ---------------------
main4 = [0] * 656
for s in range(0x41, 0x51):      # A..P (16 literals)
    main4[s] = 5
match4 = 256 + 6 + 8 * 8         # len header 6 => length 8, slot 8 => base 14
main4[match4] = 1
aligned4 = [0] * 8
aligned4[0] = 1
aligned4[1] = 1
data4 = [(s, []) for s in range(0x41, 0x51)] + [(match4, [(0, 1)])]   # 1 zero bit = aligned sym 0 code '0'
comp4 = make_vector(2, 24, main4, data4, aligned_lens=aligned4)
write('v4_aligned.bin', comp4, b'ABCDEFGHIJKLMNOPCDEFGHIJ')

print('generated v1..v4')
