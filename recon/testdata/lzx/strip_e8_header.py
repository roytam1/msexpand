#!/usr/bin/env python3
"""Strip the CAB LZX one-time E8 header bit (and optional 32-bit filesize)
from a raw CAB LZX payload, producing a wimlib-format raw block bitstream."""
import sys

src, dst = sys.argv[1], sys.argv[2]
b = open(src, 'rb').read()
bits = []
for k in range(len(b) // 2):
    u = b[2 * k] | (b[2 * k + 1] << 8)
    for i in range(15, -1, -1):
        bits.append((u >> i) & 1)

flag = bits[0]
skip = 1 + (32 if flag else 0)
rest = bits[skip:]

nb = (len(rest) + 15) // 16
out = bytearray(2 * nb)
for i, bit in enumerate(rest):
    unit, pos = divmod(i, 16)
    if pos < 8:
        out[2 * unit + 1] |= bit << (7 - pos)
    else:
        out[2 * unit] |= bit << (15 - pos)
open(dst, 'wb').write(bytes(out))
print('e8flag=%d skipped=%d bits in=%d out=%d bytes' %
      (flag, skip, len(bits), len(out)))
