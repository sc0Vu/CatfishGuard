#!/usr/bin/env python3
"""Generate icons/icon{16,48,128}.png — a shield with an "!" mark.

Standard library only (zlib + struct); 4x4 supersampling for anti-aliasing.
Usage: python3 tools/mk_icons.py
"""
import os
import struct
import zlib

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'icons')
SHIELD = (10, 102, 194)   # LinkedIn-adjacent blue
MARK = (255, 255, 255)
SS = 4


def inside_shield(x, y):
    """Unit-square coords (0..1). Flat top, straight sides, curved point."""
    if y < 0.08 or y > 0.94:
        return False
    if y <= 0.52:
        return 0.14 <= x <= 0.86
    # lower half narrows to a point at (0.5, 0.94) along a soft curve
    t = (y - 0.52) / 0.42
    half = 0.36 * (1 - t ** 1.6)
    return abs(x - 0.5) <= half


def inside_mark(x, y):
    """A bold '!' — 'look closer', not a verdict."""
    if 0.44 <= x <= 0.56 and 0.22 <= y <= 0.58:
        return True
    return (x - 0.5) ** 2 + (y - 0.70) ** 2 <= 0.065 ** 2


def render(size):
    rows = []
    for py in range(size):
        row = bytearray([0])  # filter type 0
        for px in range(size):
            shield = mark = 0
            for sy in range(SS):
                for sx in range(SS):
                    x = (px + (sx + 0.5) / SS) / size
                    y = (py + (sy + 0.5) / SS) / size
                    if inside_shield(x, y):
                        shield += 1
                        if inside_mark(x, y):
                            mark += 1
            n = SS * SS
            a = shield / n
            if shield:
                m = mark / shield
                rgb = [round(SHIELD[i] * (1 - m) + MARK[i] * m) for i in range(3)]
            else:
                rgb = [0, 0, 0]
            row += bytes(rgb + [round(a * 255)])
        rows.append(bytes(row))
    raw = b''.join(rows)

    def chunk(tag, data):
        c = struct.pack('>I', len(data)) + tag + data
        return c + struct.pack('>I', zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0)
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', ihdr) +
            chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b''))


if __name__ == '__main__':
    os.makedirs(OUT, exist_ok=True)
    for s in (16, 48, 128):
        with open(os.path.join(OUT, 'icon%d.png' % s), 'wb') as f:
            f.write(render(s))
        print('wrote icon%d.png' % s)
