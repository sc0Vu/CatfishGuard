#!/usr/bin/env python3
"""Generate icons/icon{16,48,128}.png — a shield with a fish ("catfish") on it.

Standard library only (zlib + struct); 4x4 supersampling for anti-aliasing.
Usage: python3 tools/mk_icons.py
"""
import os
import struct
import zlib

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'icons')
# Teal, deliberately NOT LinkedIn's blue (#0A66C2): the extension must not look
# like a LinkedIn product.
SHIELD = (13, 116, 102)
MARK = (255, 255, 255)
# Chrome Web Store guidance: 128px icon = 96px artwork + 16px transparent padding.
# Toolbar sizes use the full square so the shape stays legible.
PAD = {16: 0.0, 48: 0.04, 128: 0.125}
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
    """A fish facing left: oval body, forked tail, an eye cut out."""
    cx, cy, rx, ry = 0.44, 0.46, 0.22, 0.135
    eye = (x - 0.33) ** 2 + (y - 0.43) ** 2 <= 0.032 ** 2
    body = ((x - cx) / rx) ** 2 + ((y - cy) / ry) ** 2 <= 1
    # tail: a triangle from the body's back to a notched fan
    tail = False
    if 0.60 <= x <= 0.80:
        spread = 0.04 + (x - 0.60) * 0.75          # widens toward the end
        notch = max(0.0, (x - 0.72)) * 1.4         # fork in the middle
        d = abs(y - cy)
        tail = notch <= d <= spread
    # catfish barbels: two strokes sweeping forward from the mouth
    def stroke(x0, y0, x1, y1, w=0.02):
        vx, vy = x1 - x0, y1 - y0
        t = max(0.0, min(1.0, ((x - x0) * vx + (y - y0) * vy) / (vx * vx + vy * vy)))
        return (x - x0 - t * vx) ** 2 + (y - y0 - t * vy) ** 2 <= w * w
    whiskers = stroke(0.24, 0.45, 0.11, 0.37) or stroke(0.24, 0.49, 0.11, 0.58)
    return (body and not eye) or tail or whiskers


def render(size):
    pad = PAD.get(size, 0.0)
    scale = 1 - 2 * pad
    rows = []
    for py in range(size):
        row = bytearray([0])  # filter type 0
        for px in range(size):
            shield = mark = 0
            for sy in range(SS):
                for sx in range(SS):
                    x = ((px + (sx + 0.5) / SS) / size - pad) / scale
                    y = ((py + (sy + 0.5) / SS) / size - pad) / scale
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
