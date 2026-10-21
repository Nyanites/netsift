#!/usr/bin/env python3
"""Draws the NetSift app icon (assets/icon.png, 256x256 RGBA) without any dependencies.

Packets flow in three streams into a sieve; one gold packet is sifted out.
Usage: python3 scripts/make-icon.py [output.png] [size]
"""
import math
import struct
import sys
import zlib

SIZE = int(sys.argv[2]) if len(sys.argv) > 2 else 256
OUT = sys.argv[1] if len(sys.argv) > 1 else "assets/icon.png"
SS = 4  # supersamples per axis

# Layout in unit coordinates (0..1).
X0, X1, Y0, Y1, R = 0.055, 0.945, 0.055, 0.945, 0.21


def hexc(h):
    return tuple(int(h[i:i + 2], 16) for i in (1, 3, 5))


BG_TOP, BG_BOTTOM = hexc("#0b1f46"), hexc("#0f5363")
STREAMS = [(0.235, hexc("#7aa2ff"), 0.0), (0.325, hexc("#4cc9f0"), 0.33), (0.415, hexc("#38d6b4"), 0.66)]
SIEVE, SLOT, GOLD = hexc("#eef2f8"), hexc("#1a3d63"), hexc("#f6c344")


def in_round_rect(x, y):
    if x < X0 or x > X1 or y < Y0 or y > Y1:
        return False
    cx = min(max(x, X0 + R), X1 - R)
    cy = min(max(y, Y0 + R), Y1 - R)
    return (x - cx) ** 2 + (y - cy) ** 2 <= R * R


def stream_y(base, phase, x):
    return base + 0.03 * math.sin(2 * math.pi * (x * 1.15 + phase))


# Packet dots along each stream, thinning out as they near the sieve.
DOTS = []
for base, color, phase in STREAMS:
    x = 0.1 + phase * 0.05
    while x < 0.92:
        DOTS.append((x, stream_y(base, phase, x), 0.024, color))
        x += 0.092


def in_funnel(x, y):
    """Funnel: trapezoid from y=0.50 (wide) to y=0.70 (narrow), then a spout."""
    if 0.50 <= y <= 0.70:
        t = (y - 0.50) / 0.20
        half = 0.30 * (1 - t) + 0.065 * t
        return abs(x - 0.5) <= half
    if 0.70 < y <= 0.77:
        return abs(x - 0.5) <= 0.065
    return False


def in_slot(x, y):
    """Dark slits across the funnel: the sieve mesh."""
    for sy in (0.555, 0.615, 0.67):
        if abs(y - sy) <= 0.011:
            t = (sy - 0.50) / 0.20
            half = 0.30 * (1 - t) + 0.065 * t - 0.045
            return abs(x - 0.5) <= half
    return False


def shade(x, y):
    """Colour of the icon at unit point (x, y), or None outside it."""
    if not in_round_rect(x, y):
        return None
    t = (y - Y0) / (Y1 - Y0)
    col = tuple(BG_TOP[i] * (1 - t) + BG_BOTTOM[i] * t for i in range(3))
    # Faint stream lines behind the packets.
    for base, color, phase in STREAMS:
        if abs(y - stream_y(base, phase, x)) <= 0.006:
            col = tuple(col[i] * 0.55 + color[i] * 0.45 for i in range(3))
    for dx, dy, r, color in DOTS:
        if (x - dx) ** 2 + (y - dy) ** 2 <= r * r:
            col = color
    if in_funnel(x, y):
        col = SLOT if in_slot(x, y) else SIEVE
    if (x - 0.5) ** 2 + (y - 0.855) ** 2 <= 0.042 ** 2:
        col = GOLD
    return col


rows = []
for py in range(SIZE):
    row = bytearray([0])  # PNG filter type: none
    for px in range(SIZE):
        acc = [0.0, 0.0, 0.0]
        cover = 0
        for sy in range(SS):
            for sx in range(SS):
                c = shade((px + (sx + 0.5) / SS) / SIZE, (py + (sy + 0.5) / SS) / SIZE)
                if c is not None:
                    cover += 1
                    for i in range(3):
                        acc[i] += c[i]
        if cover:
            row += bytes(int(round(acc[i] / cover)) for i in range(3)) + bytes([round(255 * cover / SS ** 2)])
        else:
            row += b"\0\0\0\0"
    rows.append(bytes(row))


def chunk(kind, data):
    c = kind + data
    return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)


png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0))
png += chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b"")
with open(OUT, "wb") as f:
    f.write(png)
print(OUT, SIZE)
