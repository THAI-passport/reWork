#!/usr/bin/env python3
"""Identify a CRC by trying a catalogue of common parameter sets (stdlib only).

    python tools/crcfind.py --data 0102030405 --crc 6f91      # which known CRC maps data to crc?
    python tools/crcfind.py --list                            # catalogue with check values of "123456789"
    python tools/crcfind.py --data 313233343536373839 --crc 29b1 --width 16

Also tries the byte-swapped value and plain additive/XOR checksums. Give several --data/--crc pairs by repeating both flags in order
to cut false positives. A match on one short sample is a hint, not proof: confirm on at least three frames.
"""
import argparse
import sys

# name: (width, poly, init, refin, refout, xorout, check of b"123456789")
CATALOG = {
    "CRC-8":            (8, 0x07, 0x00, False, False, 0x00, 0xF4),
    "CRC-8/MAXIM":      (8, 0x31, 0x00, True, True, 0x00, 0xA1),
    "CRC-8/ROHC":       (8, 0x07, 0xFF, True, True, 0x00, 0xD0),
    "CRC-16/CCITT-FALSE": (16, 0x1021, 0xFFFF, False, False, 0x0000, 0x29B1),
    "CRC-16/XMODEM":    (16, 0x1021, 0x0000, False, False, 0x0000, 0x31C3),
    "CRC-16/KERMIT":    (16, 0x1021, 0x0000, True, True, 0x0000, 0x2189),
    "CRC-16/X-25":      (16, 0x1021, 0xFFFF, True, True, 0xFFFF, 0x906E),
    "CRC-16/GENIBUS":   (16, 0x1021, 0xFFFF, False, False, 0xFFFF, 0xD64E),
    "CRC-16/ARC":       (16, 0x8005, 0x0000, True, True, 0x0000, 0xBB3D),
    "CRC-16/MODBUS":    (16, 0x8005, 0xFFFF, True, True, 0x0000, 0x4B37),
    "CRC-16/USB":       (16, 0x8005, 0xFFFF, True, True, 0xFFFF, 0xB4C8),
    "CRC-16/BUYPASS":   (16, 0x8005, 0x0000, False, False, 0x0000, 0xFEE8),
    "CRC-16/DNP":       (16, 0x3D65, 0x0000, True, True, 0xFFFF, 0xEA82),
    "CRC-16/AUG-CCITT": (16, 0x1021, 0x1D0F, False, False, 0x0000, 0xE5CC),
    "CRC-32":           (32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF, 0xCBF43926),
    "CRC-32C":          (32, 0x1EDC6F41, 0xFFFFFFFF, True, True, 0xFFFFFFFF, 0xE3069283),
    "CRC-32/BZIP2":     (32, 0x04C11DB7, 0xFFFFFFFF, False, False, 0xFFFFFFFF, 0xFC891918),
    "CRC-32/MPEG-2":    (32, 0x04C11DB7, 0xFFFFFFFF, False, False, 0x00000000, 0x0376E6E7),
}


def _reflect(v, bits):
    r = 0
    for _ in range(bits):
        r = (r << 1) | (v & 1)
        v >>= 1
    return r


def crc(data, width, poly, init, refin, refout, xorout):
    top, mask = 1 << (width - 1), (1 << width) - 1
    reg = init
    for b in data:
        if refin:
            b = _reflect(b, 8)
        reg ^= b << (width - 8)
        for _ in range(8):
            reg = ((reg << 1) ^ poly) & mask if reg & top else (reg << 1) & mask
    if refout:
        reg = _reflect(reg, width)
    return reg ^ xorout


def candidates(pairs, width=None):
    found = []
    for name, (w, poly, init, ri, ro, xo, _chk) in CATALOG.items():
        if width and w != width:
            continue
        for label, fn in (("", lambda v: v), (" (byte-swapped)", lambda v, w=w: int.from_bytes(v.to_bytes(w // 8, "big"), "little"))):
            if all(fn(crc(d, w, poly, init, ri, ro, xo)) == c for d, c in pairs):
                found.append(name + label)
    if all(sum(d) & 0xFF == c for d, c in pairs):
        found.append("sum8")
    if all((-sum(d)) & 0xFF == c for d, c in pairs):
        found.append("two's complement sum8")
    x = []
    for d, c in pairs:
        v = 0
        for b in d:
            v ^= b
        x.append(v == c)
    if all(x):
        found.append("xor8")
    return found


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", action="append", default=[], help="hex bytes covered by the checksum")
    ap.add_argument("--crc", action="append", default=[], help="observed checksum, hex")
    ap.add_argument("--width", type=int, choices=(8, 16, 32))
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args(argv)
    if a.list:
        for name, p in CATALOG.items():
            got = crc(b"123456789", *p[:6])
            print("%-20s width=%-2d check=%0*X %s" % (name, p[0], p[0] // 4, got, "ok" if got == p[6] else "CATALOGUE MISMATCH"))
        return 0
    if not a.data or len(a.data) != len(a.crc):
        ap.error("give --data and --crc the same number of times")
    pairs = [(bytes.fromhex(d), int(c, 16)) for d, c in zip(a.data, a.crc)]
    found = candidates(pairs, a.width)
    print("\n".join(found) if found else "no catalogue match (custom polynomial, extra bytes covered, or different byte order)")
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
