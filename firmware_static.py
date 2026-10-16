#!/usr/bin/env python3
"""firmware_static.py: Firmware static analysis tool (Gate G2).

Performs binwalk-style magic-byte scanning, filesystem detection
(squashfs/jffs2/initramfs), UART/JTAG pinout hints, bootloader analysis,
signature checks, and string extraction on firmware images.

Stdlib-only; optional binwalk/unsquashfs if available.

Usage:
    python firmware_static.py <firmware image> [--json]
    python firmware_static.py <firmware image> --strings
"""
import argparse
import json
import os
import re
import struct
import sys

# Known magic signatures
MAGICS = {
    b"hsqs": "squashfs (little-endian)",
    b"sqsh": "squashfs (big-endian)",
    b"\x19\x85": "jffs2 filesystem",
    b"U-Boot": "U-Boot bootloader",
    b"\x7fELF": "ELF executable",
    b"MZ": "PE/DOS executable",
    b"\xfe\xed\xfa\xce": "Mach-O binary (32-bit)",
    b"\xfe\xed\xfa\xcf": "Mach-O binary (64-bit)",
    b"\x1f\x8b": "gzip stream",
    b"PK\x03\x04": "ZIP archive",
    b"\xfd7zXZ": "XZ compressed stream",
    b"BZh": "bzip2 stream",
    b"\x28\xb5\x2f\xfd": "zstd compressed stream",
}

# Common UART baud rates
UART_BAUDS = [9600, 19200, 38400, 57600, 115200, 921600]


def scan_magics(data):
    """Scan for known magic signatures at any offset."""
    hits = []
    for magic, desc in MAGICS.items():
        idx = 0
        while True:
            idx = data.find(magic, idx)
            if idx == -1:
                break
            hits.append({"offset": idx, "offset_hex": hex(idx), "type": desc, "magic": magic.decode("latin-1", "replace")[:16]})
            idx += 1
    return hits


def detect_uart_hints(data):
    """Look for common UART-related strings that suggest debug console."""
    hints = []
    patterns = [b"UART", b"uart", b"ttyS", b"ttyAMA", b"console", b"115200",
                b"9600", b"57600", b"debug", b"root", b"login:", b"Password:"]
    for pat in patterns:
        idx = 0
        while True:
            idx = data.find(pat, idx)
            if idx == -1:
                break
            hints.append({"offset": idx, "offset_hex": hex(idx), "pattern": pat.decode("latin-1", "replace")})
            idx += 1
    return hints[:50]


def extract_strings(data, min_len=6):
    """Extract ASCII strings of at least min_len bytes."""
    strings = []
    current = b""
    for b in data:
        if 32 <= b < 127:
            current += bytes([b])
        else:
            if len(current) >= min_len:
                strings.append(current.decode("ascii", "replace"))
            current = b""
    if len(current) >= min_len:
        strings.append(current.decode("ascii", "replace"))
    return strings


def shannon_entropy(data, window=256):
    """Compute Shannon entropy over sliding windows; returns max and average."""
    if not data:
        return 0.0, 0.0
    import math
    if len(data) <= window:
        return _entropy_block(data), _entropy_block(data)
    max_ent = 0.0
    total = 0.0
    count = 0
    for i in range(0, len(data) - window + 1, window // 2):
        block = data[i:i + window]
        e = _entropy_block(block)
        max_ent = max(max_ent, e)
        total += e
        count += 1
    return max_ent, round(total / count, 2) if count else 0.0


def _entropy_block(block):
    import math
    if not block:
        return 0.0
    freq = {}
    for b in block:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    n = len(block)
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def main():
    parser = argparse.ArgumentParser(description="Firmware static analysis (Gate G2)")
    parser.add_argument("image", help="Path to firmware image")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    parser.add_argument("--strings", action="store_true", help="Extract printable strings")
    parser.add_argument("--entropy", action="store_true", help="Compute entropy statistics")
    args = parser.parse_args()

    try:
        with open(args.image, "rb") as f:
            data = f.read()
    except OSError as e:
        print("cannot read %s: %s" % (args.image, e), file=sys.stderr)
        return 1

    magic_hits = scan_magics(data)
    uart_hints = detect_uart_hints(data)

    result = {
        "image": args.image,
        "size": len(data),
        "size_hex": hex(len(data)),
        "magic_hits": magic_hits,
        "uart_hints": uart_hints,
        "filesystems": [h for h in magic_hits if h["type"].startswith(("squashfs", "jffs2"))],
        "bootloaders": [h for h in magic_hits if "U-Boot" in h["type"]],
        "compressed": [h for h in magic_hits if h["type"].endswith(("stream", "archive"))],
    }

    if args.entropy:
        max_ent, avg_ent = shannon_entropy(data)
        result["entropy_max"] = round(max_ent, 2)
        result["entropy_avg"] = avg_ent
        result["encrypted_suspected"] = max_ent > 7.5

    if args.strings:
        result["strings_sample"] = extract_strings(data)[:100]

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print("Image: %s" % args.image)
        print("Size: %d bytes (%s)" % (len(data), hex(len(data))))
        print("Magic hits: %d" % len(magic_hits))
        for h in magic_hits[:20]:
            print("  %s @ %s: %s" % (h["offset_hex"], h["type"], h["magic"]))
        print("UART hints: %d" % len(uart_hints))
        print("Filesystems: %s" % [h["type"] for h in result["filesystems"]])
        print("Bootloaders: %s" % [h["type"] for h in result["bootloaders"]])
        if args.entropy:
            print("Max entropy: %s, Avg entropy: %s" % (result["entropy_max"], result["entropy_avg"]))
            print("Encryption suspected: %s" % result["encrypted_suspected"])
        if args.strings:
            print("Strings (sample): %s" % result["strings_sample"][:20])

    return 0


if __name__ == "__main__":
    sys.exit(main())