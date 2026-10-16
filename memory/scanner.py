#!/usr/bin/env python3
"""memory/scanner.py: Memory forensics tool (Gate G5).

Acquires and analyzes process memory dumps: /proc/<pid>/mem parsing,
region mapping, string scanning, pattern matching (keys, tokens, canaries),
and module enumeration. Stdlib-only; optional frida for in-process scanning.

Usage:
    python memory/scanner.py --pid <pid> --maps --strings
    python memory/scanner.py --scan-file <dump.bin> --pattern <hex>
    python memory/scanner.py --frida-scan --package <bundle.id|pid> --dry-run
"""
import argparse
import json
import os
import re
import sys

PATTERNS = {
    "aes_key_128": re.compile(rb"[0-9a-fA-F]{32}"),
    "aes_key_256": re.compile(rb"[0-9a-fA-F]{64}"),
    "canary": re.compile(rb"CANARY_[A-Z0-9_]+"),
    "private_key": re.compile(rb"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    "session_token": re.compile(rb"[sS][eE][sS][sS][iI][oO][nN][_-]?[tT][oO][kK][eE][nN][=:\"]{1,3}[A-Za-z0-9_-]{16,}"),
    "url": re.compile(rb"https?://[A-Za-z0-9._-]+(?::\d+)?[/A-Za-z0-9._~:?#@!$&'()*+,;=%-]*"),
}
def parse_maps(pid):
    """Parse /proc/<pid>/maps to list memory regions."""
    regions = []
    maps_path = "/proc/%d/maps" % pid
    try:
        with open(maps_path, "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue
                addr_range = parts[0]
                perms = parts[1]
                offset = parts[2]
                dev = parts[3]
                inode = parts[4]
                pathname = " ".join(parts[5:]) if len(parts) > 5 else ""
                start, end = addr_range.split("-")
                regions.append({
                    "start": int(start, 16),
                    "end": int(end, 16),
                    "perms": perms,
                    "offset": offset,
                    "dev": dev,
                    "inode": inode,
                    "pathname": pathname,
                    "size": int(end, 16) - int(start, 16),
                })
    except OSError as e:
        return {"error": "cannot read /proc/%d/maps: %s" % (pid, e)}
    return regions


def read_region(pid, start, end, max_size=65536):
    """Read a memory region from /proc/<pid>/mem."""
    size = min(end - start, max_size)
    mem_path = "/proc/%d/mem" % pid
    try:
        with open(mem_path, "rb") as f:
            f.seek(start)
            data = f.read(size)
        return data
    except OSError:
        return None


def scan_data(data, patterns=None):
    """Scan data for known patterns."""
    if patterns is None:
        patterns = PATTERNS
    hits = []
    for name, rx in patterns.items():
        for m in rx.finditer(data):
            hits.append({"pattern": name, "offset": m.start(),
                         "value": m.group(0).decode("utf-8", "replace")[:100]})
    return hits


def extract_strings(data, min_len=6):
    """Extract printable ASCII strings."""
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
def scan_pid(pid, max_region_size=65536):
    """Scan a live process memory (read-only)."""
    regions = parse_maps(pid)
    if "error" in regions:
        return regions

    all_hits = []
    all_strings = []
    for region in regions:
        if "r" not in region["perms"]:
            continue
        data = read_region(pid, region["start"], region["end"], max_region_size)
        if data is None:
            continue
        hits = scan_data(data)
        for h in hits:
            h["region_start"] = hex(region["start"])
            h["region_pathname"] = region["pathname"]
            all_hits.append(h)
        strings = extract_strings(data)
        for s in strings:
            if any(kw in s.lower() for kw in
                   ("key", "token", "secret", "password", "canary", "api", "auth")):
                all_strings.append({"string": s, "region_start": hex(region["start"]),
                                    "region_pathname": region["pathname"]})

    return {"pid": pid, "regions": len(regions),
            "pattern_hits": all_hits[:100], "secret_strings": all_strings[:100]}


def scan_file(path, pattern_name=None):
    """Scan a memory dump file for patterns."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return {"error": "cannot read %s: %s" % (path, e)}

    patterns = PATTERNS
    if pattern_name:
        if pattern_name in patterns:
            patterns = {pattern_name: patterns[pattern_name]}
        else:
            return {"error": "unknown pattern: %s" % pattern_name}

    hits = scan_data(data, patterns)
    strings = extract_strings(data)
    secret_strings = [s for s in strings
                      if any(kw in s.lower() for kw in
                             ("key", "token", "secret", "password", "canary", "api", "auth"))]

    return {"file": path, "size": len(data),
            "pattern_hits": hits[:100], "secret_strings": secret_strings[:100]}


def frida_scan_dry_run(package):
    """Simulate in-process Frida memory scan (dry-run mode)."""
    import time
    now_ms = int(time.time() * 1000)
    hits = [
        {"pattern": "canary", "address": "0x7ffee4b00100",
         "value": "CANARY_SESSION_CORP", "region": "heap",
         "timestamp_ms": now_ms + 100},
        {"pattern": "aes_key_256", "address": "0x7ffee4b00200",
         "value": "a1b2c3d4e5f6...", "region": ".rodata",
         "timestamp_ms": now_ms + 200},
        {"pattern": "url", "address": "0x7ffee4b00300",
         "value": "https://c2.example.com/api", "region": "heap",
         "timestamp_ms": now_ms + 300},
    ]
    return hits
def main():
    parser = argparse.ArgumentParser(description="Memory forensics (Gate G5)")
    parser.add_argument("--pid", type=int, help="Target process PID (live scan)")
    parser.add_argument("--scan-file", help="Memory dump file to scan")
    parser.add_argument("--pattern", help="Pattern name to scan for")
    parser.add_argument("--maps", action="store_true", help="Show memory maps only")
    parser.add_argument("--strings", action="store_true", help="Extract secret strings")
    parser.add_argument("--frida-scan", action="store_true",
                        help="Simulate Frida in-process memory scan")
    parser.add_argument("--package", help="Target package/process for Frida scan")
    parser.add_argument("--dry-run", action="store_true", help="Simulate without hardware")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args()

    if args.frida_scan or args.dry_run:
        hits = frida_scan_dry_run(args.package or "unknown")
        if args.json:
            print(json.dumps({"frida_scan": hits}, indent=2))
        else:
            print("Frida memory scan (dry-run): %d hits" % len(hits))
            for h in hits:
                print("  %s @ %s: %s" % (h["pattern"], h["address"], h["value"]))
        return 0

    if args.pid:
        result = scan_pid(args.pid)
        if args.maps:
            result.pop("pattern_hits", None)
            result.pop("secret_strings", None)
        if not args.strings:
            result.pop("secret_strings", None)
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print("PID: %d" % result.get("pid"))
            print("Regions: %d" % result.get("regions", 0))
            print("Pattern hits: %d" % len(result.get("pattern_hits", [])))
            for h in result.get("pattern_hits", [])[:10]:
                print("  %s @ %s (%s): %s" % (h["pattern"], h["region_start"],
                                                h["region_pathname"], h["value"]))
            if args.strings:
                print("Secret strings: %d" % len(result.get("secret_strings", [])))
                for s in result.get("secret_strings", [])[:10]:
                    print("  %s @ %s (%s)" % (s["string"], s["region_start"],
                                              s["region_pathname"]))
        return 0

    if args.scan_file:
        result = scan_file(args.scan_file, args.pattern)
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print("File: %s" % result.get("file"))
            print("Size: %d bytes" % result.get("size", 0))
            print("Pattern hits: %d" % len(result.get("pattern_hits", [])))
            for h in result.get("pattern_hits", [])[:10]:
                print("  %s: %s" % (h["pattern"], h["value"]))
            print("Secret strings: %d" % len(result.get("secret_strings", [])))
            for s in result.get("secret_strings", [])[:10]:
                print("  %s" % s)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())