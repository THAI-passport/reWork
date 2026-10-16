#!/usr/bin/env python3
"""web_static.py: Web/Electron static analysis tool (Gate G2).

Unpacks asar archives, inspects package.json, surveys Node modules,
extracts endpoints/URLs from JS bundles, and checks Electron security
preferences (nodeIntegration, contextIsolation, remote-debugging-port).

Stdlib-only (asar is zip-like, parseable via zipfile).

Usage:
    python web_static.py <app dir or asar file> [--json]
    python web_static.py <app dir or asar file> --strings
"""
import argparse
import json
import os
import re
import sys
import zipfile

URL_RX = re.compile(rb"https?://[A-Za-z0-9._-]+(?::\d+)?[/A-Za-z0-9._~:?#@!$&'()*+,;=%-]*")
ENDPOINT_RX = re.compile(rb"(?:fetch|XMLHttpRequest|axios|\.post|\.get|\.put|\.delete)\s*\([\s\S]{0,200}?['\"]([^'\"]{1,200})['\"]")
WS_RX = re.compile(rb"WebSocket|ws://|wss://")
NODE_INT_RX = re.compile(rb"nodeIntegration")
CTX_ISO_RX = re.compile(rb"contextIsolation")
REMOTE_DEBUG_RX = re.compile(rb"remote-debugging-port")


def extract_strings(data, min_len=6):
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
def is_asar(path):
    """asar is a zip-like format; check for header without full zip validation."""
    if not zipfile.is_zipfile(path):
        return False
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        return any(n.endswith(".js") or n.endswith(".json") for n in names[:50])


def read_package_json(app_dir):
    """Read package.json from app dir or asar."""
    candidates = [os.path.join(app_dir, "package.json")]
    for c in candidates:
        if os.path.isfile(c):
            with open(c, "r", encoding="utf-8", errors="replace") as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    return {"_parse_error": True}
    if is_asar(app_dir):
        with zipfile.ZipFile(app_dir) as z:
            for name in z.namelist():
                if name.endswith("package.json"):
                    with z.open(name) as f:
                        try:
                            return json.load(f)
                        except json.JSONDecodeError:
                            return {"_parse_error": True}
    return {}


def scan_js_bundle(app_dir, max_files=100):
    """Scan JS files for endpoints, URLs, security preferences."""
    urls = set()
    endpoints = set()
    security_flags = {"nodeIntegration": False, "contextIsolation": False,
                      "remoteDebugging": False}
    files_scanned = 0

    def scan_file(full):
        nonlocal files_scanned
        if files_scanned >= max_files:
            return
        try:
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            return
        files_scanned += 1
        for m in URL_RX.finditer(data):
            urls.add(m.group(0).decode("utf-8", "replace")[:200])
        for m in ENDPOINT_RX.finditer(data):
            endpoints.add(m.group(1).decode("utf-8", "replace", errors="replace")[:200])
        if WS_RX.search(data):
            security_flags["websockets"] = True
        if NODE_INT_RX.search(data):
            security_flags["nodeIntegration"] = True
        if CTX_ISO_RX.search(data):
            security_flags["contextIsolation"] = True
        if REMOTE_DEBUG_RX.search(data):
            security_flags["remoteDebugging"] = True

    if os.path.isdir(app_dir):
        for dp, dn, fns in os.walk(app_dir):
            if files_scanned >= max_files:
                break
            dn[:] = [d for d in dn if d != "node_modules"]
            for fn in sorted(fns):
                if files_scanned >= max_files:
                    break
                if fn.endswith((".js", ".json", ".html", ".ts")):
                    scan_file(os.path.join(dp, fn))
    elif is_asar(app_dir):
        with zipfile.ZipFile(app_dir) as z:
            for info in z.infolist():
                if files_scanned >= max_files:
                    break
                if info.filename.endswith((".js", ".json", ".html")):
                    try:
                        data = z.read(info.filename)
                    except OSError:
                        continue
                    files_scanned += 1
                    for m in URL_RX.finditer(data):
                        urls.add(m.group(0).decode("utf-8", "replace")[:200])
                    for m in ENDPOINT_RX.finditer(data):
                        endpoints.add(m.group(1).decode("utf-8", "replace", errors="replace")[:200])

    return {"urls": sorted(urls)[:50], "endpoints": sorted(endpoints)[:50],
            "security_flags": security_flags, "files_scanned": files_scanned}
def main():
    parser = argparse.ArgumentParser(description="Web/Electron static analysis (Gate G2)")
    parser.add_argument("path", help="Path to app directory or asar file")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    parser.add_argument("--strings", action="store_true", help="Extract printable strings")
    args = parser.parse_args()

    pkg = read_package_json(args.path)
    scan = scan_js_bundle(args.path)

    result = {
        "path": args.path,
        "package": pkg,
        "endpoints": scan["endpoints"],
        "urls": scan["urls"],
        "security_flags": scan["security_flags"],
        "files_scanned": scan["files_scanned"],
        "is_asar": is_asar(args.path),
    }

    if args.strings:
        data = b""
        if os.path.isdir(args.path):
            for dp, dn, fns in os.walk(args.path):
                dn[:] = [d for d in dn if d != "node_modules"]
                for fn in fns:
                    if fn.endswith((".js", ".json", ".html")):
                        try:
                            with open(os.path.join(dp, fn), "rb") as f:
                                data += f.read()[:50000]
                        except OSError:
                            pass
        elif is_asar(args.path):
            with zipfile.ZipFile(args.path) as z:
                for info in z.infolist():
                    if info.filename.endswith((".js", ".json", ".html")):
                        try:
                            data += z.read(info.filename)[:50000]
                        except OSError:
                            pass
        result["strings_sample"] = extract_strings(data)[:100]

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print("Path: %s" % args.path)
        print("Is asar: %s" % result["is_asar"])
        print("Package name: %s" % pkg.get("name", "unknown"))
        print("Package version: %s" % pkg.get("version", "unknown"))
        print("Main entry: %s" % pkg.get("main", "unknown"))
        print("Files scanned: %d" % scan["files_scanned"])
        print("Endpoints found: %d" % len(scan["endpoints"]))
        for ep in scan["endpoints"][:10]:
            print("  %s" % ep)
        print("URLs found: %d" % len(scan["urls"]))
        for u in scan["urls"][:10]:
            print("  %s" % u)
        print("Security flags: %s" % json.dumps(scan["security_flags"]))
        if args.strings:
            print("Strings (sample): %s" % result["strings_sample"][:20])

    return 0


if __name__ == "__main__":
    sys.exit(main())