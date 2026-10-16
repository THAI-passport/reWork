#!/usr/bin/env python3
"""ios_static.py: iOS static analysis tool (Gate G2 surface map).

Parses an unzipped IPA Payload/<app>.app directory: Info.plist, entitlements,
Mach-O load commands, exported/imported symbols, and Objective-C class names.
Outputs a surface-map fragment suitable for inclusion in PROTOCOL.md.

Stdlib-only for plist parsing; Mach-O parsing uses pure Python (no external
deps). Optional pyelftools/lief if available for deeper analysis.

Usage:
    python ios_static.py <Payload/<app>.app dir> [--bundle-id]
    python ios_static.py <ipa file>   # unzips to a temp dir first
"""
import argparse
import json
import os
import plistlib
import re
import shutil
import struct
import sys
import tempfile
import zipfile

MAGIC_MH = 0xFEEDFACE
MAGIC_MH_CIGAM = 0xCEFAEDFE
MAGIC_MH_64 = 0xFEEDFACF
MAGIC_MH_64_CIGAM = 0xCFFAEDFE

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_DYLD_INFO_ONLY = 0x22
LC_ENCRYPTION_INFO_64 = 0x2C
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x1E
LC_REEXPORT_DYLIB = 0x1F


def find_app_dir(payload_dir):
    """Return the .app directory inside Payload/."""
    for entry in os.listdir(payload_dir):
        if entry.endswith(".app"):
            return os.path.join(payload_dir, entry)
    return None


def read_plist(path):
    """Read a binary or XML plist file."""
    with open(path, "rb") as f:
        return plistlib.load(f)


def parse_macho(path):
    """Parse Mach-O header and load commands. Returns dict of findings."""
    findings = {
        "magic": None,
        "cputype": None,
        "cpusubtype": None,
        "filetype": None,
        "segments": [],
        "dylibs": [],
        "encrypted": False,
        "encryption_cryptid": None,
        "nlist_count": 0,
        "imports": [],
    }
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return findings

    if len(data) < 28:
        return findings

    magic = struct.unpack("<I", data[:4])[0]
    is_64 = magic in (MAGIC_MH_64, MAGIC_MH_64_CIGAM)

    if is_64:
        header = struct.unpack("<QIIIIIII", data[:32])
        cputype, cpusubtype, filetype, ncmds, sizeofcmds = header[1], header[2], header[3], header[4], header[5]
        cmd_offset = 32
    else:
        header = struct.unpack("<IIIIIII", data[:28])
        cputype, cpusubtype, filetype, ncmds, sizeofcmds = header[1], header[2], header[3], header[4], header[5]
        cmd_offset = 28

    findings["cputype"] = cputype
    findings["cpusubtype"] = cpusubtype
    findings["filetype"] = filetype

    cpu_names = {0x1000007: "arm64", 0x1000008: "arm64e", 0x7: "i386", 0x1000003: "x86_64"}
    findings["cpu"] = cpu_names.get(cputype, "0x%x" % cputype)

    off = cmd_offset
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack("<II", data[off:off + 8])
        if cmd == LC_SEGMENT_64:
            seg = struct.unpack("<16sQQQQQIIII", data[off:off + 80])
            segname = seg[0].split(b"\x00")[0].decode("utf-8", "replace")
            findings["segments"].append(segname)
        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
            str_off = struct.unpack("<I", data[off + 24:off + 28])[0]
            end = data.index(b"\x00", str_off) if b"\x00" in data[str_off:] else len(data)
            name = data[str_off:end].decode("utf-8", "replace")
            findings["dylibs"].append(name)
        elif cmd == LC_ENCRYPTION_INFO_64:
            cryptid = struct.unpack("<I", data[off + 8:off + 12])[0]
            findings["encryption_cryptid"] = cryptid
            findings["encrypted"] = cryptid == 1
        off += cmdsize

    return findings


def survey_objc_classes(app_dir):
    """Crude Objective-C class name survey from the Mach-O binary."""
    app_bin = None
    for entry in os.listdir(app_dir):
        full = os.path.join(app_dir, entry)
        if os.path.isfile(full) and not entry.startswith(".") and not entry.endswith((".plist", ".mobileprovision")):
            try:
                with open(full, "rb") as f:
                    head = f.read(4)
            except OSError:
                continue
            if head in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
                app_bin = full
                break
    classes = []
    if app_bin:
        try:
            with open(app_bin, "rb") as f:
                data = f.read()
            for m in re.finditer(rb"[A-Za-z][A-Za-z0-9_]{2,}", data):
                s = m.group(0).decode("ascii", "replace")
                if len(s) >= 4 and not s.startswith("__") and s.isascii():
                    classes.append(s)
        except OSError:
            pass
    seen = []
    for c in classes:
        if c not in seen:
            seen.append(c)
    return seen[:200]


def main():
    parser = argparse.ArgumentParser(description="iOS static analysis (Gate G2 surface map)")
    parser.add_argument("path", help="Path to Payload/<app>.app directory or .ipa file")
    parser.add_argument("--bundle-id", action="store_true", help="Print only CFBundleIdentifier")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args()

    path = args.path
    tmpdir = None
    if path.lower().endswith(".ipa"):
        tmpdir = tempfile.mkdtemp()
        with zipfile.ZipFile(path) as z:
            z.extractall(tmpdir)
        payload_dir = os.path.join(tmpdir, "Payload")
    else:
        payload_dir = path

    app_dir = find_app_dir(payload_dir)
    if not app_dir:
        print("no .app bundle found in %s" % path, file=sys.stderr)
        return 1

    info_plist = os.path.join(app_dir, "Info.plist")
    ent_plist = os.path.join(app_dir, "embedded.mobileprovision")

    info = read_plist(info_plist) if os.path.isfile(info_plist) else {}
    bundle_id = info.get("CFBundleIdentifier", "")
    version = info.get("CFBundleShortVersionString", "")
    build = info.get("CFBundleVersion", "")

    binary_name = os.path.basename(app_dir)[:-4]
    binary_path = os.path.join(app_dir, binary_name)
    macho = parse_macho(binary_path) if os.path.isfile(binary_path) else {}

    classes = survey_objc_classes(app_dir)

    entitlements = {}
    if os.path.isfile(ent_plist):
        try:
            with open(ent_plist, "rb") as f:
                mp = plistlib.load(f)
            entitlements = mp.get("Entitlements", {})
        except Exception:
            pass

    result = {
        "bundle_id": bundle_id,
        "version": version,
        "build": build,
        "app_dir": app_dir,
        "macho": macho,
        "objc_classes_sample": classes[:50],
        "info_plist_keys": sorted(info.keys()),
        "entitlements": entitlements,
    }

    if args.bundle_id:
        print(bundle_id)
        return 0

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print("Bundle ID: %s" % bundle_id)
        print("Version: %s (%s)" % (version, build))
        print("CPU: %s" % macho.get("cpu", "unknown"))
        print("Encrypted: %s (cryptid=%s)" % (macho.get("encrypted", False), macho.get("encryption_cryptid")))
        print("Segments: %s" % ", ".join(macho.get("segments", [])))
        print("Dylibs: %s" % ", ".join(macho.get("dylibs", [])[:20]))
        print("ObjC classes (sample): %s" % ", ".join(classes[:20]))
        print("Entitlements: %s" % json.dumps(entitlements, indent=2, default=str))

    if tmpdir:
        import shutil
        shutil.rmtree(tmpdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())