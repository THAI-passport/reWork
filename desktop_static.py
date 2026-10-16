#!/usr/bin/env python3
"""desktop_static.py: Desktop binary static analysis (Gate G2 surface map).

Analyzes PE (Windows), ELF (Linux), and Mach-O (macOS) binaries: header
parsing, import/export survey, section entropy, string extraction, and
packer detection. Stdlib-only; optional pyelftools/lief if available.

Usage:
    python desktop_static.py <binary> [--json]
"""
import argparse
import json
import os
import struct
import sys

MZ = b"MZ"
ELF_MAGIC = b"\x7fELF"
MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")

PACKER_SECTIONS = (b"UPX0", b"UPX1", b"UPX2", b"PEPACK", b"ASPROVE", b"Themida",
                   b"VMProtect", b"Obsidium", b"PECompact")


def shannon_entropy(data):
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    import math
    ent = 0.0
    n = len(data)
    for count in freq.values():
        p = count / n
        ent -= p * __import__("math").log2(p)
    return ent
def detect_format(path):
    with open(path, "rb") as f:
        head = f.read(4)
    if head[:2] == MZ:
        return "PE"
    if head == ELF_MAGIC:
        return "ELF"
    if head in MACHO_MAGICS:
        return "Mach-O"
    return "unknown"


def parse_pe(path):
    findings = {"format": "PE", "entries": [], "sections": [], "imports": [],
                "exports": [], "entropy_high": [], "packer": False,
                "signed": False, "subsystem": None, "machine": None}
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return findings

    if len(data) < 64:
        return findings

    e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    if e_lfanew + 24 > len(data):
        return findings
    sig = data[e_lfanew:e_lfanew + 4]
    if sig != b"PE\x00\x00":
        return findings
    coff = e_lfanew + 4
    machine, num_sections, timestamp, _, _, sizeof_opt, characteristics = struct.unpack(
        "<HHIIIHH", data[coff:coff + 20])
    findings["machine"] = hex(machine)
    findings["num_sections"] = num_sections
    findings["timestamp"] = timestamp
    findings["characteristics"] = hex(characteristics)

    opt = coff + 20
    magic = struct.unpack("<H", data[opt:opt + 2])[0]
    is_pe32plus = magic == 0x20B
    if is_pe32plus:
        entry, = struct.unpack("<Q", data[opt + 24:opt + 32])
        base, = struct.unpack("<Q", data[opt + 56:opt + 64])
    else:
        entry, = struct.unpack("<I", data[opt + 16:opt + 20])
        base, = struct.unpack("<I", data[opt + 52:opt + 60])
    findings["entry_point"] = hex(entry)
    findings["image_base"] = hex(base)
    findings["subsystem"] = struct.unpack("<H", data[opt + 68:opt + 70])[0] if opt + 70 <= len(data) else None

    sec_off = opt + (240 if is_pe32plus else 224)
    for i in range(num_sections):
        if sec_off + 40 > len(data):
            break
        sec = data[sec_off:sec_off + 40]
        sname = sec[:8].split(b"\x00")[0].decode("utf-8", "replace")
        vsize, vaddr, rsize, raddr = struct.unpack("<IIII", sec[8:24])
        entropy = shannon_entropy(data[raddr:raddr + min(rsize, 4096)]) if rsize and raddr + rsize <= len(data) else 0.0
        findings["sections"].append({"name": sname, "vsize": vsize, "rsize": rsize, "entropy": round(entropy, 2)})
        if entropy > 7.0:
            findings["entropy_high"].append(sname)
        if any(p in sname.encode() for p in PACKER_SECTIONS):
            findings["packer"] = True
        sec_off += 40

    dd_off = opt + (112 if is_pe32plus else 96)
    if dd_off + 8 * 2 <= len(data):
        import_rva, import_size = struct.unpack("<II", data[dd_off + 8:dd_off + 16])
        if import_rva and import_size:
            findings["imports"].append({"rva": hex(import_rva), "size": import_size,
                                        "note": "RVA present; full parse needs section mapping"})

    if dd_off + 8 * 5 <= len(data):
        sec_rva, sec_size = struct.unpack("<II", data[dd_off + 32:dd_off + 40])
        if sec_rva and sec_size:
            findings["signed"] = True

    return findings
    return findings


def parse_elf(path):
    findings = {"format": "ELF", "entries": [], "sections": [], "imports": [],
                "exports": [], "entropy_high": [], "packer": False,
                "signed": False, "machine": None, "type": None}
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return findings

    if len(data) < 64:
        return findings

    ei_class = data[4]
    ei_data = data[5]
    e_endian = "<" if ei_data == 1 else ">"

    if ei_class == 2:
        e_type, e_machine = struct.unpack(e_endian + "HH", data[16:20])
        e_entry, = struct.unpack(e_endian + "Q", data[24:32])
        e_phoff, = struct.unpack(e_endian + "Q", data[32:40])
        e_shoff, = struct.unpack(e_endian + "Q", data[40:48])
        e_phentsize, = struct.unpack(e_endian + "H", data[54:56])
        e_phnum, = struct.unpack(e_endian + "H", data[56:58])
    else:
        e_type, e_machine = struct.unpack(e_endian + "HH", data[16:20])
        e_entry, = struct.unpack(e_endian + "I", data[24:28])
        e_phoff, = struct.unpack(e_endian + "I", data[28:32])
        e_shoff, = struct.unpack(e_endian + "I", data[32:36])
        e_phentsize, = struct.unpack(e_endian + "H", data[54:56])
        e_phnum, = struct.unpack(e_endian + "H", data[56:58])

    findings["type"] = hex(e_type)
    findings["machine"] = hex(e_machine)
    findings["entry_point"] = hex(e_entry)

    machine_names = {0x3E: "x86_64", 0x3: "i386", 0xB7: "aarch64", 0xF3: "riscv"}
    findings["arch"] = machine_names.get(e_machine, "0x%x" % e_machine)

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            break
        p_type, = struct.unpack(e_endian + "I", data[off:off + 4])
        if p_type == 1:
            if ei_class == 2:
                p_offset, p_filesz, p_memsz = struct.unpack(e_endian + "QQQ",
                    data[off + 8:off + 32])
            else:
                p_offset, p_filesz, p_memsz = struct.unpack(e_endian + "III",
                    data[off + 8:off + 20])
            seg_entropy = shannon_entropy(data[p_offset:p_offset + min(p_filesz, 4096)]) if p_filesz else 0.0
            findings["sections"].append({"type": "PT_LOAD", "offset": hex(p_offset),
                                         "filesz": p_filesz, "entropy": round(seg_entropy, 2)})
            if seg_entropy > 7.0:
                findings["entropy_high"].append("PT_LOAD@%s" % hex(p_offset))

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            break
        p_type, = struct.unpack(e_endian + "I", data[off:off + 4])
        if p_type == 2:
            if ei_class == 2:
                p_offset, = struct.unpack(e_endian + "Q", data[off + 8:off + 16])
            else:
                p_offset, = struct.unpack(e_endian + "I", data[off + 8:off + 12])
            dyn_data = data[p_offset:p_offset + 256]
            idx = 0
            step = 16 if ei_class == 2 else 8
            while idx + step <= len(dyn_data):
                if ei_class == 2:
                    tag, val = struct.unpack(e_endian + "qq", dyn_data[idx:idx + 16])
                else:
                    tag, val = struct.unpack(e_endian + "ii", dyn_data[idx:idx + 8])
                if tag == 0:
                    break
                if tag == 1:
                    findings["imports"].append({"dynstr_offset": hex(val)})
                idx += step
            break

    return findings
    return findings


def parse_macho(path):
    findings = {"format": "Mach-O", "entries": [], "segments": [], "dylibs": [],
                "entropy_high": [], "packer": False, "signed": False,
                "cputype": None, "filetype": None}
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return findings

    if len(data) < 28:
        return findings

    magic = struct.unpack("<I", data[:4])[0]
    is_64 = magic in (0xFEEDFACF, 0xCFFAEDFE)

    if is_64:
        header = struct.unpack("<QIIIIIII", data[:32])
        cputype, cpusubtype, filetype, ncmds, sizeofcmds = header[1], header[2], header[3], header[4], header[5]
        cmd_offset = 32
    else:
        header = struct.unpack("<IIIIIII", data[:28])
        cputype, cpusubtype, filetype, ncmds, sizeofcmds = header[1], header[2], header[3], header[4], header[5]
        cmd_offset = 28

    findings["cputype"] = hex(cputype)
    findings["filetype"] = hex(filetype)
    cpu_names = {0x1000007: "arm64", 0x1000008: "arm64e", 0x7: "i386", 0x1000003: "x86_64"}
    findings["cpu"] = cpu_names.get(cputype, "0x%x" % cputype)

    off = cmd_offset
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack("<II", data[off:off + 8])
        if cmd == 0x19:
            seg = struct.unpack("<16sQQQQQIIII", data[off:off + 80])
            segname = seg[0].split(b"\x00")[0].decode("utf-8", "replace")
            vmaddr, vmsize, fileoff, filesize = seg[2], seg[3], seg[4], seg[5]
            seg_entropy = shannon_entropy(data[fileoff:fileoff + min(filesize, 4096)]) if filesize else 0.0
            findings["segments"].append({"name": segname, "vmaddr": hex(vmaddr),
                                         "vmsize": vmsize, "filesize": filesize, "entropy": round(seg_entropy, 2)})
            if seg_entropy > 7.0:
                findings["entropy_high"].append(segname)
        elif cmd in (0x0C, 0x1E, 0x1F):
            str_off = struct.unpack("<I", data[off + 24:off + 28])[0]
            end = data.index(b"\x00", str_off) if b"\x00" in data[str_off:] else len(data)
            name = data[str_off:end].decode("utf-8", "replace")
            findings["dylibs"].append(name)
        elif cmd == 0x2C:
            cryptid = struct.unpack("<I", data[off + 8:off + 12])[0]
            if cryptid == 1:
                findings["encrypted"] = True
        off += cmdsize

    return findings
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


def main():
    parser = argparse.ArgumentParser(description="Desktop binary static analysis (Gate G2)")
    parser.add_argument("binary", help="Path to PE/ELF/Mach-O binary")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    parser.add_argument("--strings", action="store_true", help="Also extract printable strings")
    args = parser.parse_args()

    fmt = detect_format(args.binary)
    if fmt == "PE":
        result = parse_pe(args.binary)
    elif fmt == "ELF":
        result = parse_elf(args.binary)
    elif fmt == "Mach-O":
        result = parse_macho(args.binary)
    else:
        result = {"format": "unknown", "note": "not a PE/ELF/Mach-O binary"}

    if args.strings:
        with open(args.binary, "rb") as f:
            data = f.read()
        result["strings_sample"] = extract_strings(data)[:100]

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print("Format: %s" % result.get("format"))
        if result.get("format") == "PE":
            print("Machine: %s" % result.get("machine"))
            print("Entry point: %s" % result.get("entry_point"))
            print("Image base: %s" % result.get("image_base"))
            print("Sections: %d" % len(result.get("sections", [])))
            print("High-entropy sections: %s" % result.get("entropy_high", []))
            print("Packer detected: %s" % result.get("packer", False))
            print("Signed: %s" % result.get("signed", False))
        elif result.get("format") == "ELF":
            print("Arch: %s" % result.get("arch"))
            print("Type: %s" % result.get("type"))
            print("Entry point: %s" % result.get("entry_point"))
            print("Segments: %d" % len(result.get("sections", [])))
            print("High-entropy segments: %s" % result.get("entropy_high", []))
        elif result.get("format") == "Mach-O":
            print("CPU: %s" % result.get("cpu"))
            print("Segments: %d" % len(result.get("segments", [])))
            print("High-entropy segments: %s" % result.get("entropy_high", []))
            print("Dylibs: %s" % ", ".join(result.get("dylibs", [])[:20]))
        if args.strings:
            print("Strings (sample): %s" % result.get("strings_sample", [])[:20])

    return 0


if __name__ == "__main__":
    sys.exit(main())