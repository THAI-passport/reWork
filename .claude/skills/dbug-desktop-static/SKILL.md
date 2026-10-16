---
name: dbug-desktop-static
description: Static analysis of desktop binaries (Linux ELF, macOS Mach-O, Windows PE). Header parsing, import/export table survey, section entropy, string extraction, packer detection (UPX, etc.), and .NET/Java metadata inspection. Gate G2 surface map for desktop targets.
---

# dbug-desktop-static (Gate G2: Desktop)

Desktop executables come in three major formats: PE (Windows), ELF (Linux), and Mach-O (macOS). Static analysis proceeds without installing or running the binary (AGENTS.md ground rule 2).

## 1. Binary format survey
1. Identify format by magic bytes: `MZ` (PE), `\x7fELF` (ELF), `\xfe\xed\xfa\xce|\xcf` (Mach-O).
2. PE: DOS header, NT headers, file header, optional header, section table, import directory, export directory, resources, certificate table.
3. ELF: ELF header, program headers (PT_LOAD, PT_DYNAMIC, PT_INTERP), section headers (.text, .data, .rodata, .dynsym, .dynstr), dynamic dependencies (NEEDED), exported/imported symbols.
4. Mach-O: Mach header, load commands (LC_SEGMENT_64, LC_SYMTAB, LC_DYLD_INFO_ONLY, LC_LOAD_DYLIB, LC_ENCRYPTION_INFO_64), exported/imported symbols.

## 2. Analysis steps
1. **Header parsing:** architecture, entry point, image base, section count, timestamp, characteristics (DLL characteristics, DLL vs EXE).
2. **Section entropy:** compute Shannon entropy per section; high entropy (>7.0) suggests packed/encrypted code or data.
3. **Import/export survey:** imported DLLs/frameworks and functions (indicates network, crypto, GUI frameworks used); exported functions (indicates plugin/DLL).
4. **String extraction:** ASCII and Unicode strings; filter for URLs, IP addresses, registry keys, file paths, API keys, hardcoded credentials.
5. **Packer detection:** PE: UPX section names (UPX0, UPX1, UPX2), small .text with large .rsrc, atypical entry point. ELF: packed section names, small entry stub.
6. **.NET / Java metadata:** PE with .NET header (CLR) → dnSpy/ILSpy territory; ELF with `.comment` GCC version; Java class files embedded.
7. **Code signing:** PE signature (WIN_CERTIFICATE), ELF/Mach-O signature status — unsigned binaries are `[I]` risk.

## 3. Output
Write into PROTOCOL.md a surface map: format, architecture, entry point, imported libraries, exported functions, high-entropy sections, packer indicators, code-signing status, relevant strings. Every row tagged `[C]` (confirmed in binary) or `[U]` (unknown).

## 4. Evidence tags
- `[C]` confirmed in binary headers/sections/strings
- `[U]` unknown (packed/encrypted, server-side config)
- Never `[H]` without executing on a desktop host (user-provided hardware only).

## 5. Dependencies
- `pyelftools` (ELF), `lief` (multi-format) — optional (`setup-tools.sh --emulation`)
- Stdlib-only fallback: pure Python header parsing (PE/ELF/Mach-O magic + key fields)