---
name: dbug-memory
description: Memory forensics for reverse engineering. Memory dump acquisition (Android /proc/<pid>/mem, iOS task_for_pid, desktop process memory), Volatility-style plugin skeleton for process/module/string extraction, and Frida memory scanner for key/material hunting. Gate G5 for all targets.
---

# dbug-memory (Gate G5: Memory Forensics)

Memory forensics extracts secrets, keys, and strings from process memory without modifying the target. All acquisition is read-only and user-requested (AGENTS.md ground rule 2).

## 1. Memory dump acquisition
1. **Android:** `/proc/<pid>/mem` (requires root/ptrace access), `/proc/<pid>/maps` for region layout.
2. **iOS:** `task_for_pid` (requires platform binary or entitlements), `vm_region`, `vm_read`.
3. **Desktop:** Linux `/proc/<pid>/mem`, macOS `task_for_pid`/`vm_read`, Windows `ReadProcessMemory` (requires debug privileges).

## 2. Analysis steps
1. **Region mapping:** parse /proc/<pid>/maps or equivalent to identify heap, stack, .text, .data, .rodata, libraries.
2. **String scanning:** extract printable strings from each region; filter for keys, tokens, URLs, credentials.
3. **Pattern scanning:** search for known patterns (AES keys, RSA keys, Bitcoin addresses, session tokens, canary tokens).
4. **Process/module enumeration:** list loaded modules, their base addresses and sizes (Volatility-style).
5. **Heap analysis:** identify heap allocations, freed chunks, use-after-free candidates.

## 3. Frida memory scanner
- Frida-based memory scanner that runs inside the target process (no dump file needed).
- Scan heap, stack, and .rodata for canary tokens and key material.
- Stream hits to instrumentation_events.jsonl.

## 4. Output
- `memory_dump.<pid>.bin` — raw memory dump (sanitized, git-ignored)
- `memory_analysis.md` — regions, strings, patterns found, modules
- `memory_scan.jsonl` — Frida memory scan hits
- Sync to `targets/<slug>/` per AGENTS.md contract

## 5. Evidence tags
- `[V]` verified by test vector against real code (synthetic dump)
- `[I]` inferred from static analysis
- `[H]` only with real memory dump from hardware (user must provide)
- Memory dumps may contain credentials — scrub before saving (ground rule: no personal data).

## 6. Dependencies
- Stdlib-only for /proc parsing
- `frida` for in-process memory scanner (optional)
- `volatility3` (optional; for advanced memory forensics)