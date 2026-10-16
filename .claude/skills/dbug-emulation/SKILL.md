---
name: dbug-emulation
description: CPU emulation and symbolic execution for reverse engineering. miasm-style jitter harness (ARM/x86/Mips), QEMU-user/qemu-system integration, SMT solver (z3) for constraint solving, with pure-Python fallback for offline CI. Gate G0/G4 emulation support.
---

# dbug-emulation (Gate G0/G4)

Emulation lets you analyze code without running it on real hardware or even an OS. Results are `[V]` (verified against real code in emulator) never `[H]`.

## 1. Emulation approaches
1. **miasm-style jitter:** CPU-level emulation that executes machine code in a synthetic memory model with register file, stack, and syscall stubs. Good for analyzing string decryption routines, checksum algorithms, and small functions extracted from binaries.
2. **QEMU-user:** userspace emulation of ELF/PE/Mach-O binaries for foreign architectures (ARM binary on x86 host, etc.).
3. **Qemu-system:** full-system emulation of a target board/SoC (kernel, peripherals, flash).
4. **Unicorn:** lightweight CPU emulation (existing `unicorn_aarch64_harness.py` pure-Python fallback).

## 2. SMT solving
- z3 for constraint solving: recover input values that produce a target output, find password/checksum inputs, solve path conditions.
- Pure-Python fallback: brute-force or pattern-based solving when z3 unavailable.

## 3. Safety
- Emulation is read-only and safe. No hardware interaction.
- All results labeled `[V]` (verified against emulator) — never claim `[H]`.

## 4. Output
- `emulation_report.md` — emulated function inputs/outputs, recovered strings, SMT solutions
- `emulation_trace.jsonl` — instruction trace (optional)
- Sync to `targets/<slug>/` per AGENTS.md contract

## 5. Evidence tags
- `[V]` verified against emulator/simulator
- `[I]` inferred from static analysis
- Never `[H]` — emulation never touches real hardware

## 6. Dependencies
- `unicorn`, `capstone` (optional; `setup-tools.sh --emulation`)
- `z3-solver` (optional)
- `qemu-user`, `qemu-system` (optional system tools)
- Pure-Python fallback always available