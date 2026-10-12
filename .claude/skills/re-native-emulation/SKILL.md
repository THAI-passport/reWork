---
name: re-native-emulation
description: Recover behaviour of native libraries (.so, aarch64/arm/x86) used for auth, crypto, CRC or codecs by listing symbols, reading JNI registration, disassembling with capstone/pyelftools, and running the real function under unicorn to freeze test vectors. Use when a protocol depends on code that exists only as a native library.
---

# re-native-emulation (part of gate G3)

Install optional extras only when needed: `pip install unicorn capstone pyelftools` into the venv. If wheels fail to build, say so in LOG.md; Python ports of simple functions still work.

## Steps
1. Extract the `.so` from the right ABI split (arm64-v8a first). Never commit it.
2. Surface: pyelftools `.dynsym` names and sizes; `.rodata` strings (JNI class and method names); `.rela.plt` order maps PLT stubs to libc imports.
3. Classify exports by name and size. Disassemble only functions that matter: `JNI_OnLoad` -> `RegisterNatives` table in `.data` (name, signature, pointer), then each native.
4. Constants in `.data` and tables in `.rodata` are the secrets. Compare against textbook tables (AES S-box, SAFER+, CRC tables, DES) before assuming custom crypto.
5. Do not trust a hand port. Run the real function: map PT_LOAD segments at vaddr, map a page for TPIDR_EL0 (stack canary), enable FP/SIMD (CPACR_EL1), hook PLT stubs (malloc, free, memcpy), set PC to the link register to return from a hook (not LR-4), place args per the AAPCS64 calling convention.
6. Port stage by stage (key schedule, block, wrapper) and compare each stage with the emulator on random inputs. Freeze outputs as test vectors with tag `[V]`.
7. Record negative results (a library that holds no limits or keys is still a result).

## Reference sketch
A working loader is about 50 lines: parse ELF, `mu.mem_map` each segment page-aligned, write bytes, set SP, TPIDR_EL0, hook `UC_HOOK_CODE` at PLT addresses, `emu_start(entry, until=sentinel)`. Keep the script in `client/<slug>/tools/emulate_<lib>.py`; commit the script and vectors, never the library.

## Fallbacks
Ghidra or radare2 only if the function is too large to read in capstone output. Java-side crypto is usually plain: read it in jadx instead.
