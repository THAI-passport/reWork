---
name: re-native-emulation
description: Recover behaviour of native libraries (.so, aarch64/arm/x86) used for auth, crypto, CRC or codecs - list symbols and JNI RegisterNatives with pyelftools, disassemble with capstone, and run the real function under unicorn (bundled aarch64 harness) to freeze test vectors. Use when the user asks to inspect a .so, trace JNI natives, emulate a native auth/crypto/CRC function, or check a Python port against the library; also whenever a protocol depends on code that exists only as native code.
---

# re-native-emulation (gate G3)

Install optional extras only when needed: `pip install unicorn capstone pyelftools` into the venv. If wheels fail to build, say so in LOG.md; Python ports of simple functions still work.

## Steps
1. Extract the `.so` from the right ABI split (arm64-v8a first). Never commit it.
2. Surface: pyelftools `.dynsym` names and sizes; `.rodata` strings (JNI class and method names); `.rela.plt` order maps PLT stubs to libc imports.
3. Classify exports by name and size. Disassemble only functions that matter: `JNI_OnLoad` -> `RegisterNatives` table in `.data` (name, signature, pointer), then each native.
4. Constants in `.data` and tables in `.rodata` are the secrets. Compare against textbook tables (AES S-box, SAFER+, CRC tables, DES) before assuming custom crypto.
5. Do not trust a hand port. Run the real function under unicorn with the harness and rules below.
6. Port stage by stage (key schedule, block, wrapper) and compare each stage with the emulator on random inputs. Freeze outputs as test vectors with tag `[V]`.
7. Record negative results (a library that holds no limits or keys is still a result).

## aarch64 unicorn rules (each one cost a debugging session)
| Rule | Symptom if missed |
|---|---|
| Set CPACR_EL1 bits 20-21 (`\| 3 << 20`) before running compiled C | FP/SIMD instructions fault, or results come out as zeros |
| Map a zeroed page and point TPIDR_EL0 at it | fault on `mrs xN, tpidr_el0` + load (stack canary) |
| A PLT hook sets PC to LR, never LR-4 | the `bl` re-executes: infinite loop or double call |
| Hook malloc/free/memcpy/memset/rand/`__android_log_print` by PLT address (`.rela.plt` order) | jump into unmapped libc |
| Return to a mapped sentinel address and stop there | emulation runs off the end of the function |
| Apply R_AARCH64_RELATIVE relocations if the code reads pointers from `.data`/`.got` | pointers off by the load base |
| Args per AAPCS64: x0-x7, result x0; buffers in a mapped scratch page | garbage input or output |

## Harness
`.claude/skills/re-native-emulation/scripts/unicorn_aarch64_harness.py` implements the rules above (page-aligned PT_LOAD mapping, stack, TLS page, CPACR_EL1, bump-allocator malloc, free, memcpy, table-driven PLT hooks, sentinel return). `tests/test_unicorn_harness.py` runs it on a hand-built synthetic ELF. Copy it to `client/<slug>/tools/emulate_<lib>.py`, fill `PLT_HOOKS`, add relocations if needed; commit the script and vectors, never the library.

## Fallbacks
Ghidra or radare2 only if the function is too large to read in capstone output. Java-side crypto is usually plain: read it in jadx instead.
