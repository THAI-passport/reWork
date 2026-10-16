---
name: dbug-native-emulation
description: Static reverse engineering, JNI symbol mapping, and Unicorn AArch64 CPU emulation for evasive native Android malware libraries (.so). Maps RegisterNatives tables, inspects JNI_OnLoad anti-debug, and emulates custom native string/payload decryption routines without running the whole Android OS. Use when analyzing packed native infostealers or validating native crypto algorithms.
---

# dbug-native-emulation

Recover the behavior of native Android malware libraries (`.so`, ARM64 / aarch64) used for packing, string decryption, anti-debugging, and raw socket C2 communication.

---

## 1. Native Surface Reconnaissance
1. Extract `.so` files from the ARM64 split APK:
   ```bash
   unzip -j sample.apk "lib/arm64-v8a/*.so" -d work/native/
   ```
2. Inspect exported symbols, dynamic strings, and dependencies with `readelf`:
   ```bash
   readelf -d work/native/libtarget.so      # Dynamic dependencies (libc.so, liblog.so)
   readelf --dyn-syms work/native/libtarget.so # Exported JNI functions & internals
   ```
3. Locate string decryption tables and JNI initialization:
   - Search for `JNI_OnLoad`.
   - Inspect `.rodata` for strings referencing Java classes, reflection signatures (`(Ljava/lang/String;)V`), or C2 URLs.

---

## 2. Emulating Native Decryption Routines with Unicorn

Malware frequently decrypts its C2 URLs or secondary DEX payloads inside a native C function. Rather than reversing complex arithmetic by hand, emulate the function directly using Unicorn Engine.

### AArch64 Emulation Rules
| Hardware Rule | Failure Symptom if Omitted |
|---|---|
| **CPACR_EL1 FP/SIMD Enable** (`\| 3 << 20`) | Crash / fault on floating-point or NEON vector instructions |
| **TLS / TPIDR_EL0 Stack Canary** | Crash on `mrs xN, tpidr_el0` stack protection check |
| **AAPCS64 Calling Convention** | Arguments in `x0`–`x7`; return value in `x0` |
| **Sentinel Return Address (`LR = 0x7F000000`)** | Emulation runs off into unmapped memory |
| **PLT Redirection / Stubs** | Return to `LR` after executing dummy `malloc`/`memcpy` |

### Emulation Harness Template
See `scripts/unicorn_aarch64_harness.py`:
- Maps PT_LOAD segments with page alignment.
- Initializes stack, heap, and zeroed TLS thread pointer.
- Stubs out standard libc calls (`malloc`, `free`, `memcpy`, `__android_log_print`).
- Executes target native function at virtual address `0x...` with test inputs and dumps result buffer.
