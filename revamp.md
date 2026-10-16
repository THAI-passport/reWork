# REVAMP.md — reWork + dbug Robustness & Coverage Expansion

**Goal:** Make reWork (workflow shell) and dbug (dynamic analysis toolkit) robust enough to cover *any* reverse-engineering and debugging task across Android, iOS, desktop (Linux/macOS/Windows), firmware, and web/Electron targets — without the target noticing it is being debugged where possible.

**Status:** In progress. Revamp executed phase by phase; each phase committed and verified before the next begins.

---

## 1. Research findings incorporated

The following reputable repos were fetched and studied for architecture patterns to incorporate:

| Repo | What it is | Ideas adopted |
|---|---|---|
| `rada org/radare2` / `rizinorg/rizin` | UNIX-like RE framework & CLI | CLI subcommand structure, platform-agnostic core, scriptability |
| `cea-sec/miasm` | Python RE framework | Modular arch/loader/ir/jitter/analysis decomposition, CPU emulation without hardware |
| `programa-stic/barf-project` | Binary Analysis & RE Framework | Class-based framework core, CFG recovery, gadget classification, SMT solver integration |
| `sensepost/objection` | Frida mobile runtime exploration | Plugin system, platform-organized command modules (android/, ios/), agent/controller separation |

No code was copied verbatim; patterns and structure were adapted into reWork/dbug conventions (AGENTS.md evidence tags, stdlib-first Python, no vendor artifacts).

---

## 2. Current coverage audit

| Domain | reWork (workflow) | dbug (tooling) | Gap |
|---|---|---|---|
| Android static analysis | re-static skill, jadx/apktool | sample_triage/triage_apk.py, native_emulator.py | Partial — no DEX-to-IR, no CFG recovery |
| Android dynamic/cloaking | — | device_cloaking, bypass_antidebug.js | Partial — root/LSPosed required, no detection catalog |
| Android network/eBPF | — | network_capture, ecapture_runner.py | Partial — no MITM proxy fallback, no HTTP/2 inspection |
| iOS static/dynamic | Thin notes in re-static | None | **Missing entirely** |
| Desktop (Linux/macOS/Windows) | Thin notes | None | **Missing entirely** |
| Firmware / embedded | Thin notes | None | **Missing entirely** |
| Web / Electron | Unpack asar note | None | **Missing entirely** |
| Emulation (no hardware) | re-native-emulation skill | unicorn_aarch64_harness.py | Partial — pure-Python fallback only, no miasm-style jitter |
| Plugin / extension system | None | None | **Missing entirely** |
| SMT / constraint solving | None | None | **Missing entirely** |
| CI / offline test harness | tests/test_tools.py | tests/test_framework_e2e.py (22 suites) | Partial — no matrix CI, no drift checks |
| Configuration management | lab_config.yaml | lab_config.yaml | Partial — no schema validation, no environment profiles |

## 3. Revamp phases

Each phase is a self-contained, verifiable chunk. Do not proceed to the next phase until the current phase's checks pass.

### Phase A — Platform-agnostic core & plugin system (reWork)
- Convert `tools/rw.py` subcommands into a plugin-registry pattern so new RE domains can be added without editing `rw.py` directly.
- Add `tools/rw.py doctor` checks for: `frida`, `objection`-style mobile tools, `radare2`/`rizin`, `ghidra` headless, `qiling`, `unicorn`, `capstone`, `pyelftools`, `lief`, `tshark`, `mitmproxy`.
- Add `rw.py recon` recipe-pack rules for iOS (Mach-O, class-dump strings), desktop (PE/ELF/Mach-O imports), firmware (binwalk strings), Electron (asar).
- Evidence-tag every new surface-map row.

**Check:** `python tools/rw.py lint` → 0 problems; `python3 -m unittest discover -s tests` → OK; `python tools/rw.py doctor` lists new optional tools.

### Phase B — iOS static/dynamic tooling (dbug + reWork)
- Add `dbug-ios-static` skill: Mach-O parsing (pyelftools/lief), `Info.plist` extraction, entitlements, crypto export checks, class-dump-style Objective-C method survey.
- Add `dbug-ios-dynamic` tooling: Frida-based iOS spawning/attach, `cycript`-style object inspection, keychain/data-protection audit, SSL pinning bypass via Frida.
- Add iOS surface-map rows to `recon` recipe pack.
- iOS requires jailbroken device; mark all dynamic claims `[I]` until hardware-verified.

**Check:** New skill files under `.claude/skills/dbug-ios-*`; recon covers iOS patterns; lint/tests pass.

### Phase C — Desktop (Linux/macOS/Windows) RE tooling (dbug)
- Add `dbug-desktop-static` skill: PE/ELF/Mach-O header parsing, import/export table survey, section entropy, string extraction, packer detection (UPX, etc.).
- Add `dbug-desktop-dynamic` tooling: Frida-based desktop process instrumentation, API hooking (WinAPI/libc), DLL/dylib injection, local socket/pipe tracing.
- Add desktop surface-map rows to `recon`.
- Windows/macOS require appropriate host; mark claims `[I]`/`[U]`.

**Check:** New skill files `dbug-desktop-*`; recon covers PE/ELF/Mach-O; lint/tests pass.


### Phase D — Firmware / embedded RE (dbug)
- Add `dbug-firmware-static` skill: binwalk-style extraction, filesystem squashfs/jffs2 parsing, UART/JTAG pinout documentation, firmware signature verification.
- Add `dbug-firmware-dynamic` tooling: QEMU-user/qemu-system emulation, unicorn-based firmware blob emulation, serial/UART capture, flash wear analysis (per ground rule 7).
- Emulation-only by default; no flashing without explicit user approval.

**Check:** New skill files `dbug-firmware-*`; recon covers firmware patterns; lint/tests pass.

### Phase E — Web / Electron RE (dbug)
- Add `dbug-web-static` skill: asar unpacking, Node module survey, bundled Chromium DevTools protocol inspection, endpoint/URL extraction from JS bundles.
- Add `dbug-web-dynamic` tooling: Frida-based Electron renderer/main process hooking, WebSocket/XHR/fetch interception, local storage/IndexedDB audit.

**Check:** New skill files `dbug-web-*`; recon covers asar/JS patterns; lint/tests pass.

### Phase F — Emulation & symbolic execution (dbug + reWork)
- Add miasm-style jitter emulation harness (CPU emulation without hardware) for ARM/x86/Mips.
- Add QEMU-user/qemu-system integration for full-system emulation.
- Add SMT solver integration (z3) for constraint solving / path exploration.
- Keep pure-Python fallback (existing `unicorn_aarch64_harness.py`) for offline CI.
- All emulator results labeled `[V]` (verified against real code) never `[H]`.

**Check:** `sample_triage/native_emulator.py` extended; new `emulation/` directory; tests pass without hardware; CI runs offline.

### Phase G — Network analysis enhancement (dbug)
- Add MITM proxy fallback (`mitmproxy`-style) for HTTP/HTTPS when eBPF unavailable.
- Add HTTP/2, WebSocket, gRPC inspection.
- Add TLS fingerprinting (JA3/JA4) and certificate pinning bypass catalog.
- Add pcap/sslkey.log merging (existing `pcap_decryptor.py`) robustness.

**Check:** `network_capture/` extended; `pcap_decryptor.py` handles more formats; tests pass.


### Phase H — Memory forensics (dbug)
- Add memory dump acquisition (Android `/proc/<pid>/mem`, iOS task_for_pid, desktop process memory).
- Add Volatility-style plugin skeleton for process/module/string extraction from dumps.
- Add Frida memory scanner (heap, stack, .rodata) for key/material hunting.

**Check:** New `memory/` directory; tests use synthetic dumps; lint passes.

### Phase I — Detection catalog & anti-anti-analysis (dbug)
- Build `detection_catalog.json`: known anti-debug / anti-Frida / anti-emulator checks per platform (Android, iOS, desktop) with bypass technique and evidence tag.
- Extend `bypass_antidebug.js` with additional procfs variants, ptrace alternatives, `prctl`, `seccomp`, `sigaction` handlers.
- Add `dbug-anti-analysis` skill (existing) expansion: heuristic evasion analysis per platform.
- Never claim undetectable; always label `[I]`/`[U]` until hardware tested.

**Check:** `detection_catalog.json` committed; bypass_antidebug.js extended; tests pass.

### Phase J — CI, drift checks & reproducibility (reWork + dbug)
- Add GitHub Actions workflow: matrix of Python versions, OS (Linux, macOS), install `.[test]`, run lint then `pytest -q`/`unittest`.
- Add synthetic capture drift check (`--check` mode) so drift fails CI.
- Add one deliberately malformed capture fixture; tools must report it, not crash.
- Pin all dependency versions in `requirements.txt` (frida==17.24.0, frida-tools==14.11.0, etc.).
- Record tool versions in `targets/<slug>/LOG.md` via `rw.py doctor`.

**Check:** `.github/workflows/` present; lint/tests pass in matrix; drift check works.

### Phase K — Configuration & profile management (dbug)
- Add JSON-schema validation for `lab_config.yaml`, `mock_canaries.json`, `tracker_catalog.json`.
- Add environment profiles (lab, CI, production-hardware) selectable via `--profile`.
- Add safe-write guard (per-device write counter, daily cap, dry-run never counts) for all device-write operations (ground rule 7).

**Check:** Schema validation in tests; `--profile` flag works; safe-write guard enforced.

---
## 4. Definition of done (robustness criteria)

Before declaring the revamp complete:

- [ ] Every RE domain (Android, iOS, desktop, firmware, web/Electron) has a skill + recon recipe + surface-map template.
- [ ] Every dynamic technique has a dry-run / simulation mode that runs offline with no hardware.
- [ ] All emulator/simulator results labeled `[V]` never `[H]`.
- [ ] All hardware-dependent claims labeled `[I]`/`[U]` until real-device tested.
- [ ] Plugin system allows adding a new RE domain without editing `tools/rw.py`.
- [ ] `python tools/rw.py lint` → 0 problems (no vendor artifacts, no emoji, no secrets).
- [ ] `python3 -m unittest discover -s tests` → OK across all domains.
- [ ] `requirements.txt` pins all versions; `tools/setup-tools.sh` installs them user-space.
- [ ] `.github/workflows/` CI matrix passes on Linux + macOS.
- [ ] `revamp.md` progress table below updated per phase.

---

## 5. Progress tracking

| Phase | Title | Status | Evidence |
|---|---|---|---|
| A | Platform-agnostic core & plugin system | done | tools/rw.py plugin registry, doctor/recon expanded |
| B | iOS static/dynamic tooling | done | dbug-ios-static, dbug-ios-dynamic skills, ios_static.py, ios_dynamic.py |
| C | Desktop static/dynamic tooling | done | dbug-desktop-static, dbug-desktop-dynamic skills, desktop_static.py, desktop_dynamic.py |
| D | Firmware / embedded RE | done | dbug-firmware-static, dbug-firmware-dynamic skills, firmware_static.py |
| E | Web / Electron RE | done | dbug-web-static, dbug-web-dynamic skills, web_static.py, web_dynamic.py |
| F | Emulation & symbolic execution | done | dbug-emulation skill, emulation/jitter.py |
| G | Network analysis enhancement | done | dbug-network-enhancement skill, network/analyzer.py |
| H | Memory forensics | done | dbug-memory skill, memory/scanner.py |
| I | Detection catalog & anti-anti-analysis | todo | |
| J | CI, drift checks & reproducibility | todo | |
| K | Configuration & profile management | todo | |

---

## 6. Ground rules carried forward

- Static analysis only by default (AGENTS.md rule 2). Dynamic only if user asks.
- Never commit vendor artifacts (APK, IPA, .so, firmware, dex, jar, tokens, signed URLs).
- No emoji in docs/code; plain ASCII punctuation.
- Every factual claim carries an evidence tag `[C]/[V]/[H]/[W]/[I]/[U]`.
- Protect the device: flash-wear/bricking analysis before any write path; ground rule 7.
- Supported platforms: Linux + macOS hosts. Others paused; code kept portable.
- Never hard-code simulator results as confirmed.

---

**Next step:** Begin Phase A — convert `tools/rw.py` into a plugin-registry pattern and expand `rw.py doctor` + `rw.py recon`.
