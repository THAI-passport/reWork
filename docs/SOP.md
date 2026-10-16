# SOP: reverse engineering a smartwatch companion app

Generic procedure, tool tricks and lessons. Skills under `.claude/skills/` hold the detailed procedures; this file is the map and the memory. AGENTS.md requires updating it after each decompile or code-reading pass: add what was learned that applies beyond one target, remove what turned out wrong, and keep target-specific facts in `targets/<slug>/`.

Principle: software first, hardware last. Order: public information, the app (static), native libraries (disassemble, emulate), existing captures, and only then, with the owner's approval, read-only contact with the owner's own watch. Physical work is a last resort for a named unknown that software could not settle.

## 1. Procedure by gate
| Gate | Do | Skill |
|---|---|---|
| G0 | slug, goal, assumptions; `python tools/rw.py init`, `doctor`; read `re-watch-targets` first questions | re-workflow, re-watch-targets |
| G1 | find the app, download from a reputable source, validate, hash, pin | re-acquire |
| G2 | decompile, map transports, services, entry points, stored keys | re-static, re-ble-android-patterns, re-jieli if it applies |
| G3 | byte-exact spec with worked vectors; emulate native routines | re-protocol-spec, re-native-emulation |
| G4 | layered client, simulator, dry-run, tests, lint | re-client-sim |
| G5 | handoff and recon task pack | re-workflow, re-hardware-recon |

## 2. Tool setup and probing
- `python tools/setup_tools.py` installs a user-space JDK, jadx and apktool at pinned versions (no admin rights). Probe each tool with a version flag before relying on it. `python tools/rw.py doctor` lists what is missing.
- Run long jobs detached and read the log; a foreground call can be cut by the agent shell's time limit.
- Python tools use only the standard library so they run on Linux, macOS and Windows; shell files are thin wrappers.

## 3. Acquiring and pinning
- Prefer an official source, else a reputable mirror. Listing sites disagree on version and size; use them as hints and trust the file's own manifest.
- `.xapk` and `.apks` are zips: a base APK, split APKs (native libs per ABI, language, density) and `manifest.json`. Extract only the base APK first and the arm64 split when native code matters. `unzip -t` before anything else.
- Pin by exact version and SHA-256, never by a floating "latest" link. Record a versioned or mirrored URL and where the owner keeps the exact copy (`COPY_LOCATION`, no secrets). A new vendor release is a NEW pinned entry; never edit the old hash. `--accept-new-hash` is for inspection only and the user must be told. Details: `re-acquire`, AGENTS.md.
- Rebuild on a new machine with `python tools/rebuild_analysis.py <slug>` (try `--dry-run`). Rebuild only when a named `[I]`/`[U]` claim needs the code; read the target docs first.

## 4. Decompiling
- jadx first (`-j 4`). Exit code 3 only means some methods failed to decompile. Progress output uses carriage returns: `tr '\r' '\n' < log | grep -v progress`.
- On a small or busy machine jadx can stall and be killed (exit 137): cap the heap (`--max-heap 3g` in the rebuild tool, or `JAVA_OPTS=-Xmx3g`).
- Where a method fails, read smali (`apktool d --no-res`), re-run `jadx -m simple --show-bad-code`, or use dex2jar plus CFR (`tools/recover-failed-methods.sh`). Record behaviour, not code.
- Obfuscated names do not matter: follow framework calls, string constants and stored keys; start from the UI action.
- Grep is slow on a 10k-file tree: use ripgrep with fixed strings and narrow paths.

## 5. Packer and protection triage
Signs of a packed or protected app: a tiny `classes.dex` with a stub Application class, native libraries named after protection vendors (for example names containing "jiagu", "shell", "DexHelper", "secexe" [W]), encrypted blobs in assets, `System.load` of an unpack routine, almost no BLE code in the visible tree.
- Triage means identify and record, then stop and tell the user. Do not defeat the protection.
- Alternatives that are in scope: an older or regional build of the same app that is not packed, vendor SDK documentation, third-party write-ups, captures the owner already has, and the standard-GATT layer, which needs no app code.
- Record the finding in the target's LOG.md and FACTS.md as `[C]` (what shows it) and the options.

## 6. Native libraries
Disassemble with capstone and pyelftools; emulate with unicorn; port stage by stage and compare each stage against the emulated routine; keep emulator vectors as tests that skip cleanly when the extras are missing. A negative result ("this library holds no limits") is a result. See `re-native-emulation`, `re-jieli`.

## 7. Captures
Ingest HCI snoop and pcap files with `tools/btcap.py`; map handles to UUIDs, reassemble across MTU chunks, validate checksums, report bad frames instead of dropping them. Scrub before storing; never commit raw captures. See `re-capture-ingestion`.

## 8. Tests and simulators
Build a software device from the spec to test the client, but a simulator written by you proves consistency only. Keep every uncertain value a named constant or flag so first hardware contact needs flag changes. Run `python3 -m unittest discover -s tests` and `python3 tools/rw.py lint` before each commit.

## 9. Lessons carried over from worked examples (reBeamBox e-badge, reWatch watches)
- One app may contain several transports chosen by name, service discovery or a server catalog; build a table before choosing one.
- Which transport a model uses was settled by third-party hardware reports, not by the app: label such claims `[W]` and keep a flag.
- Third-party reports contradicted an earlier code-based assumption; the fix was a documented default plus an option for the other behaviour.
- A wrong field width in a hand-written simulator stalled a transfer in the client's own test; bugs can be symmetric.
- Docs drift: do not write test counts in prose; keep disputed values in one FACTS.md; scan for contradictions after each milestone (that scan found a real client bug).
- Safe-write for storage: counter, delta skipping, minimum interval, daily cap, applied after the payload is known and before the first data frame.
- Check every claim in a task pack against the real flags; invented flags waste the first hardware session.
- Budget smartwatch ecosystem reality: models with similar numbering (e.g. T900 vs C900) often originate from completely different ODM solution houses and silicon architectures (JieLi Pi32 vs Bluetrum RISC-V). Build modular profile selectors rather than assuming monolithic protocol compatibility.
- Critical hazard: budget OTA bootloader services (such as Bluetrum Cus5610 0x18A8 and JieLi 0xAE10) often lack memory boundary checks and overwrite executing code when written to over BLE. Hard-blacklist OTA service UUIDs at the client link layer. (2026-10-14: neither id has a primary source; keep them blocked. Jieli OTA is documented on 0xAE00 itself, so also refuse OTA opcodes, not only services.)
- In-memory simulation speed: do not introduce artificial chunk pacing sleeps in unit test simulators; guard sleep delays with hardware link checks so test suites finish in milliseconds.

## 10. After each pass (checklist)
1. PROTOCOL.md: byte-level findings with tags and the source class and method.
2. FACTS.md: disputed values.
3. LOG.md of the target: every problem with cause and fix, or Unsolved plus what was tried.
4. This SOP or a skill: procedure, flags, dead ends, tricks that help the next target. Promote repeats and delete the repetition.
5. FIXES.md: anything wrong in reWork itself.
6. Commit, then push to the work branch.

## Lessons from the first watch benchmark pass (reWatch, 2026-10-12)
- When the artifact is blocked, still finish G0 and seed PROTOCOL/FACTS from the third-party document as `[W]`, then build the pure codec and simulator ahead with every layout value a named constant. A hand-computed vector in a test is own arithmetic, not evidence; say so in the test.
- Read a third-party frame layout for internal contradictions before coding it (here the ack header 0xFD versus the app header 0xDF, and what the length field counts); each goes into FACTS.md as a dispute.

## Lessons from the skill review (2026-10-14)
- Triage the app framework before grepping Java: Flutter keeps logic in `libapp.so`, React Native in `assets/index.android.bundle` (Hermes or JS). See `re-static`.
- aarch64 unicorn: CPACR_EL1 FP/SIMD on, a TLS page for TPIDR_EL0, PLT hooks return to LR, return to a mapped sentinel. Harness and table in `re-native-emulation`.
- Protobuf payloads: `protoc --decode_raw` on samples before naming fields. See `re-protocol-spec`.
- Always record the ABI split of an XAPK/APKS; natives live only there.
- Scrub capture summaries with `tools/scrub_capture.py` before committing; review the output by eye.
- Check a task pack with `python tools/rw.py taskflags <slug>` before handing it off.
- A skill description should say what a user would ask, not only which gate it belongs to.



---

# --- dbug framework (merged from cline/ya8xm47p-dbug-merge) ---

# dbug: Standard Operating Procedures (SOP) & Analysis Runbook

This document defines the official Standard Operating Procedures (SOP) for conducting dynamic analysis, threat intelligence extraction, regulatory privacy auditing, and application security penetration testing using the `dbug` framework.

---

## SOP-01: Laboratory Setup & Isolation

### 1. Objective
Establish a physically isolated, zero-trace testing environment consisting of an external Linux Wi-Fi Access Point (`ap0`) and a dedicated rooted Android test device.

### 2. Pre-Requisites
- Host machine running Linux (Debian/Ubuntu) or macOS connected to a Linux gateway host.
- Physical Android test device (Android 12-14, ARM64) rooted via Magisk, KernelSU, or APatch, with LSPosed installed.
- USB connection to test device for ADB automation.
- Dedicated Wi-Fi adapter on the Linux host configured for `hostapd`.

### 3. Procedure
1. Initialize the isolated Wi-Fi gateway on the Linux host:
   ```bash
   sudo bash network_capture/gateway_setup.sh start --config config/lab_config.yaml
   ```
2. Verify that interface `ap0` is active and `ip_forward` is enabled:
   ```bash
   ip addr show ap0
   cat /proc/sys/net/ipv4/ip_forward  # Must return 1
   ```
3. Connect the Android test device exclusively to the SSID broadcast by `ap0`. Verify the device receives an IP in the `192.168.44.0/24` subnet.
4. Apply system property cloaking on the Android device:
   ```bash
   adb shell su -c "sh /data/local/tmp/apply_stealth_props.sh"
   ```
5. Run the pre-flight verification script on the host workstation:
   ```bash
   python3 device_cloaking/verify_stealth_state.py --config config/lab_config.yaml
   ```
   **STOP CONDITION:** If any pre-flight check returns `FAIL`, do not proceed with dynamic execution until remediated.

---

## SOP-02: Malware Threat Intelligence & C2 Extraction (`profile: malware`)

### 1. Objective
Analyze captured Android infostealers, banking trojans, and spyware to extract C2 infrastructure, Telegram bot tokens, exfiltrated mock data proofs, STIX 2.1 threat bundles, and defensive YARA rules.

### 2. Procedure
1. Seed high-entropy synthetic canary credentials on the device:
   ```bash
   python3 config/seed_canaries.py --seed --config config/lab_config.yaml
   ```
2. Verify that `sinkhole_mode` is configured appropriately in `config/lab_config.yaml`:
   - Set `sinkhole_mode: true` for initial unknown samples.
   - Set `sinkhole_mode: false` for active C2 infrastructure tracking.
3. Launch the automated dynamic analysis session:
   ```bash
   python3 orchestrator.py \
       --apk samples/malware_sample.apk \
       --profile malware \
       --duration 120
   ```
4. Review generated threat intelligence artifacts in `targets/<sample_sha256>/`:
   - `REPORT.md`: Executive threat intelligence summary.
   - `ANALYSIS.md`: Runtime behavioral findings and evidence tags.
   - `IOCS.json`: Structured list of C2 domains, IPs, and bot tokens.
   - `threat_report_stix21.json`: Standards-compliant STIX 2.1 threat bundle.
   - `C2_PROTOCOL.md`: Reconstructed wire transport framing.
   - `FAMILY_ATTRIBUTION.json`: Heuristic malware family classification.
   - `Android_Infostealer_*.yar`: Defensive YARA signature.

---

## SOP-03: Commercial App Privacy & Ad-Tracker Audit (`profile: privacy`)

### 1. Objective
Audit commercial applications (e-commerce, gaming, social media) for undisclosed PII harvesting, tracking SDK bundling, and compliance with GDPR Article 5/6, CCPA, and App Store Privacy Manifest declarations.

### 2. Procedure
1. Plant synthetic canary PII (contacts, SMS OTPs, clipboard data) on the device:
   ```bash
   python3 config/seed_canaries.py --seed --config config/lab_config.yaml
   ```
2. Launch the privacy auditing session:
   ```bash
   python3 orchestrator.py \
       --package com.example.commercial \
       --profile privacy \
       --duration 120
   ```
3. Inspect privacy audit deliverables in `targets/<target_id>/`:
   - `PRIVACY_AUDIT.md`: Compliance report evaluating data minimization and disclosure.
   - `privacy_findings.json`: Categorized tracker domains and severity levels.
   - `CANARY_EXFIL_HITS.json`: Evidence of canary data sent to third-party ad networks.

---

## SOP-04: Commercial AppSec & Interactive Pen-Testing (`profile: appsec`)

### 1. Objective
Conduct penetration testing and API reverse-engineering against commercial applications with heavy RASP defenses (fintech, banking, healthcare) without triggering anti-tamper mechanisms.

### 2. Procedure
1. Verify device cloaking (`verify_stealth_state.py PASS`).
2. Launch the session in interactive mode:
   ```bash
   python3 orchestrator.py \
       --package com.example.fintech \
       --profile appsec \
       --interactive
   ```
3. On the physical Android test device:
   - Launch the application manually if not auto-spawned.
   - Complete authentication (log in with test credentials).
   - Complete Multi-Factor Authentication (SMS/TOTP) if prompted.
   - Exercise application views: profile, balance check, transaction history, funds transfer, settings.
4. In the host workstation terminal, press `Enter` to conclude the observation window.
5. The orchestrator will automatically:
   - Terminate network capture and flush eBPF TLS buffers.
   - Pull master secrets and decrypt all HTTPS streams.
   - Audit cryptographic operations against OWASP MASVS-CRYPTO.
   - Synthesize a valid OpenAPI 3.0 specification (`openapi_spec.json`).
   - Generate `API_SECURITY_REPORT.md`.

---

## SOP-05: Burp Suite & Postman Integration Workflow

### 1. Objective
Import the synthesized OpenAPI 3.0 specification into vulnerability scanners and API testing suites for automated fuzzing.

### 2. Burp Suite Professional Workflow:
1. Locate the synthesized specification in `targets/<target_id>/openapi_spec.json`.
2. In Burp Suite, open the Extender tab and install **OpenAPI Parser** (from the BApp Store).
3. Under the Extensions tab, select OpenAPI Parser and click **Browse** to load `openapi_spec.json`.
4. Burp Suite will parse all routes, parameters, and headers directly into the Target Site Map.
5. Send target endpoints to **Burp Scanner** for active audit or **Burp Intruder** for authorization fuzzing.

### 3. Postman Workflow:
1. Open Postman and click **Import**.
2. Drag and drop `openapi_spec.json`.
3. Select **Import as Collection with API**.
4. Configure collection-level environment variables (e.g., `{{baseUrl}}`, `{{token}}`).
5. Execute automated test runs using Postman Runner / Newman.

---

## SOP-06: Post-Analysis Teardown & Canary Hygiene

### 1. Objective
Ensure zero residual state, clean up synthetic credentials, and prevent artifact cross-contamination between test sessions.

### 2. Procedure
1. Force-stop and uninstall the target application:
   ```bash
   adb uninstall <package_name>
   ```
2. Purge all synthetic canary contacts, SMS messages, and clipboard text:
   ```bash
   python3 config/seed_canaries.py --clean --config config/lab_config.yaml
   ```
3. Remove temporary staging binaries from the test device:
   ```bash
   adb shell "rm -f /data/local/tmp/sample.apk /data/local/tmp/sslkey.log /data/local/tmp/tls_decrypted.pcapng"
   ```
4. Verify all output artifacts are safely archived in `sessions/<session_id>/` and `targets/<target_id>/`.
