# Problem & Solution Ledger: dbug Stealth Android Malware Sandbox

This ledger documents technical hurdles, anti-analysis evasion traps, and operational edge cases encountered during the implementation of `dbug`, along with the corresponding architectural and engineering solutions applied.

---

## Issue Log & Resolutions

### 1. Android 10+ SMS Provider Permission Denial (`WRITE_SMS`)
- **Problem / Hurdle:** Executing `content insert --uri content://sms/inbox` from standard unprivileged ADB shell (`shell` UID 2000) fails with:
  `java.lang.SecurityException: Permission Denial: writing com.android.providers.telephony.SmsProvider uri content://sms/inbox from pid=... requires android.permission.WRITE_SMS`
- **Root Cause:** Android 10+ strictly restricts the Telephony ContentProvider so that only the default SMS application or UID 0 (root) can write to the inbox.
- **Solution:**
  - In `config/seed_canaries.py`, implemented automatic root (`su -c`) elevation fallback.
  - Added `use_root: true` parameter to `config/lab_config.yaml`.
  - When invoked on rooted physical test phones, queries and inserts execute with full root privileges, bypassing `WRITE_SMS` restrictions cleanly.

---

### 2. ADB Shell Parameter Escaping & String Corruption
- **Problem / Hurdle:** Inserting synthetic canary SMS messages, contact names, or clipboard strings containing single quotes, spaces, or exclamation marks caused ADB shell syntax errors or corrupted data injection.
- **Root Cause:** Raw string interpolation into `adb shell su -c "..."` without escaping. Additionally, nested `adb shell su -c shell content ...` introduced redundant `shell` tokens into inner commands.
- **Solution:**
  - Refactored `run_adb` across `seed_canaries.py` and `verify_stealth_state.py` to use `shlex.quote`.
  - Implemented a base64 transport pipeline for clipboard seeding:
    `cmd clipboard set-text "$(echo '<base64>' | base64 -d)"`
  - Stripped leading redundant `shell` prefix when constructing the inner `su -c` command string.

---

### 3. ADB Transport Liveness under Masked Properties
- **Problem / Hurdle:** Infostealers query `init.svc.adbd` via `getprop`. Overwriting `init.svc.adbd stopped` via `resetprop` could potentially cause the host ADB daemon to drop or freeze the debugging session.
- **Root Cause:** The `init.svc.adbd` property reports the service state to user-space applications, while the underlying Linux kernel socket and `adbd` transport daemon remain bound and operational over USB or TCP.
- **Solution:**
  - Confirmed and verified that `resetprop init.svc.adbd stopped` successfully masks the property for unprivileged `getprop` callers while leaving the ADB transport socket completely intact.
  - Added Layer 5 ADB transport resilience verification to `device_cloaking/verify_stealth_state.py` to assert that caller UID responds and commands execute cleanly after property changes.

---

### 4. Detection of In-Process Settings Hooks by Evasive Malware
- **Problem / Hurdle:** Traditional analysis environments inject in-process Frida hooks to intercept `Settings.Global.getInt("adb_enabled")`. Evasive infostealers scan `/proc/self/maps` for `frida-agent.so` or evaluate timing discrepancies to detect hooking, aborting execution.
- **Root Cause:** In-process memory modification directly in the malware's address space creates detectable memory anomalies.
- **Solution:**
  - Implemented system-level provider spoofing via LSPosed `HideDevMode` (Gate G1).
  - The spoofing occurs at the `system_server` IPC provider level (UID 1000). When the unprivileged malware process queries `SettingsProvider`, the system returns `0` with zero in-process hooks inside the target process.
  - Maintained `instrumentation/agent/bypass_antidebug.js` strictly as an optional fallback when LSPosed is unavailable.

---

### 5. TLS Certificate Pinning & Evasion of MitM Proxies
- **Problem / Hurdle:** Modern Android infostealers employ OkHttp `CertificatePinner` or custom native trust stores, refusing TLS connections if an untrusted proxy CA is encountered. Furthermore, setting `http.proxyHost` is immediately detected via `System.getProperty("http.proxyHost")`.
- **Root Cause:** MitM proxies (Burp Suite, mitmproxy, Charles) require breaking TLS certificates and configuring OS-level proxy settings.
- **Solution:**
  - Replaced MitM proxies with external Linux transparent Wi-Fi routing (`network_capture/gateway_setup.sh`) on `ap0` with `iptables` NAT masquerade.
  - Intercepted TLS master secrets (`sslkey.log`) and decrypted packet streams (`tls_decrypted.pcapng`) out-of-band via Linux kernel eBPF uprobes on `/apex/com.android.conscrypt/lib64/libssl.so` using `eCapture` on `wlan0`.
  - Zero device proxy properties, zero custom CA certificates, and zero VPN (`tun0`) interfaces are instantiated on the test phone.

---

### 6. Application-Layer Pre-Encryption of Stolen Canary Data
- **Problem / Hurdle:** Even when TLS traffic is decrypted using eCapture master keys, stolen data payloads can appear as encrypted blobs if the malware applies symmetric encryption (AES, DES, RC4, or multi-round XOR) in memory before sending.
- **Root Cause:** Threat actors encrypt payloads at the application layer prior to dispatching them over HTTPS POST or Telegram Bot APIs.
- **Solution:**
  - Implemented `instrumentation/agent/crypto_dumper.js` hooking `javax.crypto.Cipher.init()` and `Cipher.doFinal()`.
  - Dynamic extraction at `doFinal()` captures pre-encryption plaintext input buffers, algorithm specifications, secret keys, and IVs.
  - `parser_correlator/canary_hunter.py` correlates pre-encryption memory dumps directly with decrypted network streams to prove the origin and transmission of stolen canary credentials.

---

### 7. Multi-Platform Host Portability & CI Testability
- **Problem / Hurdle:** Analysts operating on macOS workstations or running CI test pipelines without physical rooted Android hardware or secondary Wi-Fi AP adapters encounter execution crashes when running host scripts.
- **Root Cause:** Hard dependencies on physical hardware tools (`adb`, `iptables`, `tshark`, `ecapture`).
- **Solution:**
  - Implemented complete `--dry-run` simulation modes across all framework tools:
    - `sample_triage/triage_apk.py --dry-run`
    - `config/seed_canaries.py --dry-run`
    - `device_cloaking/verify_stealth_state.py --dry-run`
    - `network_capture/gateway_setup.sh --dry-run`
    - `network_capture/ecapture_runner.py --dry-run`
    - `instrumentation/frida_loader.py --dry-run`
    - `parser_correlator/pcap_decryptor.py --dry-run`
    - `parser_correlator/yara_generator.py`
    - `orchestrator.py --dry-run`
  - Implemented fallback regex parsers in Python tools so missing PyYAML or Frida dependencies do not crash offline pipelines.

---

### 8. Blind Dynamic Execution Without Static Profiling (Gate G0)
- **Problem / Hurdle:** Executing an unknown APK without static assessment risks deploying an incompatible architecture, triggering immediate evasion checks that were easily predictable, or missing packed payloads.
- **Root Cause:** Dynamic-only sandboxes lack context on manifest permissions, accessibility abuse, and packer wrappers before launching on device.
- **Solution:**
  - Implemented `sample_triage/triage_apk.py` (Gate G0) to safely unpack the APK, calculate cryptographic hashes, inspect native libraries for packers (`libjiagu.so`, `libsecmain.so`, `libstub.so`), extract high-risk permissions (`BIND_ACCESSIBILITY_SERVICE`, `READ_SMS`), and scan DEX string tables for anti-analysis cues and hardcoded C2s.
  - Generates `targets/<hash>/STATIC_AUDIT.md`, `TARGET.md`, `SOURCES.md`, and `FACTS.md` per `AGENTS.md` guidelines before physical device launch.

---

### 9. Immediate Defensive Operationalization (Automated YARA Synthesis)
- **Problem / Hurdle:** Analysts observing live C2 traffic had to manually draft YARA rules post-analysis to deploy to endpoint detection agents and firewalls.
- **Root Cause:** Lack of automated threat intelligence compilation linking IOC extraction to signature engineering.
- **Solution:**
  - Implemented `parser_correlator/yara_generator.py` directly integrated into `orchestrator.py`.
  - Automatically synthesizes production-ready YARA rules matching APK zip magic, package name, anti-analysis strings, and unique observed C2 domains/endpoints.

---

### 10. Native ptrace Anti-Debugging & Root Detection Evasion
- **Problem / Hurdle:** Advanced infostealers invoke native `ptrace(PTRACE_TRACEME, 0, 1, 0)` or inspect `/system/bin/su` via `access()`, self-terminating if a debugger is attached or root is detected.
- **Root Cause:** Native checks bypass Java-level hooks by calling `libc.so` primitives directly.
- **Solution:**
  - Enhanced `instrumentation/agent/bypass_antidebug.js` with native Interceptors for `ptrace` (spoofing return code 0 on `PTRACE_TRACEME`), `access` (spoofing `-1` on `/su` and `magisk` checks), and `kill` (logging caller backtrace on self-termination attempts).

---

### 11. Native Obfuscated String Decryption in Packed Native Libraries
- **Problem / Hurdle:** Advanced infostealers (Ermac, Hook, Medusa) pack C2 URLs, decryption keys, and Telegram tokens inside native `.so` libraries (e.g., `lib/arm64-v8a/libnative-crypto.so`). Static DEX decompilation reveals only empty stubs or JNI wrappers, and running them dynamically on device risks early evasion.
- **Root Cause:** C2 strings are decrypted in memory during runtime via custom unrolled XOR loops or `JNI_OnLoad` initialization routines.
- **Solution:**
  - Implemented `sample_triage/native_emulator.py` (Gate G0).
  - Emulates AArch64 native code routines using Unicorn engine when available, with a pure-Python AArch64 emulation fallback for headless/dry-run environments.
  - Automatically loads ELF PT_LOAD segments, sets up stack, TLS, and scratch memory, and emulates string decryption loops, extracting plaintext C2 endpoints with evidence tag `[C]`.

---

### 12. Omission of Canary Token Identifiers in Search Index
- **Problem / Hurdle:** When malware exfiltrated the canary token identifier itself (e.g. `CANARY_SMS_OTP_9921`) rather than the inner payload values, the canary hunter failed to report a correlation hit.
- **Root Cause:** In `parser_correlator/canary_hunter.py`, `field_key == "canary_token"` was explicitly skipped during target pattern generation.
- **Solution:**
  - Updated `load_canary_targets()` to index all string fields including `canary_token`.
  - Ensures 100% correlation coverage whether malware transmits the token ID, synthetic private keys, seed words, or mock OTP codes.

---

### 13. Canonical Workspace Synchronization & Evidence Integrity
- **Problem / Hurdle:** Automated dynamic analysis emitted deliverables into timestamped session directories (`sessions/session_<ts>_<pkg>/`), leaving the canonical `targets/<sample_hash>/` directory out-of-sync with Gate G1 through G5 deliverables.
- **Root Cause:** Analysis runs generated artifacts in session-specific temporary folders without a final reconciliation step.
- **Solution:**
  - Implemented `sync_canonical_target_repo()` in `orchestrator.py`.
  - Automatically updates `targets/<sample_hash>/` and `targets/current_sample/` with `TARGET.md` (gates marked PASS), `SOURCES.md`, `FACTS.md`, `STATIC_AUDIT.md`, `ANALYSIS.md`, `REPORT.md`, `LOG.md`, and `IOCS.json`.

---

### 14. Evasion of Commercial RASP & Anti-Tamper Protections in AppSec Audits
- **Problem / Hurdle:** Commercial enterprise and banking applications employ sophisticated RASP protections (DexGuard, Promon SHIELD, Arsan) that crash or exit upon detecting USB debugging or proxy settings, preventing penetration testing.
- **Root Cause:** AppSec auditors traditionally rely on manual Wi-Fi proxies (Burp Suite, Charles) and user CA certificates, both of which are instantly fingerprinted.
- **Solution:**
  - Applied `dbug`'s out-of-band architecture to commercial testing via `--profile appsec`.
  - Routes traffic through Linux Wi-Fi AP (`ap0`) and decrypts TLS via eBPF Conscrypt uprobes on `wlan0`. Zero proxy and zero user CA certificates are used, allowing analysts to inspect API traffic of heavily protected commercial apps cleanly.

---

### 15. Covert PII Transmission into Third-Party Advertising SDKs
- **Problem / Hurdle:** Commercial mobile applications frequently bundle closed-source ad attribution and analytics SDKs (Meta Graph, AppsFlyer, TikTok Pangle) that harvest clipboard data, contacts, or device identifiers without disclosure in privacy policies.
- **Root Cause:** Third-party SDK traffic is encrypted inside standard HTTPS tunnels and mixed with legitimate first-party application calls.
- **Solution:**
  - Implemented `parser_correlator/privacy_auditor.py` and `config/tracker_catalog.json` (`--profile privacy`).
  - Classifies destination endpoints into First-Party vs Third-Party Trackers and correlates canary data hits, generating compliance findings under GDPR Art. 5/6 and CCPA.

---

### 16. Manual API Discovery and OpenAPI Specification Bottleneck
- **Problem / Hurdle:** Mobile application penetration testing and API fuzzing require importing target endpoints into Burp Suite, Postman, or OWASP ZAP. Manually constructing API schemas from decrypted PCAP flows is time-consuming and error-prone.
- **Root Cause:** Mobile applications lack public OpenAPI/Swagger definitions.
- **Solution:**
  - Implemented automated OpenAPI 3.0 specification synthesis in `parser_correlator/appsec_auditor.py`.
  - Automatically extracts unique HTTP paths, query parameters, methods, and JSON request bodies from decrypted flows, writing `openapi_spec.json` ready for immediate fuzzing tool ingestion.

---

### 17. Single-Domain Tooling Bias (Malware-Centric Reporting Bias)
- **Problem / Hurdle:** Commercial AppSec penetration testers and privacy compliance auditors were presented with malware threat intelligence terminology ("C2 Servers", "Bot Tokens", "Banking Trojan") when evaluating legitimate fintech or e-commerce apps.
- **Root Cause:** Static templates in `orchestrator.py` hardcoded malware classification headers for `TARGET.md` and `REPORT.md` regardless of the input target type.
- **Solution:**
  - Refactored `orchestrator.py` `_sync_target_workspace` to dynamically tailor `REPORT.md` and `TARGET.md` based on `--profile {malware,privacy,appsec,all}`.
  - Authored comprehensive `README.md`, `docs/SOP.md`, and updated `AGENTS.md` and `REPO_ROADMAP.md` to elevate commercial AppSec and privacy auditing to co-equal first-class citizens.



