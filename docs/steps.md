# Steps Log: dbug Engineering & Analysis Ledger

All engineering choices, tool selections, and analysis decisions are logged chronologically.
Format conforms to `dbug-step-rationale`. Timestamps are in Asia/Saigon (+07:00).

---

## 2026-10-16

- **Step:** Initialized framework documentation, roadmap structure, and task initialization plan.
  **Decision:** Standardized on `task-init.md`, `REPO_ROADMAP.md`, `malware_debugger.md`, and `.claude/skills/`; rejected: unstructured ad-hoc implementation without gate tracking.
  **Rationale:** Analysis of evasive Android malware requires strict operational discipline, pre-flight gate enforcement, and zero analysis leakage.
  **Evidence:** [C] Repository mandate in `AGENTS.md`.
  **Revisit if:** Repository structure or gate definitions are updated.

- **Step:** Phase 1 implementation kickoff - Configuration & Canary Data Seeding (`config/`).
  **Decision:** Created declarative `config/lab_config.yaml`, high-entropy `config/mock_canaries.json`, and automated `config/seed_canaries.py` with multi-mechanism fallback (root `su -c` and unprivileged shell, multi-provider clipboard injection, and `--dry-run` simulation mode).
  **Decision:** Adopted strict `CANARY_` prefixed tokens with high-entropy identifiers (e.g., `CANARY_SMS_OTP_9921`, `0xCANARY...`); rejected: generic or realistic-only strings lacking unique canary prefixes.
  **Rationale:** Generic fake strings (e.g., standard phone numbers or random words) cause false-positive matches when scanning network dumps or decompiled trees. High-entropy prefixed strings guarantee 100% precision during correlation.
  **Evidence:** [C] Schema and correlation engine requirements in `dbug-canary-seeding` and `dbug-canary-correlation`.
  **Revisit if:** Target sample specifically implements heuristic string checks filtering out strings containing "CANARY" (if detected, rotate prefix to randomized high-entropy hex markers).

- **Step:** Phase 2 implementation - On-Device Stealth Cloaking (`device_cloaking/`).
  **Decision:** Implemented `device_cloaking/apply_stealth_props.sh` using root `resetprop` in memory (`ro.debuggable=0`, `ro.secure=1`, `sys.usb.state=mtp`, `sys.usb.config=mtp`, `init.svc.adbd=stopped`) with `apply`, `restore`, `status`, and `verify` modes.
  **Decision:** Kept `adbd` transport alive via USB/TCP while masking user-space properties via `resetprop init.svc.adbd stopped`; rejected: shutting down `adbd` or using standard Developer Options unmasked.
  **Rationale:** Infostealers query `ro.debuggable`, `sys.usb.state`, and `init.svc.adbd` to determine if ADB is attached. Masking properties in memory allows continuous host automation while presenting stock production state to the target process.
  **Evidence:** [C] Threat model in `malware_debugger.md` line 28; [C] anti-analysis cues in `dbug-device-cloaking`.
  **Revisit if:** Target sample executes native code inspecting physical hardware descriptors or USB bus descriptors directly via sysfs.

- **Step:** Implemented `device_cloaking/check_lsposed_devmode.sh` for system_server SettingsProvider audit.
  **Decision:** Verified `Settings.Global.adb_enabled` and `development_settings_enabled` at the system_server IPC layer (LSPosed `HideDevMode`); rejected: injecting in-process Frida hooks into malware process to fake settings.
  **Rationale:** In-process hooks in the malware address space alter memory layouts and can be fingerprinted by anti-hooking heuristics or watchdog threads. Spoofing at the `system_server` Binder provider level leaves zero process artifacts in the malware.
  **Evidence:** [C] `dbug-device-cloaking` Section 2; [C] `AGENTS.md` stealth hierarchy rule 3.
  **Revisit if:** Device runs KernelSU/APatch without Zygisk/LSPosed installed (fallback to in-process hook `bypass_antidebug.js`).

- **Step:** Implemented 5-layer pre-flight audit suite in `device_cloaking/verify_stealth_state.py`.
  **Decision:** Automated checks across system properties, SettingsProvider flags, VPN/tun network interfaces, system proxy properties, and default Frida TCP port 27042 (`:69A2`), with automated `--push-and-apply`, `--restore`, and `--dry-run` modes.
  **Rationale:** Pre-flight gate G1 enforcement prevents accidental malware detonation in an unmasked environment, eliminating wasted analysis runs and adversary evasion triggers.
  **Evidence:** [C] Gate G1 requirements in `AGENTS.md` and `REPO_ROADMAP.md`.
  **Revisit if:** Android 15+ deprecates or refactors getprop interfaces or introduces new framework anti-debug APIs.

- **Step:** Implemented `network_capture/gateway_setup.sh` for zero-footprint network capture.
  **Decision:** Configured transparent external Linux Wi-Fi AP (`ap0`) with iptables NAT masquerade and raw `tcpdump` capture (`-s 0 -w raw_traffic.pcap`); rejected: on-device VPN capture apps (PCAPdroid, Charles) or setting Wi-Fi HTTP proxies.
  **Rationale:** Infostealers query `http.proxyHost` and inspect network interfaces for `tun0` or `ppp0`. External routing at the gateway host leaves zero on-device artifacts or transport flags.
  **Evidence:** [C] `malware_debugger.md` lines 16-17; [C] `dbug-network-gateway` section 1.
  **Revisit if:** Analyst host workstation lacks secondary 802.11 nl80211 AP adapter (use dedicated Linux AP router or routed bridge).

- **Step:** Implemented `network_capture/ecapture_runner.py` for out-of-band TLS plaintext capture.
  **Decision:** Kernel eBPF uprobes on `/apex/com.android.conscrypt/lib64/libssl.so` via static ARM64 `ecapture` on `wlan0`, generating `sslkey.log` and `tls_decrypted.pcapng`; rejected: installing user CA certificates into Android trust store.
  **Rationale:** Infostealers enforce TLS certificate pinning (OkHttp CertificatePinner) and terminate execution if an unrecognized CA is detected. eBPF uprobes extract plaintext and master secrets directly from kernel memory without touching the malware address space.
  **Evidence:** [C] `dbug-ebpf-capture` section 1; [E] eBPF uprobes on `SSL_read`/`SSL_write`.
  **Revisit if:** Target sample statically links custom BoringSSL/OpenSSL into its own native ELF library instead of using Conscrypt (fallback to in-process Frida hooks).

- **Step:** Implemented in-process fallback stealth cloak in `instrumentation/agent/bypass_antidebug.js`.
  **Decision:** Surgical hooks on `Settings.Global.getInt`, `Debug.isDebuggerConnected()`, and `__system_property_get`; rejected: blanket hooking of all Java reflection or classloaders.
  **Rationale:** Heavy-handed hooks introduce timing anomalies that trip anti-analysis watchdogs. Surgical interception addresses specific evasion checks without bloating call stacks.
  **Evidence:** [C] Threat model in `dbug-anti-analysis` section 1; [C] `instrumentation/agent/bypass_antidebug.js`.
  **Revisit if:** Target sample performs anti-hooking scans against memory maps (`/proc/self/maps` for `frida-agent.so`).

- **Step:** Implemented pre-network crypto extraction in `instrumentation/agent/crypto_dumper.js`.
  **Decision:** Intercepted `javax.crypto.Cipher.init()` and `Cipher.doFinal()`, extracting algorithm, secret key bytes, IV bytes, plaintext input, and ciphertext output; rejected: reverse engineering custom obfuscated cipher algorithms statically.
  **Rationale:** Dynamic extraction at the `doFinal()` bottleneck captures the payload in cleartext regardless of whether the cipher was AES, DES, RC4, or multi-round XOR.
  **Evidence:** [M] Memory hook output in `instrumentation_events.jsonl`; [C] `dbug-frida-instrumentation`.
  **Revisit if:** Malware executes proprietary native encryption in C/C++ without invoking standard Java `Cipher` APIs (fallback to native `send()` or Unicorn emulation).

- **Step:** Implemented low-level socket tracer in `instrumentation/agent/socket_tracer.js` and loader in `instrumentation/frida_loader.py`.
  **Decision:** Hooked native `libc.so` `connect()`, `send()`, and `sendto()`, streaming telemetry over non-standard Frida port 38921; rejected: default port 27042.
  **Rationale:** Catches raw non-HTTP socket C2 beacons while masking the instrumentation port from local port enumerations.
  **Evidence:** [C] `malware_debugger.md` lines 28-29; [M] `instrumentation_events.jsonl`.
  **Revisit if:** Malware detects Frida through thread name checks or anonymous executable page scanning.

- **Step:** Implemented TLS packet decryptor in `parser_correlator/pcap_decryptor.py`.
  **Decision:** Integrated `tshark` TLS keylog decryption (`-o tls.keylog_file:<keylog>`) with fallback simulated flows; rejected: manual packet reassembly or proxy logs.
  **Rationale:** Out-of-band TLS master secrets (`sslkey.log`) captured via eBPF enable 100% deterministic decryption of raw Wi-Fi gateway frames without device certificates.
  **Evidence:** [E] eBPF NSS master secret; [N] raw L3/L4 gateway PCAP frames.
  **Revisit if:** Target malware utilizes non-TLS proprietary protocol over custom TCP port.

- **Step:** Implemented multi-encoding canary correlation engine in `parser_correlator/canary_hunter.py`.
  **Decision:** Automated scanning across raw, Base64, Hexadecimal, and URL-encoded variants against both memory dumps and decrypted network flows; rejected: single-encoding substring searches.
  **Rationale:** Modern infostealers transform harvested credentials (Base64 encoding, hex packing) before dispatching them over HTTP POST or Telegram bot APIs. Multi-encoding permutations eliminate false negatives.
  **Evidence:** [M] Pre-encryption buffer matches; [N] decrypted network payload matches in `CANARY_EXFIL_HITS.json`.
  **Revisit if:** Malware compresses data (gzip, zlib, brotli) prior to custom encryption (add decompression pre-processor).

- **Step:** Implemented automated threat intelligence extractor in `parser_correlator/ioc_extractor.py` and master workflow in `orchestrator.py`.
  **Decision:** Normalized indicators into machine-readable `iocs.json`, STIX 2.1 JSON bundle (`threat_report_stix21.json`), and evidence-tagged executive Markdown report (`analysis_report.md`).
  **Rationale:** Converts raw sandbox telemetry into standardized, publication-grade threat intelligence deliverables for defensive analysts and automated SIEM ingestion.
  **Evidence:** [C] `dbug-threat-intel` specification; [C] STIX 2.1 schema compliance.
  **Revisit if:** STIX 2.1 schema is superseded or custom TAXII feed format is required.

- **Step:** Implemented Gate G0 static triage engine in `sample_triage/triage_apk.py`.
  **Decision:** Automated safe pre-detonation static assessment parsing APK hashes, permissions, accessibility services, packers, anti-analysis strings, and hardcoded C2s without executing untrusted code on the host; rejected: launching dynamic analysis blindly without static profiling.
  **Rationale:** Static triage identifies evasive heuristics, packers, and architecture before physical device spawn, ensuring cloaking countermeasures are armed appropriately.
  **Evidence:** [C] `dbug-sample-triage` specification; [C] `sample_triage/triage_apk.py`.
  **Revisit if:** Target sample is heavily protected by commercial VMP (virtual machine protector) requiring dynamic Dalvik bytecode dumping.

- **Step:** Implemented defensive YARA signature generator in `parser_correlator/yara_generator.py`.
  **Decision:** Automatically synthesized YARA detection rules from observed C2 domains, Telegram tokens, and package identifiers; rejected: manual manual YARA authoring.
  **Rationale:** Enables immediate defensive perimeter deployment and retro-hunting across organizational telemetry.
  **Evidence:** [C] AGENTS.md ground rule 4; [C] `parser_correlator/yara_generator.py`.
  **Revisit if:** Generated YARA rule produces false positives on standard library dependencies (adjust condition to require 2+ unique C2 strings).

- **Step:** Enhanced in-process cloaking in `instrumentation/agent/bypass_antidebug.js` with ptrace and anti-root file access interceptors.
  **Decision:** Hooked native `ptrace(PTRACE_TRACEME)` returning 0, hooked `access()` spoofing -1 for `/su` checks, and hooked `kill()` to trace self-termination attempts.
  **Rationale:** Evasive infostealers attempt self-ptrace to detect attached debuggers and self-terminate upon finding `/system/bin/su`.
  **Evidence:** [C] `dbug-anti-analysis` section 1; [M] in-process libc interceptors.
  **Revisit if:** Malware invokes direct raw syscalls (`svc 0`) bypassing `libc.so` stubs.

- **Step:** Implemented automated C2 protocol framing & specification reconstructor in `parser_correlator/c2_protocol_decoder.py`.
  **Decision:** Analyzed decrypted HTTP/TLS flows, WebSocket headers, and socket streams to reconstruct wire layout, magic bytes, length prefix, serialization format, and tasking opcodes into `C2_PROTOCOL.md`; rejected: manual packet inspection.
  **Rationale:** Accelerates reverse engineering and enables reproducible C2 emulation and signature generation.
  **Evidence:** [N] Network captures; [M] native socket arguments.
  **Revisit if:** Target sample communicates over custom raw UDP protocol.

- **Step:** Implemented behavioral malware family attribution engine in `parser_correlator/family_classifier.py`.
  **Decision:** Evaluated observed permissions, anti-analysis checks, C2 transports, and crypto algorithms against the `dbug-infostealer-catalog` (Ermac, Hook, CraxsRAT, SpyNote, Godfather, Octo), outputting confidence-scored `FAMILY_ATTRIBUTION.json`.
  **Rationale:** Connects low-level execution artifacts to strategic adversary profiling and MITRE ATT&CK mappings.
  **Evidence:** [C] Permissions and DEX cues; [M] crypto algorithm; [N] transport signatures.
  **Revisit if:** Novel or hybrid malware families emerge that do not match existing catalog profiles.

- **Step:** Implemented defensive AArch64 native string decryptor and JNI emulation harness in `sample_triage/native_emulator.py`.
  **Decision:** Built native emulator supporting Unicorn engine with a pure-Python fallback for headless CI and dry-run environments to decrypt obfuscated strings in `.so` files; rejected: forcing physical device execution for every native string routine.
  **Rationale:** Advanced infostealers store C2 URLs and tokens inside packed native `.so` libraries that cannot be decompiled by standard Dalvik decompiler tools (`jadx`/`apktool`).
  **Evidence:** [C] Native `.so` ELF segments; [C] decompiled JNI strings.
  **Revisit if:** Target library depends on extensive proprietary native Android OS frameworks outside libc.

- **Step:** Synchronized canonical sample workspace `targets/<sample_hash>/` in `orchestrator.py`.
  **Decision:** Automated synchronization of `TARGET.md`, `SOURCES.md`, `FACTS.md`, `STATIC_AUDIT.md`, `ANALYSIS.md`, `REPORT.md`, `LOG.md`, and `IOCS.json` at pipeline completion; rejected: leaving analysis deliverables scattered in ephemeral session directories.
  **Rationale:** Strict compliance with `AGENTS.md` directory structure ensures reproducible and auditable analysis packages.
  **Evidence:** [C] Workspace layout in `AGENTS.md`.
  **Revisit if:** Target document schema is updated.

- **Step:** Implemented comprehensive automated end-to-end test suite in `tests/test_framework_e2e.py`.
  **Decision:** Implemented 12 automated unit and integration tests verifying all 6 gates (G0-G5) across seeding, cloaking, capture, instrumentation, decryption, correlation, and attribution; rejected: manual interactive testing only.
  **Rationale:** Guarantees regression protection and testability across development workstations and continuous integration pipelines.
  **Evidence:** [C] Test suite test runner output in `tests/test_framework_e2e.py`.
  **Revisit if:** New pipeline stages or CLI options are introduced.

- **Step:** Implemented curated mobile tracking and analytics taxonomy in `config/tracker_catalog.json`.
  **Decision:** Standardized on signatures for top 10 advertising, attribution, and analytics networks (Meta Graph, Firebase, AppsFlyer, Adjust, Kochava, TikTok Pangle, Branch, Mixpanel, Sentry, Unity Ads); rejected: unstructured domain lists without risk ratings.
  **Rationale:** Distinguishing First-Party API backends from Third-Party ad trackers enables automated compliance audits under GDPR and CCPA.
  **Evidence:** [C] `config/tracker_catalog.json`.
  **Revisit if:** New advertising networks or regional tracking SDKs (e.g., in Asia/EU markets) are observed.

- **Step:** Implemented mobile app privacy & data leakage auditor in `parser_correlator/privacy_auditor.py`.
  **Decision:** Automated correlation of decrypted flows and canary hits against the tracker taxonomy, outputting `PRIVACY_AUDIT.md` and `privacy_findings.json`; rejected: manual log inspection for privacy auditing.
  **Rationale:** Enables immediate regulatory compliance reporting (GDPR Article 5 Data Minimization, CCPA Notice Requirements, and App Store Privacy Manifest audits) for commercial apps.
  **Evidence:** [N] Decrypted network flows; [M] canary correlation hits.
  **Revisit if:** Target application uses encrypted proprietary protobuf tracking envelopes.

- **Step:** Implemented OWASP MASVS AppSec auditor and OpenAPI 3.0 synthesizer in `parser_correlator/appsec_auditor.py`.
  **Decision:** Automated cryptographic hygiene checks (MASVS-CRYPTO-1 ECB mode, static IVs, deprecated ciphers) and synthesized valid OpenAPI 3.0 JSON specification (`openapi_spec.json`) alongside `API_SECURITY_REPORT.md`; rejected: manual Swagger authoring.
  **Rationale:** Directly bridges out-of-band mobile packet captures with penetration testing tools (Postman, Burp Suite, OWASP ZAP) without breaking certificate pinning.
  **Evidence:** [M] `Cipher.init` parameters; [N] decrypted REST/GraphQL flows.
  **Revisit if:** Application adopts gRPC over HTTP/2 framing.

- **Step:** Integrated multi-profile engine and interactive testing mode into `orchestrator.py`.
  **Decision:** Added `--profile {malware,privacy,appsec,all}` and `--interactive` mode allowing human testers to navigate protected apps while capture runs; rejected: forcing malware-only reporting on commercial apps.
  **Rationale:** Elevates `dbug` into a universal mobile security platform for both adversarial threat intelligence and defensive commercial application auditing.
  **Evidence:** [C] `orchestrator.py` CLI interface; [C] `tests/test_framework_e2e.py` (16 tests pass).
  **Revisit if:** Additional profiles (e.g. IoT companion auditing, Bluetooth BLE tracking) are required.

- **Step:** Formulated Non-Malware First-Class Architecture Plan in `task-non-malware.md`.
  **Decision:** Formalized a triple-track operational architecture (`malware`, `privacy`, `appsec`, `all`) that leverages the exact same zero-trace out-of-band capture and cloaking foundation to evade both malware evasion checks and commercial RASP engines; rejected: treating non-malware as a peripheral plugin.
  **Rationale:** Commercial banking, fintech, and enterprise apps use the exact same anti-tamper and anti-debugging checks as infostealers; an out-of-band architecture solves interception for both domains identically.
  **Evidence:** [C] `task-non-malware.md` architecture specification.
  **Revisit if:** New regulatory compliance frameworks (e.g. EU NIS2, DORA) require custom reporting sections.

- **Step:** Promoted Non-Malware Doctrine into `AGENTS.md`, `REPO_ROADMAP.md`, `README.md`, and `docs/SOP.md`.
  **Decision:** Updated system mandate, minimal prompts, RASP equivalence matrix, workspace layout, and gates ledger to elevate commercial application security and privacy auditing to co-equal first-class citizens alongside malware analysis; authored comprehensive `README.md` and `docs/SOP.md` runbook; rejected: keeping repository documentation malware-exclusive.
  **Rationale:** Ensures any autonomous agent or human analyst operating `dbug` understands the complete operational boundaries across malware threat intelligence, privacy auditing, and interactive penetration testing.
  **Evidence:** [C] `AGENTS.md`, `REPO_ROADMAP.md`, `README.md`, `docs/SOP.md`.
  **Revisit if:** Core operational contracts or prompt schemas are updated.

- **Step:** Implemented profile-tailored executive reporting in `orchestrator.py`.
  **Decision:** Dynamically tailored `REPORT.md` and `TARGET.md` classifications, executive summaries, and artifact lists based on active profile (`privacy`, `appsec`, `all`, `malware`); added YAML config fallback in `config/lab_config.yaml`; rejected: hardcoding malware threat intel headers for privacy and appsec audits.
  **Rationale:** Delivers clear, professional executive reports appropriate for regulatory auditors and AppSec stakeholders without irrelevant malware C2 terminology.
  **Evidence:** [C] `orchestrator.py`; [D] verified via `--dry-run` across all profiles.
  **Revisit if:** Additional executive templates are requested.

- **Step:** Created specialized Claude skills for Non-Malware workflows.
  **Decision:** Added `.claude/skills/dbug-privacy-audit/SKILL.md` (tracker taxonomy, canary PII leakage, GDPR/CCPA compliance) and `.claude/skills/dbug-appsec-masvs/SKILL.md` (OWASP MASVS crypto hygiene, OpenAPI 3.0 generation, interactive pen-testing); rejected: monolithic skill file.
  **Rationale:** Follows the established modular skill architecture for agentic onboarding and task delegation.
  **Evidence:** [C] `.claude/skills/dbug-privacy-audit/SKILL.md`, `.claude/skills/dbug-appsec-masvs/SKILL.md`.
  **Revisit if:** New mobile security standards (e.g. MASVS v2 updates) are published.



