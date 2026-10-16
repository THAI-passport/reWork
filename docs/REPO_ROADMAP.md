# `dbug`: Step-by-Step Repository Implementation Plan


# SYSTEM MANDATE & DEFENSIVE RESEARCH CONTEXT

You are a Senior Android Security Engineer and Defensive Malware Research Assistant helping build an isolated, automated Android Dynamic Malware Analysis Sandbox and Threat Intelligence Toolkit.


## Repository Purpose
A modular dynamic analysis and network-interception framework for observing evasive Android infostealers in an isolated lab environment. The toolkit masks USB debugging/developer telemetry on the physical test device, captures decrypted TLS and raw socket traffic without VPN/Proxy artifacts, and extracts pre-encryption mock data payloads.

---

## Target Directory Structure

```text
dbug/
├── README.md
├── malware_debugger.md                 # Threat model & anti-evasion rules
├── REPO_ROADMAP.md                  # Step-by-step build instructions
├── config/
│   ├── lab_config.yaml              # Device serial, interface names, target package, canary strings
│   └── mock_canaries.json           # Synthetic credentials/PII planted on the device
├── device_cloaking/
│   ├── apply_stealth_props.sh       # Magisk/KernelSU resetprop script to mask ADB & debug flags
│   └── verify_stealth_state.py      # Audits device properties & SettingsProvider before malware launch
├── network_capture/
│   ├── gateway_setup.sh             # Linux Wi-Fi AP hotspot + iptables transparent redirection
│   ├── ecapture_runner.py           # Automates eBPF libssl.so uprobe TLS key/pcapng capture on wlan0
│   └── sinkhole_inetsim.conf        # Optional local sinkhole config for safe C2 emulation
├── instrumentation/
│   ├── agent/
│   │   ├── bypass_antidebug.js      # Frida hooks for Settings.Global, Debug, and __system_property_get
│   │   ├── crypto_dumper.js         # Hooks javax.crypto.Cipher & native crypto before network send
│   │   └── socket_tracer.js         # Hooks DNS (InetAddress/getaddrinfo) and libc connect()/send()
│   └── frida_loader.py              # Spawns/attaches using custom port & parses JSON IPC logs
├── parser_correlator/
│   ├── pcap_decryptor.py            # Merges eCapture TLS master keys with raw tcpdump PCAPs
│   ├── canary_hunter.py             # Searches decrypted flows & crypto dumps for mock data leakage
│   └── ioc_extractor.py             # Generates structured JSON/STIX report of C2 IPs, domains, and URLs
└── orchestrator.py                  # Master CLI to run a full automated stealth analysis session
```

---

## Step-by-Step Implementation Phases

### Phase 1: Configuration & Canary Data Seeding (`config/`)
**Goal:** Define environment variables and plant trackable fake data on the test phone so we can immediately spot exfiltration in memory or network logs.
- **Step 1.1:** Create `config/lab_config.yaml` storing the ADB device ID, target APK path, package name, wireless interface (`wlan0`), and Linux gateway interface (`ap0`).
- **Step 1.2:** Create `config/mock_canaries.json` containing unique, high-entropy synthetic strings (e.g., fake SMS OTPs, dummy crypto seed phrases, fake session cookies, and test contact entries).
- **Step 1.3:** Write a helper script (`config/seed_canaries.py`) to push the synthetic contacts, SMS messages, and clipboard strings onto the Android device prior to installing the malware sample.

---

### Phase 2: On-Device Stealth Cloaking (`device_cloaking/`)
**Goal:** Keep USB debugging (`adbd`) active for automation while making the OS report a completely stock, un-debugged production state to user-space apps.
- **Step 2.1:** Build `device_cloaking/apply_stealth_props.sh` to run via root (`su -c`) and execute `resetprop` on `ro.debuggable` (0), `ro.secure` (1), `sys.usb.state` (mtp), and `sys.usb.config` (mtp).
- **Step 2.2:** Add commands/scripts to verify that LSPosed HideDevMode (or equivalent `system_server` Binder hook) is active so `Settings.Global.getInt("adb_enabled")` and `"development_settings_enabled"` return 0 without injecting into the malware process.
- **Step 2.3:** Build `device_cloaking/verify_stealth_state.py` to run pre-flight checks from the host machine, asserting that no default frida-server port (27042), proxy properties (`http.proxyHost`), or `tun0` interfaces are exposed.

---

### Phase 3: Zero-Footprint Network & TLS Interception (`network_capture/`)
**Goal:** Capture 100% of DNS queries, raw TCP/UDP sockets, and plaintext HTTPS traffic without setting an Android proxy or installing a user CA certificate.
- **Step 3.1:** Write `network_capture/gateway_setup.sh` for the Linux host to initialize an isolated Wi-Fi access point (`ap0`), enable IPv4 forwarding, and start background tcpdump capture for all raw L3/L4 traffic and DNS lookups.
- **Step 3.2:** Write `network_capture/ecapture_runner.py` to manage the static ARM64 `ecapture` binary in `/data/local/tmp/`, launching `ecapture tls -m pcap -i wlan0` in the background to hook `/apex/com.android.conscrypt/lib64/libssl.so` via kernel eBPF uprobes.
- **Step 3.3:** Add clean teardown handlers (SIGINT/SIGTERM) to flush `.pcapng` and `sslkey.log` buffers and pull them to the host workstation after the run completes.

---

### Phase 4: Dynamic Runtime & Pre-Network Crypto Instrumentation (`instrumentation/`)
**Goal:** Catch application-layer encryption (AES/RC4/XOR) applied to stolen mock data before it enters the TLS tunnel, and log hardcoded native socket connections.
- **Step 4.1:** Implement `instrumentation/agent/bypass_antidebug.js` as a fallback in-process cloak for `Settings.Global`, `android.os.Debug`, and native `libc.so` `__system_property_get`.
- **Step 4.2:** Implement `instrumentation/agent/crypto_dumper.js` to hook `javax.crypto.Cipher.init()` and `doFinal()`, emitting structured JSON events via Frida `send()` containing the algorithm, key/IV hex, and plaintext/ciphertext buffers.
- **Step 4.3:** Implement `instrumentation/agent/socket_tracer.js` to hook `InetAddress.getByName()`, `java.net.URL`, and native `libc.so` `connect()` / `send()` to catch custom non-HTTP C2 protocols.
- **Step 4.4:** Build `instrumentation/frida_loader.py` in Python to compile/load the scripts, attach to the target APK via a randomized non-default port, and stream all JSON telemetry to a timestamped session log.

---

### Phase 5: Traffic Decryption, Canary Correlation & Threat Intelligence (`parser_correlator/` & `orchestrator.py`)
**Goal:** Automatically correlate what the malware stole in memory with the exact remote server it contacted, extract C2 protocols, classify malware family, and generate STIX 2.1 bundles.
- **Step 5.1:** Write `parser_correlator/pcap_decryptor.py` using `tshark` / `pyshark` to combine the raw gateway PCAP and eCapture TLS keylog into a unified decrypted HTTP/TCP stream log.
- **Step 5.2:** Write `parser_correlator/canary_hunter.py` to scan both the Frida `Cipher.doFinal` dumps and the decrypted PCAP streams for any string matching `config/mock_canaries.json`, flagging the exact timestamp and destination IP/URL where exfiltration occurred.
- **Step 5.3:** Write `parser_correlator/c2_protocol_decoder.py` to reconstruct custom C2 transports and frame parsing.
- **Step 5.4:** Write `parser_correlator/family_classifier.py` for behavioral heuristic malware attribution (SharkBot, Ermac, Vultur, SpyNote, Cerberus, Teabot).
- **Step 5.5:** Write `parser_correlator/yara_generator.py` for automated defensive YARA rule synthesis.
- **Step 5.6:** Write `parser_correlator/ioc_extractor.py` and `orchestrator.py` to tie all phases into a single CLI workflow generating STIX 2.1 bundles and markdown reports.

---

### Phase 6: Commercial AppSec, Privacy Auditing & Interactive Pen-Testing (First-Class Non-Malware)
**Goal:** Leverage zero-trace out-of-band capture and device cloaking to bypass commercial RASP (DexGuard, Promon, AppSealing) and evaluate commercial apps for privacy leakage and OWASP MASVS compliance.
- **Step 6.1:** Build `config/tracker_catalog.json` establishing a structured taxonomy of top mobile ad attribution, analytics, and tracking SDKs.
- **Step 6.2:** Build `parser_correlator/privacy_auditor.py` to correlate decrypted HTTP flows against the tracker taxonomy and canary tokens, generating `PRIVACY_AUDIT.md` and `privacy_findings.json` for GDPR/CCPA compliance.
- **Step 6.3:** Build `parser_correlator/appsec_auditor.py` to perform OWASP MASVS cryptographic hygiene audits (detecting AES/ECB, static IVs, deprecated ciphers) and synthesize a valid OpenAPI 3.0 specification (`openapi_spec.json`) for automated API fuzzing.
- **Step 6.4:** Implement multi-profile execution (`--profile {malware,privacy,appsec,all}`) and human-in-the-loop interactive mode (`--interactive`) in `orchestrator.py`.
- **Step 6.5:** Expand automated test suite in `tests/test_framework_e2e.py` to 16 comprehensive suites covering all profiles and verification criteria.