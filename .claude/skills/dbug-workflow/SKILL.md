---
name: dbug-workflow
description: Orchestrates an end-to-end stealth Android malware analysis session on physical hardware - from sample intake and static triage to device cloaking, canary seeding, out-of-band network/eBPF capture, runtime instrumentation, canary correlation, and STIX 2.1 threat intelligence reporting across Gates G0 to G5. Use whenever planning or executing dynamic analysis runs, automating malware sessions, or coordinating sub-tasks across dbug skills.
---

# dbug-workflow

Master orchestrator for stealth dynamic analysis of evasive Android infostealers and RATs.

**Core Defensive Mandate:** Observe real malware execution, extract Command & Control (C2) infrastructure, and catch exfiltrated canary data **without alerting the malware that it is running in an instrumented environment**.

---

## 1. Evidence Tag Legend (Canonical)
Tag all statements, claims, and findings across target documentation:
- `[C]` **Code / Static:** Confirmed in decompiled Java/Smali, manifest, or native binary symbols.
- `[D]` **Dynamic Action:** Observed behavior on the physical device (app spawn, UI overlay, file write).
- `[M]` **Memory / Hook:** Intercepted in-memory via Frida hooks (`Cipher.doFinal`, JNI, socket args).
- `[N]` **Network Capture:** Observed in Wi-Fi gateway `tcpdump` PCAP (DNS query, TCP SYN, TLS handshake).
- `[E]` **eBPF Kernel:** Plaintext TLS or master secret captured via Conscrypt `libssl.so` uprobe.
- `[W]` **External / Third-party:** Threat intelligence feeds, VirusTotal, vendor blogs (unverified locally).
- `[I]` **Inferred:** Deduced from correlated evidence.
- `[U]` **Unknown:** Hypothesis requiring testing on device.

---

## 2. Gate Architecture & Skill Map

| Gate | Phase & Objective | Primary Skill | Key Inputs & Tools | Deliverables / Artifacts |
|---|---|---|---|---|
| **G0** | **Sample Intake & Static Triage** | `dbug-sample-triage` | Sample APK/XAPK, `apktool`, `jadx`, SHA-256 | Static assessment, manifest analysis, permissions, anti-debug cues |
| **G1** | **Device Cloaking & Pre-Flight** | `dbug-device-cloaking` | Rooted physical phone, `resetprop`, LSPosed | `verify_stealth_state.py` pass; masked ADB, no tun0/proxy |
| **G2** | **Canary Data Seeding** | `dbug-canary-seeding` | `config/mock_canaries.json`, `seed_canaries.py` | Seeded contacts, SMS inbox, clipboard tokens on device |
| **G3** | **Zero-Footprint Capture Setup** | `dbug-network-gateway` & `dbug-ebpf-capture` | Linux AP (`ap0`), `tcpdump`, `ecapture` eBPF | Out-of-band `raw_traffic.pcap`, `tls_decrypted.pcapng`, `sslkey.log` |
| **G4** | **Dynamic Stealth Execution** | `dbug-frida-instrumentation` | Custom port Frida (`38921`), `hl_daemon`, hooks | `instrumentation_events.jsonl` (crypto dumps, sockets, DNS) |
| **G5** | **Correlate, Decrypt & Report** | `dbug-canary-correlation` & `dbug-threat-intel` | `tshark`, `pyshark`, `canary_hunter.py` | Decrypted streams, canary exfil hits, STIX 2.1 JSON, Markdown report |

---

## 3. Operational Execution Sequence

### Step 0: Session Initialization
1. Establish session directory: `targets/<sample_hash>/` or `sessions/<timestamp>_<package>/`.
2. Record initial sample metadata in `TARGET.md` using `dbug-sample-triage`.
3. Log decisions and deviations in `docs/steps.md` using `dbug-step-rationale`.

### Step 1: Pre-Flight Device Audit (Gate G1)
- Run `python3 device_cloaking/verify_stealth_state.py`.
- Ensure:
  - System properties: `ro.debuggable=0`, `ro.secure=1`, `sys.usb.state=mtp`.
  - Android settings: `Settings.Global.getInt("adb_enabled") == 0` via LSPosed HideDevMode.
  - Network hygiene: No `tun0`/`ppp0` interfaces, no `http.proxyHost` property.
  - Frida stealth: Port `27042` closed; custom agent running on randomized port (`38921`).
- **Stop condition:** If any cloaking check fails, do NOT launch the malware. Fix properties or LSPosed module first.

### Step 2: Plant Canaries (Gate G2)
- Execute `python3 config/seed_canaries.py --config config/lab_config.yaml`.
- Verify synthetic SMS, contacts, and clipboard entries exist on the physical phone.

### Step 3: Arm Out-of-Band Network & eBPF Captures (Gate G3)
1. On Linux Gateway Host: `sudo bash network_capture/gateway_setup.sh start`
   - Spawns isolated AP (`ap0`), enables routing, starts raw `tcpdump`.
2. On Android Device: Launch eBPF capture via `python3 network_capture/ecapture_runner.py start`
   - Attaches kernel uprobe on `/apex/com.android.conscrypt/lib64/libssl.so`.

### Step 4: Launch Sample with Dynamic Hooks (Gate G4)
- Execute `python3 instrumentation/frida_loader.py --apk <sample.apk> --port 38921 --duration 120`
- Frida injects `bypass_antidebug.js`, `crypto_dumper.js`, and `socket_tracer.js`.
- Stream real-time events to `instrumentation_events.jsonl`.

### Step 5: Graceful Teardown & Collection
1. Force-stop and uninstall target malware package.
2. Send SIGTERM to eCapture; sync and pull `sslkey.log` and `tls_decrypted.pcapng`.
3. Stop gateway `tcpdump` and pull `raw_traffic.pcap`.
4. Run `python3 config/seed_canaries.py --clean` to remove remaining mock canaries.
5. Restore standard device state if analysis cycle is complete.

### Step 6: Post-Processing & Intelligence Generation (Gate G5)
1. Decrypt TLS flows with `pcap_decryptor.py` using captured master secrets.
2. Scan decrypted payloads and crypto dumps for canary hits using `canary_hunter.py`.
3. Extract IOCs, C2 infrastructure, and Telegram/Discord channels with `ioc_extractor.py`.
4. Generate final STIX 2.1 bundle and `analysis_report.md`.

---

## 4. Anti-Patterns & Disallowed Actions
- **NEVER** launch malware with standard USB debugging unmasked.
- **NEVER** configure an HTTP proxy in Android Wi-Fi settings (`http.proxyHost`).
- **NEVER** use on-device VPN capture apps (e.g., PCAPdroid, Charles) creating `tun0`.
- **NEVER** install untrusted user CAs as the primary interception strategy.
- **NEVER** run default Frida server names or default port `27042`.
