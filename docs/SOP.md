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
