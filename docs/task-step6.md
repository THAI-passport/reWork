# Phase 6 Plan & Task Breakdown: First-Class Commercial AppSec & Privacy Auditing (`task-step6.md`)

## 1. Phase Objective & Architectural Mandate

The objective of **Phase 6** is to elevate `dbug` from a malware-only dynamic analysis sandbox into a **universal stealth mobile security toolkit** supporting three first-class operational profiles:
1. **`malware` (Threat Intelligence & Defense):** C2 extraction, bot token harvesting, STIX 2.1 threat bundle, YARA generation, malware family attribution.
2. **`privacy` (Data Leakage & Regulatory Compliance):** Automated auditing of PII, contacts, SMS, and clipboard leakage to third-party ad/tracking SDKs (Meta, Google, AppsFlyer, Adjust, ByteDance) for GDPR, CCPA, and App Store review compliance.
3. **`appsec` (Mobile Application Penetration Testing & API Audit):** Zero-trace API endpoint discovery, OpenAPI 3.0 export, OWASP MASVS cryptographic audit (ECB modes, static IVs, weak ciphers), and interactive login testing against heavily protected commercial apps (fintech, banking, e-commerce) without tripping commercial RASP / anti-tamper protections.

---

## 2. Tasks for Phase 6

| Task ID | Component | Description | Deliverables |
| :--- | :--- | :--- | :--- |
| **T6.1** | `config/tracker_catalog.json` | Knowledge base of third-party mobile advertising, analytics, telemetry, and tracking SDK domains. | `config/tracker_catalog.json` |
| **T6.2** | `parser_correlator/privacy_auditor.py` | Privacy auditor correlating canary leakage and decrypted network flows against third-party tracker domains. | `parser_correlator/privacy_auditor.py`<br>`PRIVACY_AUDIT.md`<br>`privacy_findings.json` |
| **T6.3** | `parser_correlator/appsec_auditor.py` | AppSec auditor analyzing cryptographic hygiene (OWASP MASVS) and generating OpenAPI 3.0 API specifications. | `parser_correlator/appsec_auditor.py`<br>`API_SECURITY_REPORT.md`<br>`openapi_spec.json` |
| **T6.4** | `orchestrator.py` Profile & Interactive Engine | Introduces `--profile {malware,privacy,appsec,all}` and `--interactive` mode for manual tester interaction. | `orchestrator.py` |
| **T6.5** | Automated Test Suite Extension | Unit & integration tests in `tests/test_framework_e2e.py` verifying privacy, appsec, and multi-profile workflows. | `tests/test_framework_e2e.py` |
| **T6.6** | Framework Ledgers & Documentation | Update `docs/steps.md`, `completed.md`, `problem_solution.md`, `FIXES.md`, and `LOG.md`. | Ledgers |

---

## 3. Technical Specifications

### Task 6.1: `config/tracker_catalog.json`
- **Scope:** Curated taxonomy of top mobile tracking, advertising, and analytics networks:
  - **Advertising & Attribution:** AppsFlyer, Adjust, Branch.io, Kochava, Meta/Facebook Graph, Google Ads/AdMob, Unity Ads, ByteDance/Pangle.
  - **Analytics & Telemetry:** Google Firebase/App-Measurement, Mixpanel, Amplitude, Flurry, Segment, CleverTap.
  - **Crash & Performance:** Sentry, Firebase Crashlytics, Bugsnag, New Relic.
- **Fields per entry:** Domain suffixes, company/network name, tracker category, privacy sensitivity score.

### Task 6.2: `parser_correlator/privacy_auditor.py`
- **Correlation Logic:**
  1. Inspects all decrypted HTTP/TLS requests from `decrypted_http_requests.jsonl`.
  2. Resolves destination domains against `config/tracker_catalog.json` to classify destinations into First-Party API vs Third-Party Tracker vs Crash Reporter.
  3. Correlates `CANARY_EXFIL_HITS.json` to determine what sensitive data (contacts, SMS OTPs, clipboard, wallet keys) was transmitted to third-party tracking entities.
- **Outputs:**
  - `privacy_findings.json`: Machine-readable audit detailing tracked SDKs, transmitted data types, and risk levels.
  - `PRIVACY_AUDIT.md`: Executive compliance report citing GDPR Article 5/6 principles, California CCPA data disclosure violations, and App Store privacy manifest discrepancies.

### Task 6.3: `parser_correlator/appsec_auditor.py`
- **OWASP MASVS Cryptographic Audit (MASVS-CRYPTO):**
  - Analyzes `instrumentation_events.jsonl` from `crypto_dumper.js`.
  - Flags insecure cipher modes: AES/ECB (no IV), static hardcoded IVs (e.g. all zeros or sequential bytes), DES/3DES, MD5/SHA1 hashing.
  - Reports secret key reuse and plain HTTP fallbacks.
- **API Inventory & OpenAPI 3.0 Export (MASVS-NETWORK):**
  - Aggregates unique HTTP endpoints, methods (`GET`, `POST`, `PUT`, `DELETE`), headers, query parameters, and request body JSON schemas.
  - Emits a valid OpenAPI 3.0 JSON specification (`openapi_spec.json`) suitable for import into Postman, Burp Suite, or OWASP ZAP.
  - Emits `API_SECURITY_REPORT.md`.

### Task 6.4: `orchestrator.py` Profile & Interactive Engine
- **CLI Options:**
  - `--profile {malware,privacy,appsec,all}`: Defaults to `malware`.
  - `--interactive`: Instead of terminating after a fixed `--duration`, maintains zero-trace capture alive indefinitely while presenting interactive instructions to the analyst. Stops cleanly on `Ctrl+C` or Enter key and runs post-processing.
- **Target Reconciliation:** Synchronizes profile deliverables to `targets/<target_id>/`:
  - If `--profile privacy` or `all`: generates `PRIVACY_AUDIT.md` and `privacy_findings.json`.
  - If `--profile appsec` or `all`: generates `API_SECURITY_REPORT.md` and `openapi_spec.json`.
  - If `--profile malware` or `all`: generates `C2_PROTOCOL.md`, `threat_report_stix21.json`, YARA rule, and `FAMILY_ATTRIBUTION.json`.

---

## 4. Verification & Validation Criteria
1. `config/tracker_catalog.json` validates against JSON schema.
2. `privacy_auditor.py` correctly classifies first-party vs third-party endpoints and flags PII leakage.
3. `appsec_auditor.py` detects weak crypto algorithms and outputs valid OpenAPI 3.0 JSON.
4. `orchestrator.py --profile all --dry-run` executes all stages without failure.
5. All 14+ automated tests in `tests/test_framework_e2e.py` pass with exit code 0.
