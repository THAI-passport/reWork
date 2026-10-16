---
name: dbug-privacy-audit
description: Commercial mobile application privacy auditing and ad-tracker PII exfiltration analysis (Gate G5). Correlates decrypted HTTP/2 network flows and synthetic canary data against the curated tracking taxonomy (config/tracker_catalog.json). Flags undisclosed personal data leakage to ad attribution and analytics networks (Meta, AppsFlyer, Adjust, ByteDance) and generates GDPR/CCPA compliance reports.
---

# dbug-privacy-audit (Gate G5: Privacy Profile)

Audits commercial mobile applications for undisclosed personal data harvesting, third-party tracking SDK transmissions, and regulatory compliance breaches (GDPR Article 5/6, California CCPA, Apple/Google Privacy Manifest declarations).

---

## 1. Operational Rationale

Commercial applications bundle dozens of third-party SDKs for attribution, advertising, behavioral analytics, and crash reporting. These SDKs frequently harvest user data (clipboard, contacts, SMS OTPs, unique hardware identifiers) without explicit consent or contrary to declared privacy disclosures.

Because `dbug` intercepts network traffic out-of-band via eBPF TLS uprobes without installing user CA certificates or proxy settings, commercial apps and their bundled SDKs transmit their authentic production traffic without triggering proxy-detection routines.

---

## 2. Tracking Network Taxonomy (`config/tracker_catalog.json`)

The tracker database catalogs mobile analytics, attribution, advertising, and crash reporting services:
- **Attribution & Ad Networks:** AppsFlyer (`appsflyer.com`), Adjust (`adjust.com`), Branch.io (`branch.io`), Kochava (`kochava.com`), Meta/Facebook Graph (`graph.facebook.com`), Google Ads/AdMob (`googleads.g.doubleclick.net`), TikTok/Pangle (`pangolin-sdk-toutiao.com`), Unity Ads (`unity3d.com`).
- **Analytics & Telemetry:** Google Firebase Analytics (`app-measurement.com`), Mixpanel (`api.mixpanel.com`), Amplitude (`api2.amplitude.com`), Flurry (`data.flurry.com`), Segment (`api.segment.io`), CleverTap (`clevertap.com`).
- **Crash & Performance:** Sentry (`sentry.io`), Firebase Crashlytics (`crashlytics.com`), Bugsnag (`notify.bugsnag.com`), New Relic (`mobile-collector.newrelic.com`).

---

## 3. Privacy Auditing Workflow (`parser_correlator/privacy_auditor.py`)

Run the auditor against a session containing decrypted flows and canary hits:

```bash
python3 parser_correlator/privacy_auditor.py \
    --session-dir sessions/session_<id> \
    --package com.example.commercial \
    --catalog config/tracker_catalog.json
```

### Analysis Steps:
1. **Endpoint Classification:** Each decrypted HTTP request from `decrypted_http_requests.jsonl` is checked against domain suffixes in `config/tracker_catalog.json`:
   - Matches are tagged with the tracker name, category (`Advertising & Attribution`, `Analytics & Telemetry`, `Crash & Performance`), and sensitivity score.
   - Non-matching domains with matching package root names are classified as `First-Party API`.
   - Other domains are classified as `Unknown Third-Party`.
2. **Canary Leakage Cross-Referencing:** Ingests `CANARY_EXFIL_HITS.json` to identify which synthetic tokens (`CANARY_CONTACT_...`, `CANARY_SMS_OTP_...`, `CANARY_CLIPBOARD_...`, `CANARY_WALLET_...`) were transmitted to third-party endpoints.
3. **Risk Scoring:** Assigns GDPR and CCPA risk ratings:
   - **CRITICAL:** High-entropy canary secrets (SMS OTPs, crypto seed phrases) sent to third-party trackers.
   - **HIGH:** Personal data (contacts, clipboard contents) leaked to ad networks without consent.
   - **MEDIUM:** Device fingerprinting / hardware identifiers transmitted to multiple analytics networks.
   - **LOW:** Standard aggregated first-party telemetry or crash reporting with no canary hits.

---

## 4. Key Deliverables
- `PRIVACY_AUDIT.md`: Human-readable regulatory audit report citing GDPR Article 5(1)(c) data minimization, CCPA Section 1798.100 disclosure, and App Store manifest discrepancies.
- `privacy_findings.json`: Structured machine-readable findings detailing contacted trackers, transmitted data types, request URLs, and severity ratings.
- Synchronized into `targets/<target_id>/PRIVACY_AUDIT.md` and `privacy_findings.json`.
