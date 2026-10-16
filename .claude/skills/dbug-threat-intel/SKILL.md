---
name: dbug-threat-intel
description: Automated threat intelligence extraction and reporting (Gate G5). Aggregates observed C2 endpoints, resolved DNS queries, Telegram bot tokens, and canary hits into structured IOC formats (JSON, STIX 2.1) and executive Markdown threat reports. Use when finalizing analysis sessions, exporting indicators of compromise, or generating intelligence deliverables.
---

# dbug-threat-intel (Gate G5)

Transform raw telemetry from sandbox runs into actionable Indicators of Compromise (IOCs) and standardized STIX 2.1 threat intelligence bundles.

---

## 1. IOC Extractor Architecture (`parser_correlator/ioc_extractor.py`)

Extracts network observables, credentials, and exfiltration destinations from:
1. `raw_traffic.pcap` / `decrypted_http_requests.txt`
2. `dnsmasq.log` (DNS queries)
3. `instrumentation_events.jsonl` (Frida crypto & socket events)
4. `CANARY_EXFIL_HITS.json` (Confirmed stolen data)

---

## 2. STIX 2.1 Threat Bundle Generator

Produces standard STIX 2.1 objects:
- `malware` (Sample metadata, family classification)
- `infrastructure` (C2 servers, Telegram bot endpoints)
- `ipv4-addr` & `domain-name` (Resolved indicators)
- `observed-data` (Canary credentials compromised)
- `relationship` (Malware `communicates-with` Infrastructure)

Example generator snippet:
```python
import uuid
import json
import datetime

def make_stix_bundle(sample_sha256, family_name, c2_ips, c2_domains):
    now = datetime.datetime.utcnow().isoformat() + "Z"
    malware_id = f"malware--{uuid.uuid4()}"
    objects = [
        {
            "type": "malware",
            "spec_version": "2.1",
            "id": malware_id,
            "created": now,
            "modified": now,
            "name": family_name or "Android Infostealer",
            "is_family": False,
            "malware_types": ["trojan", "infostealer"],
            "description": f"Observed Android infostealer sample SHA256: {sample_sha256}"
        }
    ]

    for ip in c2_ips:
        ip_id = f"ipv4-addr--{uuid.uuid4()}"
        objects.append({
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": ip_id,
            "value": ip
        })
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "relationship_type": "communicates-with",
            "source_ref": malware_id,
            "target_ref": ip_id
        })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects
    }
```

---

## 3. Executive Markdown Threat Report Template

Outputs `targets/<slug>/analysis_report.md`:

```markdown
# Dynamic Malware Analysis & Threat Report: <Package Name>

- **Sample SHA-256:** `4a8f9c...`
- **Family Attribution:** Hook / Ermac / CraxsRAT / Generic Infostealer
- **Analysis Timestamp:** 2026-10-16 17:00:00 UTC
- **Device Environment:** Physical Pixel (Android 13, ARM64, Cloaked)

## 1. Executive Summary
- Brief statement of malicious activity observed.
- Status of data theft: Confirmed theft of mock SMS OTP and crypto wallet seed phrase.

## 2. Infrastructure & C2 Indicators
| Indicator | Type | ASN / Registrar | First Seen | Role |
|---|---|---|---|---|
| `198.51.100.24:8443` | IPv4:Port | AS12345 Host | 17:02:11 | Primary C2 Beacon |
| `api.telegram.org/bot...` | Telegram Bot | Telegram Inc. | 17:02:45 | Exfiltration Channel |

## 3. Dynamic Execution & Crypto Observations
- **Cipher Algorithms:** AES/CBC/PKCS5Padding
- **Observed Key:** `0a1b2c3d4e5f...`
- **Exfiltrated Canaries:**
  - `CANARY-SMS-OTP-9921` (Sent via HTTP POST to `/api/v1/gate`)
  - `CANARY-WALLET-ALPHA` (Sent via Telegram bot message)

## 4. Anti-Analysis Techniques Encountered
- Queried `Settings.Global.ADB_ENABLED` (Spoofed to 0 via LSPosed)
- Read `sys.usb.state` via `libc.so` (Spoofed to mtp)
```
