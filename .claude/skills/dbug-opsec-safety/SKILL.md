---
name: dbug-opsec-safety
description: Operational security, malware containment, and lab safety protocols for defensive Android malware research. Enforces physical and network isolation, prevents lateral movement or DDoS egress, governs safe sample handling and quarantine, and ensures sensitive lab host IP/MAC addresses are scrubbed from reports and commits. Use before executing untrusted samples, reviewing network boundaries, or publishing intelligence reports.
---

# dbug-opsec-safety: Lab Containment & Hygiene

Guidelines and guardrails for conducting safe, isolated dynamic analysis of evasive Android malware.

---

## 1. Network Containment & Egress Guardrails

1. **Dedicated Isolated Access Point:**
   - The test phone connects exclusively to `ap0` on the isolated Linux gateway.
   - The test phone must NEVER share an SSID or VLAN with personal devices, developer machines, or corporate networks.
2. **Immediate Abort & Kill Triggers:**
   Terminate the malware process (`adb shell am force-stop <package>` / `kill -9`) immediately if any of the following are observed in gateway logs:
   - **Local Subnet Scanning:** Attempts to ping, ARP scan, or port-scan RFC1918 addresses (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`).
   - **High-Volume Packet Flooding / DDoS:** Burst UDP/SYN flooding exceeding 100 packets/second.
   - **Outbound Spreading / Worm Activity:** Exploitation attempts against Bluetooth, Wi-Fi Direct, or adjacent devices.
   - **Telephony Abuse:** Bulk SMS dispatch to premium-rate numbers.
3. **No Active Offensive Interaction:**
   - Never interactively log in to threat-actor web panels.
   - Never submit attacker forms or solve adversary CAPTCHAs.
   - Observe, capture, and record passively.

---

## 2. Sample Handling & Storage Discipline

- **Quarantine Location:** Store untrusted APKs in a dedicated git-ignored directory (`samples/` or `targets/<sample_hash>/artifacts/`).
- **Archive Password Convention:** Compressed malware archives must be encrypted with standard research password `infected`.
- **Never Execute on Host:** Never run APK unpacking scripts that invoke untrusted native helpers on the host workstation. Decompilation with `jadx` and `apktool` runs inside unprivileged user containers or sandboxed CLI environments.
- **Git Hygiene:** Never add raw binaries (`.apk`, `.dex`, `.so`, `.jar`, `.elf`) to git tracking. Run `git status` before every commit.

---

## 3. Telemetry Sanitization & Privacy Scrubbing

Before committing notes, logs, or STIX reports, scrub:
| Item | Sensitive Content | Sanitization Format |
|---|---|---|
| **Lab Wi-Fi Gateway MAC** | Real BSSID / MAC address | `XX:XX:XX:XX:00:01` |
| **Analyst Host Public IP** | Real egress IP address | Mask or replace with documentation placeholder `198.51.100.1` |
| **Device Serial Number** | Real hardware IMEI / ADB serial | `<DEVICE_SERIAL_REDACTED>` |
| **Analyst File Paths** | `/Users/<username>/...` | `/workspace/dbug/...` |

---

## 4. Post-Session Decontamination
After every malware execution session:
1. `adb uninstall <package>`
2. Purge device temporary folders: `adb shell su -c "rm -rf /data/local/tmp/*"`
3. Clear mock canaries: `python3 config/seed_canaries.py --clean`
4. Reboot test phone if persistent service or accessibility hooks were granted.
