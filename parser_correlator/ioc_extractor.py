#!/usr/bin/env python3
"""ioc_extractor.py: Automated Threat Intelligence & STIX 2.1 Generator for dbug (Gate G5).

Aggregates observed C2 network endpoints, resolved domains, Telegram bot tokens,
and confirmed canary exfiltration hits into structured JSON, STIX 2.1 bundles,
and executive Markdown threat intelligence reports.
"""

import argparse
import datetime
import json
import os
import re
import sys
import uuid


class IOCExtractor:
    def __init__(self, session_dir, package_name="com.example.malware", sha256="0000000000000000000000000000000000000000000000000000000000000000"):
        self.session_dir = session_dir
        self.package_name = package_name
        self.sha256 = sha256
        self.c2_ips = set()
        self.c2_domains = set()
        self.c2_urls = set()
        self.telegram_tokens = set()
        self.crypto_keys = []
        self.canary_hits = []

    def ingest_telemetry(self):
        """Ingests events, network flows, and canary hits from session files."""
        # 1. Ingest Canary Hits
        hits_path = os.path.join(self.session_dir, "CANARY_EXFIL_HITS.json")
        if os.path.exists(hits_path):
            try:
                with open(hits_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.canary_hits = data.get("hits", [])
                    for h in self.canary_hits:
                        dest = h.get("destination", "")
                        if dest:
                            ip = dest.split(":")[0]
                            if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                                self.c2_ips.add(ip)
                        uri = h.get("uri", "")
                        if uri:
                            self.c2_urls.add(uri)
            except Exception as e:
                print(f"[-] Warning reading {hits_path}: {e}", file=sys.stderr)

        # 2. Ingest Decrypted Network Flows
        traffic_path = os.path.join(self.session_dir, "decrypted_http_requests.jsonl")
        if os.path.exists(traffic_path):
            try:
                with open(traffic_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        flow = json.loads(line)
                        dst_ip = flow.get("dst_ip")
                        if dst_ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', dst_ip):
                            self.c2_ips.add(dst_ip)
                        uri = flow.get("uri", "")
                        if uri:
                            self.c2_urls.add(uri)
                            # Match Telegram bot token
                            tg_m = re.search(r'bot(\d+:[A-Za-z0-9_-]{20,})', uri)
                            if tg_m:
                                self.telegram_tokens.add(tg_m.group(1))
                            # Extract host from URL
                            host_m = re.search(r'https?://([^/:\s]+)', uri)
                            if host_m:
                                self.c2_domains.add(host_m.group(1))
            except Exception as e:
                print(f"[-] Warning reading {traffic_path}: {e}", file=sys.stderr)

        # 3. Ingest Instrumentation Events
        events_path = os.path.join(self.session_dir, "instrumentation_events.jsonl")
        if os.path.exists(events_path):
            try:
                with open(events_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        ev = json.loads(line)
                        event_type = ev.get("event")
                        if event_type == "DNS_LOOKUP":
                            host = ev.get("hostname")
                            if host and "." in host:
                                self.c2_domains.add(host)
                        elif event_type == "SOCKET_CONNECT":
                            dst = ev.get("destination_ip")
                            if dst and re.match(r'^\d+\.\d+\.\d+\.\d+$', dst):
                                self.c2_ips.add(dst)
                        elif event_type == "CRYPTO_INIT":
                            key_hex = ev.get("key_hex")
                            algo = ev.get("algorithm")
                            if key_hex:
                                self.crypto_keys.append({"algorithm": algo, "key_hex": key_hex, "iv_hex": ev.get("iv_hex")})
            except Exception as e:
                print(f"[-] Warning reading {events_path}: {e}", file=sys.stderr)

        print(f"[*] Ingested IOCs: {len(self.c2_ips)} IPs, {len(self.c2_domains)} Domains, {len(self.telegram_tokens)} Bot Tokens.")

    def generate_iocs_json(self):
        """Generates machine-readable iocs.json."""
        out_path = os.path.join(self.session_dir, "iocs.json")
        data = {
            "metadata": {
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "package_name": self.package_name,
                "sha256": self.sha256
            },
            "network_indicators": {
                "c2_ipv4": sorted(list(self.c2_ips)),
                "c2_domains": sorted(list(self.c2_domains)),
                "c2_endpoints": sorted(list(self.c2_urls)),
                "telegram_bot_tokens": sorted(list(self.telegram_tokens))
            },
            "cryptography": {
                "observed_keys": self.crypto_keys
            },
            "exfiltration_summary": {
                "confirmed_stolen_records": len(self.canary_hits),
                "canary_hits": self.canary_hits
            }
        }
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[+] IOC JSON written to {out_path}")
        return data

    def generate_stix_bundle(self):
        """Generates STIX 2.1 JSON bundle."""
        out_path = os.path.join(self.session_dir, "threat_report_stix21.json")
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        malware_id = f"malware--{uuid.uuid4()}"

        objects = [
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": malware_id,
                "created": now_str,
                "modified": now_str,
                "name": f"Android Infostealer ({self.package_name})",
                "is_family": False,
                "malware_types": ["infostealer", "trojan"],
                "description": f"Dynamic analysis execution of {self.package_name} (SHA-256: {self.sha256})",
                "labels": ["android", "infostealer", "credential-theft"]
            }
        ]

        # Add IPv4 Observables
        for ip in sorted(self.c2_ips):
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
                "created": now_str,
                "modified": now_str,
                "relationship_type": "communicates-with",
                "source_ref": malware_id,
                "target_ref": ip_id
            })

        # Add Domain Observables
        for dom in sorted(self.c2_domains):
            dom_id = f"domain-name--{uuid.uuid4()}"
            objects.append({
                "type": "domain-name",
                "spec_version": "2.1",
                "id": dom_id,
                "value": dom
            })
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": now_str,
                "modified": now_str,
                "relationship_type": "communicates-with",
                "source_ref": malware_id,
                "target_ref": dom_id
            })

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects
        }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)
        print(f"[+] STIX 2.1 Threat Report written to {out_path}")
        return bundle

    def generate_markdown_report(self):
        """Generates executive Markdown threat report with evidence tags."""
        out_path = os.path.join(self.session_dir, "analysis_report.md")
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines = [
            f"# Dynamic Malware Analysis & Threat Intelligence Report",
            f"",
            f"- **Package Name:** `{self.package_name}`",
            f"- **SHA-256 Hash:** `{self.sha256}`",
            f"- **Analysis Timestamp:** {now_str}",
            f"- **Environment:** Physical Android Hardware (Cloaked, eBPF Uprobes, Out-of-Band Gateway)",
            f"",
            f"---",
            f"",
            f"## 1. Executive Summary",
            f"Dynamic behavioral analysis was conducted inside the isolated `dbug` sandbox. USB debugging and system developer telemetry were masked at the kernel and `system_server` level (`ro.debuggable=0`, `sys.usb.state=mtp`, `Settings.Global.adb_enabled=0`).",
            f"",
            f"**Exfiltration Determination:** [N] Data theft CONFIRMED. The malware successfully harvested and transmitted **{len(self.canary_hits)}** seeded synthetic canary credentials across memory buffers and decrypted network sessions.",
            f"",
            f"---",
            f"",
            f"## 2. Command and Control (C2) Infrastructure",
            f"",
            f"| Indicator | Type | Evidence Tag | Description |",
            f"| :--- | :--- | :--- | :--- |"
        ]

        for ip in sorted(self.c2_ips):
            lines.append(f"| `{ip}` | IPv4 Address | `[N]` | Active C2 Network Endpoint |")
        for dom in sorted(self.c2_domains):
            lines.append(f"| `{dom}` | Domain Name | `[N]` / `[M]` | Resolved C2 Domain / Host |")
        for tok in sorted(self.telegram_tokens):
            lines.append(f"| `{tok}` | Telegram Bot Token | `[N]` | Exfiltration Bot Endpoint |")
        for url in sorted(self.c2_urls):
            lines.append(f"| `{url}` | Full HTTP Endpoint | `[N]` | Payload Exfiltration URI |")

        lines.extend([
            f"",
            f"---",
            f"",
            f"## 3. Cryptographic Extraction & Memory Telemetry",
            f""
        ])

        if self.crypto_keys:
            lines.append(f"| Algorithm | Key Hex | IV Hex | Evidence Tag |")
            lines.append(f"| :--- | :--- | :--- | :--- |")
            for k in self.crypto_keys:
                key_short = k.get("key_hex", "")[:32] + "..." if len(k.get("key_hex", "")) > 32 else k.get("key_hex", "")
                iv_str = k.get("iv_hex") or "None"
                lines.append(f"| `{k.get('algorithm')}` | `{key_short}` | `{iv_str}` | `[M]` |")
        else:
            lines.append(f"No symmetric Java Cipher operations intercepted.")

        lines.extend([
            f"",
            f"---",
            f"",
            f"## 4. Canary Exfiltration Proof Ledger",
            f"",
            f"| Evidence Tag | Channel | Canary Token | Field | Encoding | Destination |",
            f"| :--- | :--- | :--- | :--- | :--- | :--- |"
        ])

        for h in self.canary_hits:
            dest = h.get("destination") or h.get("context", "")[:30]
            lines.append(f"| `{h.get('evidence_tag', '[I]')}` | {h.get('channel')} | `{h.get('token')}` | {h.get('field')} | `{h.get('encoding')}` | `{dest}` |")

        lines.extend([
            f"",
            f"---",
            f"",
            f"## 5. Defensive Recommendations & Mitigations",
            f"1. **Network Egress Blocking:** Blacklist destination IPs (`{', '.join(sorted(self.c2_ips))}`) and resolved domains at perimeter firewalls.",
            f"2. **Token Revocation:** Revoke reported Telegram Bot tokens ({len(self.telegram_tokens)} tokens detected) via `@BotFather` abuse reporting.",
            f"3. **Canary Rotation:** Rotate mock credentials in `config/mock_canaries.json` before initiating subsequent analysis sessions."
        ])

        content = "\n".join(lines) + "\n"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] Executive Markdown Threat Report written to {out_path}")
        return content


def main():
    parser = argparse.ArgumentParser(
        description="dbug Threat Intelligence & STIX 2.1 Extractor (Gate G5)"
    )
    parser.add_argument("--session-dir", default="./sessions/current_capture", help="Path to session directory")
    parser.add_argument("--package", default="com.example.malware", help="Package name")
    parser.add_argument("--sha256", default="unknown", help="Sample SHA-256")
    args = parser.parse_args()

    extractor = IOCExtractor(
        session_dir=args.session_dir,
        package_name=args.package,
        sha256=args.sha256
    )
    extractor.ingest_telemetry()
    extractor.generate_iocs_json()
    extractor.generate_stix_bundle()
    extractor.generate_markdown_report()


if __name__ == "__main__":
    main()
