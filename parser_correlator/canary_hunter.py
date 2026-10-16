#!/usr/bin/env python3
"""canary_hunter.py: Multi-Encoding Canary Exfiltration Correlation Engine (Gate G5).

Scans Frida cryptographic dumps and decrypted network streams for seeded synthetic
canary credentials across raw, Base64, Hexadecimal, and URL-encoded formats.
Provides definitive proof of data theft and links stolen data directly to destination C2s.
"""

import argparse
import base64
import json
import os
import sys
import urllib.parse


class CanaryHunter:
    def __init__(self, canaries_path, crypto_events_path, decrypted_traffic_path, output_hits_path):
        self.canaries_path = canaries_path
        self.crypto_events_path = crypto_events_path
        self.decrypted_traffic_path = decrypted_traffic_path
        self.output_hits_path = output_hits_path
        self.targets = []
        self.hits = []

    def _generate_encodings(self, raw_str):
        """Generates common malware data transformation representations."""
        variants = {"raw": raw_str}
        try:
            b64 = base64.b64encode(raw_str.encode("utf-8")).decode("utf-8")
            variants["base64"] = b64
        except Exception:
            pass
        try:
            hx = raw_str.encode("utf-8").hex()
            variants["hex"] = hx
        except Exception:
            pass
        try:
            url_enc = urllib.parse.quote(raw_str)
            if url_enc != raw_str:
                variants["url"] = url_enc
        except Exception:
            pass
        return variants

    def load_canary_targets(self):
        """Loads and indexes all high-entropy strings from mock_canaries.json."""
        if not os.path.exists(self.canaries_path):
            print(f"[!] Canaries file not found at '{self.canaries_path}'", file=sys.stderr)
            return

        with open(self.canaries_path, "r", encoding="utf-8") as f:
            canaries_data = json.load(f)

        for category, items in canaries_data.items():
            if not isinstance(items, list):
                continue
            for item in items:
                token = item.get("canary_token", "CANARY_TOKEN")
                for field_key, field_val in item.items():
                    if isinstance(field_val, str) and len(field_val) >= 4:
                        self.targets.append({
                            "category": category,
                            "token": token,
                            "field": field_key,
                            "original": field_val,
                            "encodings": self._generate_encodings(field_val)
                        })

        print(f"[*] Indexed {len(self.targets)} canary search patterns across categories.")

    def scan_memory_dumps(self):
        """Scans Frida Cipher.doFinal and instrumentation events."""
        if not os.path.exists(self.crypto_events_path):
            print(f"[-] Notice: Memory dumps file '{self.crypto_events_path}' not found.")
            return

        print(f"[*] Scanning Frida memory dumps: {self.crypto_events_path}")
        with open(self.crypto_events_path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except Exception:
                    continue

                # Compile searchable text blob from event
                search_blob = " ".join([
                    str(event.get("input_utf8", "") or ""),
                    str(event.get("input_hex", "") or ""),
                    str(event.get("output_utf8", "") or ""),
                    str(event.get("output_hex", "") or ""),
                    line
                ])

                for target in self.targets:
                    for enc_type, pattern in target["encodings"].items():
                        if pattern in search_blob:
                            self.hits.append({
                                "channel": "MEMORY",
                                "category": target["category"],
                                "token": target["token"],
                                "field": target["field"],
                                "encoding": enc_type,
                                "matched_value": target["original"][:50],
                                "timestamp": event.get("timestamp_ms"),
                                "context": f"Cipher event: {event.get('algorithm', 'CRYPTO')} (Line {line_idx})",
                                "evidence_tag": "[M]"
                            })

    def scan_network_streams(self):
        """Scans decrypted HTTP/TCP application payloads."""
        if not os.path.exists(self.decrypted_traffic_path):
            print(f"[-] Notice: Decrypted traffic file '{self.decrypted_traffic_path}' not found.")
            return

        print(f"[*] Scanning decrypted network traffic: {self.decrypted_traffic_path}")
        with open(self.decrypted_traffic_path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    flow = json.loads(line)
                except Exception:
                    continue

                search_blob = " ".join([
                    str(flow.get("uri", "") or ""),
                    str(flow.get("payload", "") or ""),
                    line
                ])

                for target in self.targets:
                    for enc_type, pattern in target["encodings"].items():
                        if pattern in search_blob:
                            dst = f"{flow.get('dst_ip', '0.0.0.0')}:{flow.get('dst_port', '0')}"
                            uri = flow.get("uri", "")
                            self.hits.append({
                                "channel": "NETWORK",
                                "category": target["category"],
                                "token": target["token"],
                                "field": target["field"],
                                "encoding": enc_type,
                                "matched_value": target["original"][:50],
                                "timestamp": flow.get("timestamp"),
                                "destination": dst,
                                "uri": uri,
                                "context": f"HTTP {flow.get('method', 'POST')} to {dst}{uri}",
                                "evidence_tag": "[N]"
                            })

    def deduplicate_and_persist(self):
        """Deduplicates matched hits and writes CANARY_EXFIL_HITS.json."""
        unique_hits = []
        seen = set()
        for h in self.hits:
            key = (h["channel"], h["token"], h["field"], h["encoding"], h.get("destination"))
            if key not in seen:
                seen.add(key)
                unique_hits.append(h)

        os.makedirs(os.path.dirname(os.path.abspath(self.output_hits_path)), exist_ok=True)
        with open(self.output_hits_path, "w", encoding="utf-8") as f:
            json.dump({"total_exfiltration_hits": len(unique_hits), "hits": unique_hits}, f, indent=2)

        print("=" * 65)
        print("CANARY EXFILTRATION CORRELATION REPORT")
        print("=" * 65)
        if unique_hits:
            print(f"[!] CONFIRMED DATA THEFT: {len(unique_hits)} canary records exfiltrated!")
            printf_fmt = "%-8s %-12s %-22s %-8s %-25s"
            print(printf_fmt % ("Tag", "Channel", "Canary Token", "Encoding", "Destination / Context"))
            print("-" * 75)
            for h in unique_hits:
                dest = h.get("destination") or h.get("context", "")[:25]
                print(printf_fmt % (
                    h["evidence_tag"],
                    h["channel"],
                    h["token"][:22],
                    h["encoding"],
                    dest[:25]
                ))
        else:
            print("[+] Zero canary tokens detected in memory dumps or network streams.")
        print("=" * 65)
        print(f"[+] Output persisted: {self.output_hits_path}")
        return unique_hits


def main():
    parser = argparse.ArgumentParser(
        description="dbug Canary Exfiltration Hunter & Correlation Engine (Gate G5)"
    )
    parser.add_argument("--canaries", default="config/mock_canaries.json", help="Path to mock_canaries.json")
    parser.add_argument("--events", default="./sessions/current_capture/instrumentation_events.jsonl", help="Frida events log")
    parser.add_argument("--traffic", default="./sessions/current_capture/decrypted_http_requests.jsonl", help="Decrypted traffic log")
    parser.add_argument("--output", default="./sessions/current_capture/CANARY_EXFIL_HITS.json", help="Output hits JSON")
    args = parser.parse_args()

    hunter = CanaryHunter(
        canaries_path=args.canaries,
        crypto_events_path=args.events,
        decrypted_traffic_path=args.traffic,
        output_hits_path=args.output
    )
    hunter.load_canary_targets()
    hunter.scan_memory_dumps()
    hunter.scan_network_streams()
    hunter.deduplicate_and_persist()


if __name__ == "__main__":
    main()
