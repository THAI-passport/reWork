---
name: dbug-canary-correlation
description: Traffic decryption and multi-layer canary data hunting (Gate G5). Merges raw gateway PCAPs with eCapture sslkey.log using tshark/pyshark, and scans decrypted HTTP/2, WebSockets, raw TCP, and Frida crypto dumps for seeded canary credentials across plaintext, Base64, Hex, and URL encodings. Proves data exfiltration and links stolen data directly to destination C2 IP/URL.
---

# dbug-canary-correlation (Gate G5)

Correlate in-memory cryptographic dumps with out-of-band network captures to identify exactly which canary records were stolen and where they were sent.

---

## 1. TLS Traffic Decryption (`parser_correlator/pcap_decryptor.py`)

Using Wireshark/tshark to decrypt captured TLS streams via the eCapture master keylog:

```bash
# Decrypt raw PCAP with sslkey.log and extract plaintext HTTP/HTTP2
tshark -r sessions/current_capture/raw_traffic.pcap \
       -o "tls.keylog_file:sessions/current_capture/sslkey.log" \
       -Y "http.request.method == POST || http2.header.name == \":method\"" \
       -T fields -e frame.time -e ip.dst -e http.request.full_uri -e http.file_data \
       > sessions/current_capture/decrypted_http_requests.txt
```

Python wrapper using `pyshark`:
```python
import pyshark

def decrypt_pcap(pcap_path, keylog_path):
    print(f"[*] Decrypting {pcap_path} with keys from {keylog_path}...")
    cap = pyshark.FileCapture(
        pcap_path,
        override_prefs={'tls.keylog_file': keylog_path},
        display_filter='http || http2'
    )
    flows = []
    for pkt in cap:
        try:
            flow_data = {
                "timestamp": str(pkt.sniff_time),
                "src": pkt.ip.src,
                "dst": pkt.ip.dst,
                "payload": getattr(pkt.http, 'file_data', '') if hasattr(pkt, 'http') else ''
            }
            flows.append(flow_data)
        except AttributeError:
            continue
    cap.close()
    return flows
```

---

## 2. Multi-Encoding Canary Hunter (`parser_correlator/canary_hunter.py`)

Canaries are often transformed before transmission. The hunter scans target buffers across multiple representations:

```python
import base64
import urllib.parse
import json

def generate_encodings(raw_string):
    encodings = {
        "raw": raw_string,
        "base64": base64.b64encode(raw_string.encode()).decode(),
        "hex": raw_string.encode().hex(),
        "url": urllib.parse.quote(raw_string)
    }
    return encodings

def hunt_canaries(canaries_file, decrypted_traffic_file, crypto_dumps_file):
    with open(canaries_file, "r") as f:
        canaries = json.load(f)

    # Compile canary target patterns
    targets = []
    for category, items in canaries.items():
        for item in items:
            for k, val in item.items():
                if isinstance(val, str) and len(val) >= 6:
                    targets.append((category, k, val, generate_encodings(val)))

    findings = []

    # 1. Scan Frida Crypto Dumps
    print("[*] Scanning Frida Crypto Dumps for Canaries...")
    with open(crypto_dumps_file, "r") as f:
        for line in f:
            event = json.loads(line)
            # Scan hex buffers
            raw_text = bytes.fromhex(event.get("input_hex") or "").decode(errors="ignore")
            for cat, key, original, variants in targets:
                for enc_type, pattern in variants.items():
                    if pattern in raw_text or pattern in line:
                        findings.append({
                            "source": "FRIDA_CRYPTO_DUMP",
                            "category": cat,
                            "key": key,
                            "canary": original,
                            "encoding": enc_type,
                            "timestamp": event.get("timestamp_ms")
                        })

    # 2. Scan Decrypted Network Traffic
    print("[*] Scanning Decrypted Network Streams for Canaries...")
    with open(decrypted_traffic_file, "r") as f:
        traffic_content = f.read()
        for cat, key, original, variants in targets:
            for enc_type, pattern in variants.items():
                if pattern in traffic_content:
                    findings.append({
                        "source": "NETWORK_EXFILTRATION",
                        "category": cat,
                        "key": key,
                        "canary": original,
                        "encoding": enc_type,
                        "evidence": "Observed in decrypted HTTP/TCP payload"
                    })

    return findings
```

---

## 3. Output Format
Outputs `targets/<slug>/CANARY_EXFIL_HITS.json`:
- Exact time of exfiltration.
- Exfiltration channel (Telegram, HTTPS POST, raw TCP socket).
- Destination endpoint (IP, Port, Domain, URL path).
- Stolen credential types (SMS OTP, banking cookie, seed phrase).
