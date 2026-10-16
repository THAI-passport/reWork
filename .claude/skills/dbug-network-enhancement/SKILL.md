---
name: dbug-network-enhancement
description: Network analysis enhancement beyond eBPF capture. MITM proxy fallback, HTTP/2/WebSocket/gRPC inspection, TLS fingerprinting (JA3/JA4), certificate pinning bypass catalog, and pcap/sslkey.log merging robustness. Gate G3 network analysis for all targets.
---

# dbug-network-enhancement (Gate G3: Network)

Network analysis goes beyond raw pcap capture to protocol-aware inspection. Enhances the existing eBPF capture (dbug-ebpf-capture skill) with MITM fallback, application-layer decoding, and TLS fingerprinting.

## 1. Capture layers
1. **L3/L4 raw capture:** existing eBPF/tcpdump PCAP (out-of-band, no Android proxy/VPN).
2. **MITM proxy fallback:** when eBPF unavailable, run mitmproxy-style transparent proxy on the Linux gateway. Requires installing user CA on the target (may trigger pinning detection — `[I]` risk).
3. **Application-layer decode:** HTTP/1.1, HTTP/2, WebSocket, gRPC, DNS, TLS handshake parsing from decrypted streams.

## 2. TLS fingerprinting
- **JA3/JA4:** compute client/server TLS fingerprint from ClientHello (cipher suites, extensions, elliptic curves). Compare against known fingerprints to identify libraries/frameworks.
- **Certificate pinning bypass catalog:** document known bypass techniques per platform (Android: trustkit, network security config; iOS: TrustKit, AFNetworking; desktop: cert stores).

## 3. PCAP/sslkey.log merging
- Merge eCapture sslkey.log with raw tcpdump PCAP using tshark/pyshark (existing `pcap_decryptor.py`).
- Handle multiple TLS sessions, session resumption, and QUIC.
- Output decrypted HTTP/TCP stream log.

## 4. Output
- `network_analysis_report.md` — TLS fingerprints, endpoints, protocols, pinning bypass status
- `decrypted_streams.jsonl` — decrypted application-layer streams
- Sync to `targets/<slug>/` per AGENTS.md contract

## 5. Evidence tags
- `[C]` confirmed in capture/decrypted stream
- `[V]` verified by test vector against real code
- `[I]` inferred (fingerprint match, bypass catalog)
- `[U]` unknown (encrypted, unknown protocol)

## 6. Dependencies
- `tshark` (optional; `setup-tools.sh`)
- `pyshark` or `scapy` (optional Python modules)
- `mitmproxy` (optional MITM fallback)