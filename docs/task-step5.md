# Phase 5 Plan & Task Breakdown: Traffic Decryption, Canary Correlation & IOC Reporting (`task-step5.md`)

## 1. Phase Objective & Operational Mandate
The goal of **Phase 5 (Gate G5)** is to automatically correlate what the malware stole in memory with the exact remote server it contacted.

We bridge two independent observation channels:
1. **Memory Channel (Frida `instrumentation_events.jsonl`):** Pre-encryption buffers, secret keys, IVs, and plaintext tokens harvested from `Cipher.doFinal()`.
2. **Network Channel (`raw_traffic.pcap` + `sslkey.log` via eCapture):** Decrypted TLS streams and raw TCP packets captured out-of-band on the gateway.

By running a multi-encoding pattern search (raw, base64, hex, URL-encoded) against both channels using `config/mock_canaries.json`, the sandbox provides indisputable evidence of data theft, identifies exfiltration channels (Telegram, HTTP POST, direct socket), and generates standardized STIX 2.1 threat intelligence bundles.

---

## 2. Tasks for Phase 5

| Task ID | Component | Description | Deliverable |
| :--- | :--- | :--- | :--- |
| **T5.1** | `parser_correlator/pcap_decryptor.py` | Combines raw gateway PCAP and eCapture `sslkey.log` using `tshark` / `pyshark` to extract plaintext HTTP/1.1 and HTTP/2 flows. | `parser_correlator/pcap_decryptor.py` |
| **T5.2** | `parser_correlator/canary_hunter.py` | Multi-encoding canary correlation engine scanning crypto dumps and decrypted traffic for mock data leakage. | `parser_correlator/canary_hunter.py` |
| **T5.3** | `parser_correlator/ioc_extractor.py` | Normalizes C2 endpoints, domains, and tokens into structured JSON, STIX 2.1 bundles, and executive Markdown reports. | `parser_correlator/ioc_extractor.py` |
| **T5.4** | `orchestrator.py` | Master CLI tying all gates (G0-G5) into an automated end-to-end analysis workflow (`python3 orchestrator.py --apk sample.apk --duration 120`). | `orchestrator.py` |
| **T5.5** | Framework Ledgers & Summaries | Create `completed.md`, `problem_solution.md`, and update `docs/steps.md`, `LOG.md`, `FIXES.md`. | Ledgers |

---

## 3. Technical Specifications

### Task 5.1: `parser_correlator/pcap_decryptor.py`
- **Decryption Engine:** Executes `tshark` with `-o tls.keylog_file:<sslkey.log>` to decrypt TLS records.
- **Extracted Fields:** Frame timestamp, source IP/port, destination IP/port, HTTP method, URI, request headers, POST body data (`http.file_data`).
- **Resilience:** If `tshark` is not installed or the PCAP is empty, provides a graceful fallback parser so the pipeline continues processing without unhandled exceptions.

### Task 5.2: `parser_correlator/canary_hunter.py`
- **Target Ingestion:** Reads all synthetic credentials from `config/mock_canaries.json`.
- **Encoding Permutations:** Expands each canary into raw UTF-8, Base64, Hexadecimal, and URL-encoded variants.
- **Search Scope:**
  1. Frida crypto events: `input_utf8`, `input_hex`, `output_utf8`.
  2. Decrypted network requests: POST bodies, query strings, headers.
- **Hit Record:** Timestamp, canary category, token name, encoding matched, channel (Memory vs Network), destination IP/URL.

### Task 5.3: `parser_correlator/ioc_extractor.py`
- **Observables:** C2 IPv4 addresses, domains, ports, URLs, Telegram bot tokens, cryptocurrency addresses.
- **Outputs:**
  1. `iocs.json`: Machine-readable summary of all indicators.
  2. `threat_report_stix21.json`: STIX 2.1 bundle with `malware`, `infrastructure`, `ipv4-addr`, `domain-name`, and `relationship` objects.
  3. `analysis_report.md`: Executive threat report with evidence tags (`[C]`, `[D]`, `[M]`, `[N]`, `[E]`).

### Task 5.4: `orchestrator.py`
- **Workflow Pipeline:**
  1. Load config & sample metadata (`lab_config.yaml`).
  2. Run pre-flight stealth audit (`verify_stealth_state.py`).
  3. Seed mock canaries (`seed_canaries.py`).
  4. Start gateway capture (`gateway_setup.sh start`) and eBPF (`ecapture_runner.py start`).
  5. Spawn malware with Frida instrumentation (`frida_loader.py`).
  6. Countdown observation window.
  7. Teardown: terminate malware, flush and pull PCAPs/keylogs, clean canaries (`seed_canaries.py --clean`).
  8. Correlate: run `pcap_decryptor.py`, `canary_hunter.py`, `ioc_extractor.py`.
  9. Print executive findings summary to console.
- **Offline Simulation:** `--dry-run` simulates the entire analysis lifecycle from start to finish.

---

## 4. Verification & Gate G5 Criteria
- **Pass Condition:**
  1. `pcap_decryptor.py` outputs decrypted HTTP flow records.
  2. `canary_hunter.py` identifies canary tokens in memory dumps and network streams.
  3. `ioc_extractor.py` outputs valid STIX 2.1 JSON and Markdown report.
  4. `orchestrator.py --dry-run` completes all gates G1 through G5 end-to-end with exit code 0.
