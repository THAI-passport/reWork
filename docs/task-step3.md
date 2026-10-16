# Phase 3 Plan & Task Breakdown: Zero-Footprint Network & TLS Interception (`task-step3.md`)

## 1. Phase Objective & Operational Mandate
The goal of **Phase 3 (Gate G3)** is to intercept 100% of out-of-band network traffic (DNS lookups, raw TCP/UDP flows, and plaintext TLS sessions) without setting an Android system proxy (`http.proxyHost`), without installing untrusted user CA certificates, and without creating VPN (`tun0`) interfaces on the physical device.

Modern infostealers evade network analysis by:
1. **Detecting System Proxies:** Reading `http.proxyHost` or calling `ConnectivityManager.getDefaultProxy()`.
2. **Checking for VPN Interception:** Scanning `NetworkInterface.getNetworkInterfaces()` for `tun0` or `ppp0`.
3. **Enforcing TLS Pinning:** Using OkHttp `CertificatePinner` or custom native trust stores, aborting handshakes if an untrusted proxy CA is encountered.

### Stealth Countermeasure Hierarchy
- **Network Layer:** Transparent external routing via a dedicated Linux Wi-Fi Access Point (`ap0`) with `iptables` NAT masquerade and raw `tcpdump` capture.
- **Crypto Layer:** Linux kernel eBPF uprobes on Conscrypt's `libssl.so` using `eCapture` on `wlan0`. Extracts TLS master secrets (`sslkey.log`) and decrypted packet payloads (`tls_decrypted.pcapng`) directly from kernel space with zero memory modification inside the malware address space.

---

## 2. Tasks for Phase 3

| Task ID | Component | Description | Deliverable |
| :--- | :--- | :--- | :--- |
| **T3.1** | `network_capture/gateway_setup.sh` | Linux Wi-Fi AP (`ap0`) configuration, hostapd, dnsmasq, iptables NAT, and background tcpdump capture. Supports `start`, `stop`, `status`, and `--dry-run`. | `network_capture/gateway_setup.sh` |
| **T3.2** | `network_capture/ecapture_runner.py` | Python host controller managing static ARM64 `ecapture` eBPF uprobes on `/apex/com.android.conscrypt/lib64/libssl.so`. Emits `sslkey.log` and `tls_decrypted.pcapng`. | `network_capture/ecapture_runner.py` |
| **T3.3** | Graceful Teardown & Buffer Flushing | Implements signal handlers (SIGINT/SIGTERM), syncs device eBPF buffers, and pulls capture artifacts to the host workstation. | Integrated in `ecapture_runner.py` & `gateway_setup.sh` |
| **T3.4** | `network_capture/sinkhole_inetsim.conf` | Isolated DNS and HTTP/HTTPS sinkhole configuration for safe C2 emulation in offline lab environments. | `network_capture/sinkhole_inetsim.conf` |
| **T3.5** | Framework Ledgers | Update `docs/steps.md`, `LOG.md`, and `FIXES.md` with engineering rationale and verification results. | `docs/steps.md`, `LOG.md`, `FIXES.md` |

---

## 3. Technical Specifications

### Task 3.1: `network_capture/gateway_setup.sh`
- **Host Dependencies:** Linux host (or remote Linux AP gateway) with `hostapd`, `dnsmasq`, `iptables`, `tcpdump`.
- **Interface Parameters:** AP interface `ap0` (IP: `192.168.44.1`), upstream interface `eth0`, subnet `192.168.44.0/24`.
- **Capture File:** Outputs `raw_traffic.pcap` with full packet payloads (`-s 0`).
- **Dry-run Mode:** `--dry-run` flag prints exact commands for macOS or non-Linux host testing.

### Task 3.2: `network_capture/ecapture_runner.py`
- **Device Requirements:** Android 12-14 (ARM64), Linux kernel 5.4+ with eBPF and uprobes enabled.
- **Binary Target:** `/data/local/tmp/ecapture`.
- **Target Library:** `/apex/com.android.conscrypt/lib64/libssl.so` (with fallback to 32-bit `/apex/com.android.conscrypt/lib/libssl.so`).
- **CLI Commands:** `start`, `stop`, `status`, `pull`.
- **Simulation:** Full `--dry-run` support for automated host testing.

---

## 4. Verification & Gate G3 Criteria
- **Pass Condition:**
  1. `gateway_setup.sh start` successfully initializes routing and begins `tcpdump` on `ap0`.
  2. `ecapture_runner.py start` attaches eBPF uprobes to Conscrypt `libssl.so`.
  3. `ecapture_runner.py stop --pull-dir <dir>` cleanly shuts down eCapture via SIGINT/SIGTERM, flushes buffers, and pulls `sslkey.log` and `tls_decrypted.pcapng`.
