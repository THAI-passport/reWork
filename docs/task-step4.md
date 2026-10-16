# Phase 4 Plan & Task Breakdown: Dynamic Runtime & Pre-Network Crypto Instrumentation (`task-step4.md`)

## 1. Phase Objective & Operational Mandate
The goal of **Phase 4 (Gate G4)** is to intercept pre-network cryptographic operations (AES, DES, RC4, XOR) applied to stolen canary credentials before payloads enter the TLS tunnel, and trace direct low-level native socket connections that bypass standard Java HTTP APIs.

Modern infostealers frequently encrypt stolen mock data in memory using symmetric ciphers prior to transmission, or communicate directly via native C2 sockets (`connect()`, `send()`). If analysts only capture encrypted packets or TLS streams, the adversary's encryption key and inner protocol format remain unknown.

### In-Process Hooking Guardrails
- **Minimal Footprint:** In-process hooks are surgical and restricted to essential primitives (`Cipher.init()`, `Cipher.doFinal()`, `connect()`, `send()`). Monolithic framework hooking is forbidden to avoid timing delays and anti-hooking heuristics.
- **Port Masking:** Frida server executes on non-standard port `38921` (masking default `27042`) under a renamed process (`hl_daemon`).
- **Telemetry Streaming:** All captured buffers, secret keys, IVs, and socket connections are emitted asynchronously via Frida `send()` and streamed to `instrumentation_events.jsonl` on the host.

---

## 2. Tasks for Phase 4

| Task ID | Component | Description | Deliverable |
| :--- | :--- | :--- | :--- |
| **T4.1** | `instrumentation/agent/bypass_antidebug.js` | In-process fallback hooks for `Settings.Global`, `android.os.Debug`, native `libc.so` `__system_property_get`, and `/proc/self/status` `TracerPid`. | `instrumentation/agent/bypass_antidebug.js` |
| **T4.2** | `instrumentation/agent/crypto_dumper.js` | Intercepts `javax.crypto.Cipher` init and doFinal. Dumps algorithm, key bytes, IV bytes, input plaintext, and output ciphertext as hex. | `instrumentation/agent/crypto_dumper.js` |
| **T4.3** | `instrumentation/agent/socket_tracer.js` | Hooks `InetAddress.getByName()`, `java.net.URL`, and native `libc.so` `connect()` / `send()` / `sendto()` for IPv4 and IPv6 direct C2 beacons. | `instrumentation/agent/socket_tracer.js` |
| **T4.4** | `instrumentation/frida_loader.py` | Python host loader spawning target APK over custom port `38921`, loading consolidated agent scripts, and writing JSON telemetry to disk. Includes `--dry-run`. | `instrumentation/frida_loader.py` |
| **T4.5** | Framework Ledgers | Update `docs/steps.md`, `LOG.md`, and `FIXES.md` with engineering rationale and verification results. | `docs/steps.md`, `LOG.md`, `FIXES.md` |

---

## 3. Technical Specifications

### Task 4.1: `instrumentation/agent/bypass_antidebug.js`
- **Java Layer:** Overloads `Settings.Global.getInt` for `adb_enabled` and `development_settings_enabled` returning `0`.
- **Debug APIs:** Overrides `android.os.Debug.isDebuggerConnected()` and `waitingForDebugger()` returning `false`.
- **Native Layer:** Intercepts `__system_property_get` in `libc.so` for `ro.debuggable` (writes `"0"`) and `sys.usb.state` (writes `"mtp"`).
- **Procfs Cloaking:** Intercepts `openat` / `read` calls targeting `/proc/self/status` to mask `TracerPid` as `0`.

### Task 4.2: `instrumentation/agent/crypto_dumper.js`
- **Target APIs:** `javax.crypto.Cipher.init(int opmode, Key key, ...)` and `javax.crypto.Cipher.doFinal(byte[] input)`.
- **Telemetry Payload:**
  - `event`: `"CRYPTO_INIT"` and `"CRYPTO_DOFINAL"`.
  - `algorithm`: e.g., `"AES/CBC/PKCS5Padding"`.
  - `opmode`: `"ENCRYPT_MODE"` (1) vs `"DECRYPT_MODE"` (2).
  - `key_hex`: Extracted secret key bytes.
  - `iv_hex`: Extracted initialization vector.
  - `input_hex` & `output_hex`: Complete pre-encryption and post-encryption byte arrays.

### Task 4.3: `instrumentation/agent/socket_tracer.js`
- **Native Target:** `libc.so` exports `connect`, `send`, `sendto`.
- **Java Target:** `java.net.InetAddress.getByName`, `java.net.URL.<init>`.
- **Telemetry Payload:**
  - `event`: `"SOCKET_CONNECT"`, `"SOCKET_SEND"`, `"DNS_LOOKUP"`.
  - Destination IP, port, URL string, protocol family (`AF_INET`, `AF_INET6`).

### Task 4.4: `instrumentation/frida_loader.py`
- **Host Execution:** Python 3 standard library + optional `frida` package.
- **Port Management:** Connects to `127.0.0.1:38921` via `frida.get_device_manager().add_remote_device(...)`.
- **Simulation Mode:** `--dry-run` simulates spawn, agent compilation, and generates sample `instrumentation_events.jsonl` without requiring an active device.

---

## 4. Verification & Gate G4 Criteria
- **Pass Condition:**
  1. `frida_loader.py` cleanly connects on custom port `38921` and spawns target package.
  2. Injected agents emit structured JSON events to `instrumentation_events.jsonl`.
  3. Pre-encryption canary strings are successfully captured in `CRYPTO_DOFINAL` input buffers.
