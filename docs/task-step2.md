# Phase 2 Plan & Task Breakdown: On-Device Stealth Cloaking (`task-step2.md`)

## 1. Phase Objective & Operational Mandate
The goal of **Phase 2 (On-Device Stealth Cloaking)** is to maintain active USB debugging (`adbd`) and host automation capabilities while making the Android OS report a completely stock, un-debugged production state to user-space applications.

Modern Android infostealers actively query multiple system layers to detect dynamic instrumentation environments:
1. **System Properties:** Inspecting `ro.debuggable`, `ro.secure`, `sys.usb.state`, `sys.usb.config`, and `init.svc.adbd`.
2. **Java SettingsProvider:** Querying `Settings.Global.ADB_ENABLED` and `DEVELOPMENT_SETTINGS_ENABLED`.
3. **Network Interfaces & Proxies:** Detecting `tun0`/`ppp0` VPN interfaces and `http.proxyHost` properties.
4. **Local Network Ports:** Connecting to or scanning `/proc/net/tcp` for default Frida port `27042` (`:69A2`) or remote ADB port `5555`.

If any of these indicators are exposed, the malware terminates execution or emits decoy traffic, blinding the analyst to true C2 infrastructure.

---

## 2. Tasks for Phase 2

| Task ID | Component | Description | Deliverable |
| :--- | :--- | :--- | :--- |
| **T2.1** | `device_cloaking/apply_stealth_props.sh` | Shell script for device root (`su -c`) using Magisk/KernelSU `resetprop` to mask properties in memory. Supports `apply`, `restore`, and `status`. | `device_cloaking/apply_stealth_props.sh` |
| **T2.2** | `device_cloaking/check_lsposed_devmode.sh` | Diagnostic script auditing `system_server` Binder spoofing and LSPosed `HideDevMode` status. | `device_cloaking/check_lsposed_devmode.sh` |
| **T2.3** | `device_cloaking/verify_stealth_state.py` | Host-side pre-flight audit asserting 5 cloaking layers before malware launch. Includes `--dry-run`, `--push-and-apply`, and `--restore`. | `device_cloaking/verify_stealth_state.py` |
| **T2.4** | Framework Ledgers | Update `docs/steps.md`, `LOG.md`, and `FIXES.md` with engineering rationale and test results. | `docs/steps.md`, `LOG.md`, `FIXES.md` |

---

## 3. Technical Specifications per Task

### Task 2.1: `device_cloaking/apply_stealth_props.sh`
- **Execution Environment:** Android shell with root privileges (`su -c`).
- **Binary Discovery:** Detects `resetprop` in standard PATH, `/data/adb/ksu/bin/resetprop` (KernelSU), `/data/adb/ap/bin/resetprop` (APatch), or `/system/bin/resetprop` (Magisk).
- **Target Properties (`apply`):**
  - `ro.debuggable 0`
  - `ro.secure 1`
  - `ro.build.type user`
  - `ro.build.tags release-keys`
  - `sys.usb.state mtp`
  - `sys.usb.config mtp`
  - `persist.sys.usb.config mtp`
  - `init.svc.adbd stopped` (masks property while leaving daemon socket alive)
- **Target Properties (`restore`):**
  - `ro.debuggable 1`
  - `sys.usb.state adb`
  - `sys.usb.config adb`
  - `init.svc.adbd running`
- **Status Mode (`status`):** Audits current property values and reports PASS/FAIL status table.

### Task 2.2: `device_cloaking/check_lsposed_devmode.sh`
- **Objective:** Verify that `Settings.Global.getInt("adb_enabled")` and `"development_settings_enabled"` return `0` at the `system_server` IPC level without injecting in-process hooks into the target malware.
- **Checks:**
  1. Inspects `/data/adb/lspd` and `/data/adb/modules` for LSPosed / Zygisk framework status.
  2. Queries `settings get global adb_enabled` and `settings get global development_settings_enabled`.
  3. Verifies `content query --uri content://settings/global --where "name='adb_enabled'"` from unprivileged contexts.
  4. Returns structured diagnostic output with clear remediation instructions if LSPosed `HideDevMode` is inactive.

### Task 2.3: `device_cloaking/verify_stealth_state.py`
- **Host Execution:** Python 3 standard library with optional PyYAML support.
- **Pre-Flight Audit Layers:**
  1. **Layer 1: System Properties:** `ro.debuggable == 0`, `ro.secure == 1`, `sys.usb.state == mtp`, `init.svc.adbd == stopped`.
  2. **Layer 2: SettingsProvider:** `Settings.Global.adb_enabled in ('0', 'null', '')`.
  3. **Layer 3: Network Hygiene:** Zero `tun`, `ppp`, or `p2p` interfaces; `http.proxyHost` empty.
  4. **Layer 4: Port Exposure:** Port `27042` (`:69A2`) absent from `/proc/net/tcp` and `/proc/net/tcp6`.
  5. **Layer 5: ADB Transport Resilience:** Confirms ADB responds despite masked properties.
- **Automation CLI:**
  - `--config <path>`: Path to `config/lab_config.yaml`.
  - `--serial <id>`: Target ADB serial.
  - `--dry-run`: Simulation mode for automated testing without physical hardware.
  - `--push-and-apply`: Pushes `apply_stealth_props.sh` to device and executes it via `su -c` before auditing.
  - `--restore`: Pushes and executes restore command on device.

---

## 4. Verification & Gate G1 Criteria
- **Pass Condition:** `python3 device_cloaking/verify_stealth_state.py` exits with code `0`.
- **Fail Condition:** Any property mismatch, detected VPN interface, active proxy, or exposed Frida port causes exit code `1` and prints exact violation.
- **Teardown / Restore:** Verified that `--restore` returns device to developer state.
