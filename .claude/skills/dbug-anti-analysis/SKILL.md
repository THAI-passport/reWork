---
name: dbug-anti-analysis
description: Threat model, detection vector catalog, and stealth countermeasures for evasive Android malware. Details detection mechanisms across Java APIs (Settings.Global, Debug), System Properties (ro.debuggable, sys.usb.state), Native/Procfs (TracerPid, /proc/net/tcp, frida-agent), and Network Environment (tun0, http.proxyHost, SSL Pinning). Use when designing hooks, debugging evasion failures, or troubleshooting malware cloaking.
---

# dbug-anti-analysis: Threat Model & Countermeasures

Evasive Android infostealers actively interrogate their runtime environment before delivering their payload. If any analysis artifact is detected, the malware alters execution flow, emits decoy traffic, or self-terminates.

---

## 1. Detection Vectors & Countermeasure Matrix

| Layer | Monitored Artifacts | Detection Mechanism | Required Countermeasure |
|---|---|---|---|
| **Java Settings** | `Settings.Global.ADB_ENABLED`<br>`DEVELOPMENT_SETTINGS_ENABLED` | Queries `Settings.Global.getInt(resolver, "adb_enabled")` | Spoof return value to `0` at IPC layer via LSPosed `HideDevMode` or early Frida hook. |
| **Java Debugger** | `Debug.isDebuggerConnected()`<br>`Debug.waitingForDebugger()` | Invokes framework debugging APIs | Hook `android.os.Debug` to return `false`. |
| **System Properties** | `ro.debuggable`<br>`ro.secure`<br>`init.svc.adbd`<br>`sys.usb.state`<br>`sys.usb.config` | Reads properties via `android.os.SystemProperties` or native `__system_property_get` | Overwrite properties in kernel/init memory via Magisk/KernelSU `resetprop` (`ro.debuggable 0`, `sys.usb.state mtp`), or hook libc property getters. |
| **Native Procfs** | `/proc/self/status` (`TracerPid`) | Inspects `TracerPid` for non-zero integer indicating `ptrace` attachment | Hook libc `open`/`read` or use eBPF / kernel patch to return `TracerPid: 0`. |
| **Memory Maps** | `/proc/self/maps`<br>`/proc/self/smaps` | Searches for `frida-agent.so`, `gadget.so`, `xposed.dex`, or anonymous executable pages | Run Frida with renamed binaries (`hl_daemon`), memory hiding (Zygisk Shamiko / Zygisk Assistant), or avoid in-process injection entirely. |
| **Network Ports** | `127.0.0.1:27042` (Frida)<br>`127.0.0.1:5555` (ADB) | Connects to localhost or inspects `/proc/net/tcp` | Run Frida on randomized non-standard port (`38921`); isolate or mask local port listings. |
| **Network Interfaces** | `tun0`, `ppp0`, `p2p0` | Enumerates `NetworkInterface.getNetworkInterfaces()` or checks flags for `TRANSPORT_VPN` | **Strictly avoid VPN packet capture tools.** Use an external Wi-Fi Access Point on the Linux host (`ap0`). |
| **Proxy Settings** | `http.proxyHost`<br>`http.proxyPort` | Reads `System.getProperty("http.proxyHost")` or `ConnectivityManager.getDefaultProxy()` | **Strictly avoid OS Wi-Fi proxy settings.** Route traffic transparently at the Linux host gateway with `iptables`. |
| **TLS Certificates** | Custom CA Trust Stores | Checks X.509 certificate chains, public key pins (HPKP / OkHttp `CertificatePinner`) | Extract plaintext TLS out-of-band via kernel eBPF uprobes on `libssl.so` using `ecapture` instead of breaking TLS certificates. |

---

## 2. Strictly Forbidden Anti-Patterns (Failure Traps)

1. **Unmasked USB Debugging:**
   - *Trap:* Enabling USB Debugging in Developer Options and launching the malware without property spoofing.
   - *Consequence:* Infostealer detects `adb_enabled == 1` and `sys.usb.state == "adb"` and remains dormant.
2. **Wi-Fi Proxy in Android Settings:**
   - *Trap:* Specifying a proxy host/port (e.g., `192.168.1.50:8080`) in Android Wi-Fi network configuration.
   - *Consequence:* Malware queries system proxy properties, detects MitM environment, and halts C2 communication.
3. **On-Device VPN Capture (PCAPdroid, Charles, HttpCanary):**
   - *Trap:* Running a local VPN tunnel on the Android test phone to capture packets.
   - *Consequence:* Malware checks `NetworkCapabilities.hasTransport(TRANSPORT_VPN)` or reads `tun0` from `/sys/class/net/` and terminates.
4. **Heavy-Handed In-Process Hooking:**
   - *Trap:* Injecting monolithic Frida scripts that hook hundreds of framework methods simultaneously.
   - *Consequence:* Timing anomalies, memory map signature detection, and app crashes from anti-Frida watchdogs.

---

## 3. Preferred Defense-in-Depth Architecture

```
Physical Android Device (Production Appearance)
 ├── Root Layer: Magisk / KernelSU
 │    └── resetprop: ro.debuggable=0, sys.usb.state=mtp
 ├── System Server Layer: LSPosed
 │    └── HideDevMode: Spoofs Settings.Global at IPC provider
 ├── Kernel Layer: Linux 5.4+ eBPF
 │    └── eCapture: Uprobe on Conscrypt libssl.so (Zero memory writes in malware)
 └── Out-of-Band Network: Isolated Wi-Fi AP (ap0)
      └── Linux Gateway: Transparent NAT + tcpdump (Zero device artifacts)
```
