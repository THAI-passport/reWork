---
name: dbug-device-cloaking
description: On-device environment cloaking and pre-flight state validation (Gate G1). Keeps ADB daemon operational while masking USB debugging, ro.debuggable, sys.usb.state, and developer telemetry from user-space malware via Magisk/KernelSU resetprop and LSPosed HideDevMode. Run before launching malware to audit ports, interfaces, and system properties.
---

# dbug-device-cloaking (Gate G1)

Maintain full ADB automation control over the physical test phone while presenting a completely stock, un-debugged production Android OS state to user-space applications.

---

## 1. Automated Property Masking Script

### `device_cloaking/apply_stealth_props.sh`
Run on the Android device with root privileges via `adb shell su -c`:

```bash
#!/system/bin/sh
# Mask system properties using Magisk / KernelSU resetprop

ACTION="${1:-apply}"

if [ "$ACTION" = "restore" ]; then
    echo "[*] Restoring default debug properties..."
    resetprop ro.debuggable 1
    resetprop sys.usb.state adb
    resetprop sys.usb.config adb
    resetprop init.svc.adbd running
    echo "[+] Restore complete."
    exit 0
fi

echo "[*] Applying stealth cloaking properties..."
# 1. Mask debuggable and security flags
resetprop ro.debuggable 0
resetprop ro.secure 1
resetprop ro.build.type user
resetprop ro.build.tags release-keys

# 2. Mask USB state to simulate ordinary charging or MTP
resetprop sys.usb.state mtp
resetprop sys.usb.config mtp
resetprop persist.sys.usb.config mtp

# 3. Mask adbd service status without killing the socket
resetprop init.svc.adbd stopped

echo "[+] Stealth properties applied successfully."
```

---

## 2. System Server Provider Spoofing (LSPosed)

Malware frequently calls:
```java
Settings.Global.getInt(context.getContentResolver(), "adb_enabled", 0);
Settings.Global.getInt(context.getContentResolver(), "development_settings_enabled", 0);
```
Querying these settings triggers IPC to `system_server`'s `SettingsProvider`.
- **Countermeasure:** Enable LSPosed module `HideDevMode` (or equivalent Xposed module) targeting `system_server`.
- This ensures that when any unprivileged app queries `SettingsProvider`, the system returns `0` without needing in-process hooks inside the malware process.

---

## 3. Pre-Flight Verification Audit

### `device_cloaking/verify_stealth_state.py`
Run on the host machine prior to each analysis session:

```python
import subprocess
import sys

def adb_shell(cmd):
    return subprocess.check_output(["adb", "shell", cmd], text=True).strip()

def audit():
    print("[*] Running Pre-Flight Stealth State Audit...")
    failures = []

    # 1. Audit System Properties
    checks = {
        "ro.debuggable": "0",
        "ro.secure": "1",
        "sys.usb.state": "mtp",
        "sys.usb.config": "mtp",
        "init.svc.adbd": "stopped"
    }
    for prop, expected in checks.items():
        val = adb_shell(f"getprop {prop}")
        if val != expected:
            failures.append(f"Property {prop} is '{val}', expected '{expected}'")

    # 2. Audit Network Interfaces (No VPN / tun)
    ifaces = adb_shell("ip -o link show | awk -F': ' '{print $2}'").split()
    for iface in ifaces:
        if iface.startswith(("tun", "ppp", "p2p")):
            failures.append(f"Forbidden interface found: {iface}")

    # 3. Audit Proxy Properties
    proxy = adb_shell("getprop http.proxyHost")
    if proxy:
        failures.append(f"HTTP proxy detected: {proxy}")

    # 4. Audit Default Frida Port
    netstat = adb_shell("netstat -tuln 2>/dev/null || cat /proc/net/tcp")
    if "27042" in netstat or ":69A2" in netstat: # 27042 in hex is 69A2
        failures.append("Default Frida port 27042 is open!")

    if failures:
        print("[!] Pre-flight audit FAILED with the following violations:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)

    print("[+] All stealth cloaking checks PASSED. Environment is clean.")

if __name__ == "__main__":
    audit()
```

---

## 4. Operational Checklist Before Detonation
- [ ] Physical device Wi-Fi connected to isolated AP (`ap0`).
- [ ] Gateway routing confirmed (`ping -c 1 1.1.1.1` via physical phone works).
- [ ] Properties masked: `ro.debuggable == 0`, `sys.usb.state == mtp`.
- [ ] `verify_stealth_state.py` returns exit code `0`.
- [ ] ADB connection verified functional (`adb shell` still works over USB or TCP).
