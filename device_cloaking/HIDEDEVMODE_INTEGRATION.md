# HideDevMode Integration Runbook (dbug Gate G1, Layer B)

**Upstream:** https://github.com/dongdevcom/HideDevMode (LSPosed module).
**Role:** system_server Binder-level spoof of `Settings.Global` developer flags so every
app process reads `adb_enabled=0` and `development_settings_enabled=0`, including after
app-process restarts and across cached Binder proxies. `resetprop`
(`device_cloaking/apply_stealth_props.sh`, Layer A) covers the kernel/property layer;
HideDevMode covers the `system_server` SettingsProvider layer. Both are required for
the full dbug stealth posture; neither alone is sufficient.

This document contains procedures only. No APKs, binaries, or package artifacts are
committed to this repository (AGENTS.md ground rule).

---

## 1. Prerequisites (device)

- Rooted physical Android test device (Android 12-14, ARM64), dedicated lab hardware only.
- Magisk / KernelSU / APatch with `resetprop` available on the device.
- LSPosed framework installed and active (Zygisk/LSPosed runtime).
- ADB access from the host workstation (`adb devices` lists the device).
- Device operates only on the isolated Wi-Fi gateway (`ap0`); never bridge to production networks.

---

## 2. Install HideDevMode

1. Obtain the HideDevMode release APK from the upstream project releases page
   (https://github.com/dongdevcom/HideDevMode/releases). Verify the download
   out-of-band (e.g., project documentation); dbug does not mirror or hash the APK.
2. Install on the test device:

   ```
   adb install HideDevMode-release.apk
   ```

3. Confirm the package is visible to the shell:

   ```
   adb shell pm path com.dongdevcom.hidedevmode
   ```

   Note: confirm the actual package id from the release APK; update
   `config/lab_config.yaml` `lsposed.hide_dev_mode_package` if it differs.

---

## 3. Enable the Module

1. Open the LSPosed Manager app on the test device.
2. Enable the HideDevMode module.
3. In the module configuration, select the target package(s) under analysis (e.g.
   `com.example.malware`) so the `Settings.Global` hook is applied to those processes.
4. Reboot the device so LSPosed loads the module into `system_server` and the zygote
   namespace for spawned target processes.

---

## 4. Verify (host-side, Gate G1 Layer 6)

Run the pre-flight audit before every dynamic launch:

```
python3 device_cloaking/verify_stealth_state.py --config config/lab_config.yaml
```

Expected Layer 6 output:

```
[*] Layer 6: Auditing LSPosed HideDevMode Module (Developer-Option Hiding)...
  [+] HideDevMode module package 'com.dongdevcom.hidedevmode' installed and enabled (PASS)
      system_server Settings.Global spoof: adb_enabled=0, development_settings_enabled=0
[+] ALL PRE-FLIGHT STEALTH CHECKS PASSED (Gate G1 Clear).
```

If the module is absent or disabled, Layer 6 emits a WARN by default. To make Gate G1
halt when HideDevMode is not active, set in `config/lab_config.yaml`:

```yaml
  telemetry:
    lsposed:
      hide_dev_mode_required: true
```

The orchestrator stops the pipeline on any G1 failure, so no malware is detonated
without the cloaking layer verified.

---

## 5. Remediation

| Condition | Action |
| :--- | :--- |
| `pm path <pkg>` returns nothing | Install the HideDevMode release APK (`adb install`). |
| Package listed under `pm list packages -d` | Enable the module in LSPosed Manager; reboot. |
| Module installed but `adb_enabled` still reads `1` | Confirm module is enabled for the target package in LSPosed Manager; reboot; re-run Layer 6 audit. |
| LSPosed not running | Install LSPosed framework (zygisk) and reboot before HideDevMode can function. |

---

## 6. Post-Run

- After the analysis session, force-stop and uninstall the target package.
- Wipe planted canaries: `python3 config/seed_canaries.py --clean --config config/lab_config.yaml`.
- Do not keep HideDevMode enabled on any device that touches production networks.
