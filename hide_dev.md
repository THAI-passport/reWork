# hide_dev.md — Hiding Android Developer Options for Stealth Analysis

## Purpose

Modern Android malware and commercial RASP engines query
`Settings.Global.ADB_ENABLED` and `development_settings_enabled` to detect
analysis environments. If either is `1`, the target may halt execution, wipe
itself, or send decoy traffic.

`apply_stealth_props.sh` masks system properties (`ro.debuggable`, `sys.usb.state`,
etc.) but does **not** touch `Settings.Global`. This document and the companion
script `device_cloaking/hide_dev_options.sh` close that gap by writing
`adb_enabled=0` and `development_settings_enabled=0` at the `system_server`
SettingsProvider level via root (`su -c`).

## Companion Script

`device_cloaking/hide_dev_options.sh`

Modes:

| Mode | Description |
|------|-------------|
| `apply` | Set `adb_enabled=0` and `development_settings_enabled=0` via `settings put global` |
| `status` | Print current values of both settings |
| `verify` | Exit 0 if both are `0`, exit 1 otherwise |
| `restore` | Revert to developer defaults (`adb_enabled=1`, `development_settings_enabled=1`) |

## Usage

```bash
# Apply developer-option hiding (run on the rooted test device via ADB)
adb shell su -c "sh /data/local/tmp/hide_dev_options.sh apply"

# Verify current state
adb shell su -c "sh /data/local/tmp/hide_dev_options.sh status"

# Strict verification (exit code 0 = hidden, 1 = exposed)
adb shell su -c "sh /data/local/tmp/hide_dev_options.sh verify"

# Restore developer defaults after analysis is complete
adb shell su -c "sh /data/local/tmp/hide_dev_options.sh restore"
```

## Integration with dbug Pipeline

The orchestrator calls this during Gate G1 (pre-flight) and during
`--sanitize` teardown:

1. **Gate G1** — `verify_stealth_state.py --apply-dev-hide` applies the hide
   before the target is launched, then audits that both settings read back as `0`.
2. **Sanitize** — `sanitize_device_state.py` Tier 2 clears proxy settings and
   ensures developer options remain hidden between analysis runs.

## Evidence Tags

- `[C]` Code / Static — confirmed in `Settings.Global` bytecode references
- `[D]` Dynamic Action — observed `settings put global` taking effect on device
- `[M]` Memory / Hook — Frida `bypass_antidebug.js` also hooks `getInt` in-process
- `[N]` Network Capture — not applicable (device-local setting)

## Anti-Patterns

- **NEVER** rely solely on `resetprop` to hide `adb_enabled` — malware reads
  `Settings.Global` directly, not system properties.
- **NEVER** leave `development_settings_enabled=1` during a stealth run — it
  signals an active developer environment to RASP engines.
- **NEVER** skip this step when switching from Non-Malware Debugging Mode to
  Stealth Malware Mode — standard debugging leaves `adb_enabled=1` exposed.
