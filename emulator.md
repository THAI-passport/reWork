# emulator.md — Android Emulator / AVD Launch with adb-over-TCP and Stealth Cloaking

## Purpose

dbug runs dynamic analysis against a physical Android test device by default. Some lab workflows (no USB, headless container, remote host, or a device that must stay off USB) need an Android emulator (AVD) as the analysis target instead.

This document scopes and implements:

1. Launching an AVD from the host (headless).
2. Switching the emulator's adbd to adb-over-TCP and connecting so the pipeline addresses it as a normal `host:port` serial.
3. Applying stealth cloaking so malware/RASP cannot detect it is running in an emulator under analysis.
4. Handing the resulting TCP serial to the dbug pipeline (Gate G1 onwards) and tearing the emulator down afterward.

No APK, system image, emulator snapshot, or vendor artifact is committed here (AGENTS.md ground rule 3).

## Scope

In scope:

- `tools/emulator_launch.py` — host-side launcher (Python 3 stdlib only, dry-run capable).
- `device_cloaking/apply_emulator_stealth.sh` — device-side `resetprop` cloaking of emulator indicators.
- Opt-in `--avd` integration in `orchestrator.py` (only active when `--avd` is given; default USB behavior unchanged).
- Dry-run mode that simulates every step without `adb`, `emulator`, an AVD, or a device.

Out of scope:

- Downloading or building Android SDK platform-tools, emulator system images, or AVD definitions. The analyst provides these.
- Rooting the emulator or installing Magisk/KernelSU/APatch (`resetprop` requires root; the AVD must be rootable).
- Any contact with vendor servers beyond downloading the public SDK artifact.

## Prerequisites

- Android SDK platform-tools (`adb`) and emulator (`emulator`) on `PATH` or under `$ANDROID_HOME`/`$ANDROID_SDK_ROOT`.
- An existing AVD (`emulator -list-avds` lists it). Use a rootable x86_64/arm64-v8a system image (Android 12-14 recommended).
- The lab device reaches the isolated Wi-Fi gateway only; never bridge emulator traffic to production networks.
- `verify_stealth_state.py`, `hide_dev_options.sh`, `apply_stealth_props.sh` already present (`device_cloaking/`).

## Architecture

```
host                                          emulator (AVD)
----                                          ------------
emulator_launch.py  --launch-->  emulator -avd <avd> -port 5554 -no-window ...
                                                  |
                                                  | wait: sys.boot_completed == 1
                                                  v
                                    adb -s emulator-5554 tcpip 5557   (adbd listens on TCP 5557)
                                                  |
                                    adb connect 127.0.0.1:5557        (host serial: 127.0.0.1:5557)
                                                  |
                                                  | push + run device_cloaking scripts
                                                  |   apply_stealth_props.sh apply   (Layer A)
                                                  |   apply_emulator_stealth.sh apply (Layer C)
                                                  |   hide_dev_options.sh apply     (Layer B)
                                                  v
                                    verify_stealth_state.py --serial 127.0.0.1:5557  (Gate G1)
                                                  |
                                                  |  tcp serial handed to orchestrator
                                                  v
                                     dbug stages G1 .. G5 run against the emulator
                                                  |
                                                  v (teardown)
                                     emulator_launch.py stop   (adb emu kill)
                                     (unless --keep-emulator)
```

The TCP serial (`127.0.0.1:5557`) is what `self.serial` becomes in `orchestrator.py`, so every later stage (`--serial`) addresses the emulator exactly like a USB device. No USB cable is required.

## Stealth model (hold up debugging without being detected)

Android malware and commercial RASP engines probe for emulators. If they confirm an emulator they may halt, wipe, or serve decoy traffic. The cloaking below is applied before the target launches, mirroring the two-layer model in `apply_stealth_props.sh` (Layer A: kernel/property) and `hide_dev_options.sh` (Layer B: Settings.Global via LSPosed HideDevMode). This feature adds Layer C: emulator-indicator masking.

| # | Anti-emulator check | Bypass applied by this feature | Evidence |
|---|---------------------|-------------------------------|----------|
| AND-009 | `ro.kernel.qemu == 1` | `resetprop ro.kernel.qemu 0` (best effort; read-only on some images) | [I] |
| AND-010 | `ro.product.model/device/name` contains "sdk"/"google_sdk"/"emulator" | `resetprop` to a non-emulator model (e.g. Pixel) | [I] |
| AND-011 | `ro.hardware == "goldfish"` / "ranchu" | `resetprop ro.hardware` to a device value | [I] |
| AND-012 | `ro.build.fingerprint` / `ro.build.description` contains "generic"/"sdk"/"google" | `resetprop` build fingerprint to a release build | [I] |
| AND-013 | `ro.product.board`/`brand`/`manufacturer`, `ro.serialno` | `resetprop` each to production values | [I] |
| AND-014 | `ro.emulator == 1` or `qemu.*` properties present | `resetprop ro.emulator 0` | [I] |
| AND-015 | `ro.debuggable == 1` / `Settings.Global.adb_enabled == 1` | `apply_stealth_props.sh` + `hide_dev_options.sh` (Layers A+B) | [C] |
| AND-016 | adb on default TCP port 5555 scanned | adb-over-TCP on a non-default port (`--tcp-port`, default 5557) | [I] |
| AND-017 | `/proc/cpuinfo` reports x86/"GenuineIntel" on an ARM target | requires custom AVD image / CPU; documented as a hard limit | [I] |
| AND-018 | Telephony `PHONE_TYPE_NONE`, absent sensors | not mitigated here; documented as a detectable emulator trait | [I] |

Properties marked best-effort: `resetprop` can override init-space properties at runtime, but read-only props baked into the system image/ramdisk may revert or be invisible to some readers. Where `resetprop` cannot reach a property, the fix is a custom AVD system image with `build.prop`/`default.prop` edited, or emulator property overrides at launch. No bypass is claimed as undetectable — every dynamic claim above is `[I]` until verified on a real AVD against a real sample.

`ro.kernel.qemu` and `ro.hardware` are set by the kernel/init at boot and are the hardest to mask from inside a booted emulator; prefer a pre-cloaked AVD image over runtime `resetprop` for those two.

## Integration with dbug gates

- Gate G1 (pre-flight stealth audit): `verify_stealth_state.py --serial <tcp>` runs against the emulator after cloaking; the pipeline halts on failure, so no sample is detonated unless cloaking verifies.
- Gate G3 (capture): eCapture/Frida run against `--serial <tcp>` exactly as on USB.
- Teardown: `sanitize_device_state.py --serial <tcp>` runs Tiers 1-6 against the emulator, then the emulator is stopped unless `--keep-emulator`.

## lab_config.yaml additions

```yaml
  device:
    serial: ""              # filled by emulator_launch launch (tcp serial)
    connection_type: "tcpip"  # usb | tcpip
    emulator:
      avd: ""               # AVD name; empty = physical USB device
      tcp_port: 5557        # adb-over-TCP port (non-default, stealth)
      emulator_port: 5554   # emulator base port (adb is base+1)
      keep_emulator: false  # stop the AVD after the run
```

## Usage

```
# List available AVDs
python tools/emulator_launch.py list-avds

# Dry-run: simulate launch + cloaking, print the would-be tcp serial
python tools/emulator_launch.py launch --avd Pixel_6_API_34 --tcp-port 5557 --dry-run

# Real launch (requires adb/emulator and a rootable AVD)
python tools/emulator_launch.py launch --avd Pixel_6_API_34 --tcp-port 5557

# Verify stealth state against a running emulator
python tools/emulator_launch.py verify --serial 127.0.0.1:5557

# Stop the emulator
python tools/emulator_launch.py stop --serial 127.0.0.1:5557
```

Orchestrator integration (opt-in, only when `--avd` is passed):

```
python orchestrator.py --apk samples/sample.apk --package com.example.malware \
    --avd Pixel_6_API_34 --emulator-tcp-port 5557 --dry-run
```

When `--avd` is given, the orchestrator launches the AVD, switches adbd to adb-over-TCP, applies stealth cloaking, verifies (Gate G1), runs the full pipeline against the tcp serial, then stops the emulator unless `--keep-emulator`. Without `--avd`, behavior is unchanged (physical USB device via `serial` from `lab_config.yaml`).

## Evidence tags

- `[C]` confirmed in existing `device_cloaking` code (resetprop + Settings.Global layers).
- `[V]` dry-run behavior verified by `tests/test_emulator_launch.py` (no device required).
- `[I]` inferred anti-emulator bypass; not hardware-verified. Treat as best-effort.
- `[U]` custom-AVD-image requirement for read-only boot props.

## Anti-patterns

- **NEVER** launch the emulator with the default adb port 5555 and leave it; RASP scans for default-port patterns. Use `--tcp-port` on a high, non-default port.
- **NEVER** skip Gate G1 verification on an emulator; emulator `ro.debuggable` is `1` by default on many system images and must be masked first.
- **NEVER** commit the AVD system image, `userdata-qemu.img`, or any emulator snapshot to this repo (ground rule 3).
- **NEVER** bridge the emulator's network to production; route through the isolated gateway only.

## Cloud / headless instances (no KVM)

Most cloud Linux instances do not expose `/dev/kvm` and lack nested
virtualization. Without KVM the Android emulator cannot use hardware
acceleration and boots extremely slowly (or not at all) with default flags.
This launcher handles that gracefully:

- `kvm_available()` detects `/dev/kvm`. When it is absent, `no_kvm` is set
  automatically and the launch command adds `-no-accel` plus `-gpu off`
  (software rendering), with a longer default boot timeout (600 s).
- Pass `--no-kvm` explicitly to force the software-rendering path.
- The emulator runs headless by default (`-no-window -no-audio`) and forces
  headless when `DISPLAY` is unset, which is the norm on cloud/container
  hosts.
- Use `python tools/emulator_launch.py doctor` to check whether `adb`,
  `emulator`, and KVM are present, and to get per-OS install hints.
- `python tools/rw.py doctor` also reports KVM and `emulator` status.

Realistic expectation: on a cloud instance without KVM/nested virtualization,
emulator boot is slow and some graphics-dependent apps may not run correctly.
For a dependable Android-analysis target on the cloud, use an instance type
that exposes KVM (nested virtualization enabled) or attach a real Android
device over adb-over-TCP instead. The dry-run mode (`--dry-run`) validates
the entire launch + stealth + serial path with no Android tooling at all.

## Open questions / what only hardware settles

- Whether `resetprop` reliably masks `ro.kernel.qemu` and `ro.hardware` on the target AVD image version (test on the real AVD before the first malware run; mark `[V]` or `[H]` there).
- Whether the target sample detects the emulator via `Build.FINGERPRINT`, telephony `PHONE_TYPE_NONE`, or absent sensors after cloaking (only a real sample run can confirm).
- Whether the emulator's adbd binds `tcpip` to all interfaces so `127.0.0.1:<port>` connects from the host in this lab's network namespace.
