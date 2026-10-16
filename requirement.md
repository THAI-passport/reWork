# requirement.md — Requirements and per-OS install for reWork/dbug

This file lists every component needed to run reWork (and the dbug dynamic-analysis
gates) on Windows, macOS, and Linux/Unix, and how to install each one. It is the
single install reference referenced by README.md, AGENTS.md, and setup_tools.py.

Core reWork tools are Python 3 standard library only and run on all three OSes with
no third-party packages. Third-party downloads (JDK, jadx, apktool, Frida, Android
SDK) happen at install time via tools/setup_tools.py and are never committed to this
repo (AGENTS.md ground rule 3).

No emoji anywhere in this file. Plain ASCII punctuation only.

## 1. What you need

| Component | Purpose | Required for | OS notes |
|---|---|---|---|
| Python 3 (3.10+) | Runs all reWork/dbug tools | Everything | Built-in on macOS/Linux; install on Windows |
| python3-venv | Isolated venv for optional pip deps | setup_tools.py --no-venv skips this | python3-venv package on Debian/Ubuntu |
| JDK 17 (Temurin/Adoptium) | Runs jadx and apktool | Static analysis gates (G0-G2) | Downloaded by setup_tools.py |
| jadx 1.5.6 | DEX -> Java decompiler | Static analysis (re-static) | Downloaded by setup_tools.py |
| apktool 3.0.3 | APK decode/rebuild | Static analysis (re-static) | Downloaded by setup_tools.py |
| pytest | Test runner | python -m unittest works without it; pytest optional | Installed into .venv |
| Android SDK platform-tools (adb) | Talk to a physical device or emulator over USB/TCP | Dynamic gates (G1-G5) and the emulator/AVD launch | Not installed by setup_tools.py; see section 4 |
| Android SDK emulator + an AVD | Headless Android target when no USB device exists | --avd mode in orchestrator.py (opt-in) | Not installed by setup_tools.py; see section 4 |
| tshark / Wireshark | PCAP/pcapng reading and capture | tools/btcap.py, network capture gates (optional) | apt install tshark, brew install wireshark, Wireshark installer |
| PyYAML | YAML lab config parsing | orchestrator/verify fall back to regex without it | pip install pyyaml |
| Frida + frida-tools | Runtime instrumentation (Gate G4) | dbug dynamic analysis (optional; tests skip without it) | pip install; device-side frida-server needs root/jailbreak |
| unicorn, capstone, pyelftools | Native .so emulation and disassembly | Gate G0 native emulation (optional; --emulation) | pip install with build chain |

Mandatory to run anything: Python 3.10+. Everything else is optional but needed for
specific gates; missing optional tools are reported by python tools/rw.py doctor and
tests skip gracefully rather than failing.
## 2. One-command setup (works on Windows, macOS, Linux)

# clone
git clone https://github.com/THAI-passport/reWork.git
cd reWork
git checkout cline/0x0yhj88   # or the branch you are working on

# install JDK 17, jadx, apktool into ~/tools and a .venv with pip deps
python tools/setup_tools.py

# with native emulation extras (unicorn, capstone, pyelftools)
python tools/setup_tools.py --emulation

# skip the venv (use system Python only)
python tools/setup_tools.py --no-venv

# print what would be downloaded for this machine, without downloading
python tools/setup_tools.py --check

# verify what is installed
python tools/rw.py doctor

tools/setup-tools.sh is a thin shell wrapper around tools/setup_tools.py for
Linux/macOS; on Windows run python tools/setup_tools.py from PowerShell or cmd.

setup_tools.py installs into ~/tools (no admin rights) and prints PATH lines to add
to ~/.bashrc / ~/.zshrc (macOS/Linux) or setx (Windows). It is idempotent: safe to
re-run.

## 3. Per-OS install details

### 3.1 Windows (PowerShell or cmd)

Prerequisites:
- Python 3.10+: from https://www.python.org/downloads/ or the Microsoft Store. Check
  python --version and py -3 --version. Enable Add Python to PATH at install.
- JDK 17: setup_tools.py downloads Temurin automatically, or
  winget install EclipseAdoptium.Temurin.17.JRE.
- Git: https://git-scm.com/download/win (Git Bash also works).

Install:
py -3 tools/setup_tools.py        # JDK, jadx, apktool, .venv
py -3 tools/setup_tools.py --emulation

Add to PATH once (printed by setup_tools.py):
setx JAVA_HOME "%HOME%\tools\jdk"
setx PATH "%JAVA_HOME%\bin;%HOME%\tools\jadx\bin;%HOME%\tools\apktool;%PATH%"

Optional:
- tshark: Wireshark installer from https://www.wireshark.org/download.html
- adb + emulator: section 4 (Android SDK platform-tools via winget or Android Studio)

Run checks:
py -3 tools/rw.py doctor
py -3 -m unittest discover -s tests

### 3.2 macOS (Homebrew)

Prerequisites:
- Python 3.10+: brew install python (or python.org installer). Apple Silicon and
  Intel x86_64 both supported by setup_tools.py.
- Homebrew: https://brew.sh/

Install:
brew install python
python3 tools/setup_tools.py      # JDK, jadx, apktool, .venv (~/tools)
python3 tools/setup_tools.py --emulation

setup_tools.py appends PATH to ~/.zshrc (and ~/.bashrc if present). Reload the shell
or run:
export JAVA_HOME="$HOME/tools/jdk"
export PATH="$JAVA_HOME/bin:$HOME/tools/jadx/bin:$HOME/tools/apktool:$PATH"

Optional:
- tshark: brew install wireshark
- adb: brew install android-platform-tools
- emulator + AVD: section 4 (Android Studio command-line tools)

Run checks:
python3 tools/rw.py doctor
python3 -m unittest discover -s tests

### 3.3 Linux / Unix (Debian/Ubuntu, RHEL, generic)

Prerequisites:
- Python 3.10+ and venv: apt install python3 python3-venv (Debian/Ubuntu) or
  equivalent on your distro.
- curl/wget and unzip may be needed by setup_tools.py downloads.

Install:
python3 tools/setup_tools.py      # JDK, jadx, apktool, .venv
python3 tools/setup_tools.py --emulation

setup_tools.py appends PATH to ~/.bashrc. Reload or run:
export JAVA_HOME="$HOME/tools/jdk"
export PATH="$JAVA_HOME/bin:$HOME/tools/jadx/bin:$HOME/tools/apktool:$PATH"

Optional distro packages:
- tshark: apt install tshark (needs root) or dnf install wireshark-cli
- adb: apt install adb (package name android-sdk-platform-tools on some distros)
- emulator + AVD: section 4 (Android Studio command-line tools; needs 64-bit and
  KVM acceleration for speed: apt install cpu-checker qemu-kvm and check kvm-ok)

Run checks:
python3 tools/rw.py doctor
python3 -m unittest discover -s tests

## 4. Android SDK for the emulator / adb-over-TCP feature

The emulator/AVD launch I added (tools/emulator_launch.py, orchestrator.py --avd,
see emulator.md) needs the Android SDK on the host. setup_tools.py does NOT install
this; install it separately per OS.

### 4.1 Install platform-tools and emulator

- Windows: winget install Google.AndroidSdkPlatformTools (adb) and install the
  emulator via Android Studio (SDK Manager -> SDK Tools -> Android Emulator, plus
  Android SDK Command-line Tools).
- macOS: brew install android-platform-tools (adb); emulator via Android Studio
  SDK Manager.
- Linux: apt install adb or download command-line tools from
  https://developer.android.com/studio and run sdkmanager platform-tools emulator.

Add platform-tools and emulator to PATH (or set ANDROID_HOME / ANDROID_SDK_ROOT;
emulator_launch.py finds adb/emulator from either).

### 4.2 Create a rootable AVD

emulator -list-avds
avdmanager create avd -n Pixel_6_API_34 -k "system-images;android-34;google_apis;x86_64"

Use a rootable x86_64/arm64-v8a system image (Android 12-14 recommended). The AVD
must be rootable (Magisk/KernelSU/APatch) for resetprop stealth cloaking to work;
without root, only the Settings.Global layer (hide_dev_options.sh) applies.

## 5. Python pip dependencies (core vs optional extras)

Core reWork tools need zero pip packages. setup_tools.py creates .venv and installs:

- pytest, bleach, pillow - test tooling and media generation
- With --emulation (or --full): unicorn, capstone, pyelftools - native emulation.
  If a wheel is unavailable or the build chain is missing, setup_tools.py reports it
  non-fatally; core and tests still work, emulation tests skip.

requirements.txt additionally pins Frida 17.24.0 / frida-tools 14.11.0, pyelftools,
unicorn, capstone for the dbug dynamic-analysis profile. Install into the venv if you
need Frida-based instrumentation:

.venv/Scripts/activate        # Windows
source .venv/bin/activate     # macOS/Linux
pip install -r requirements.txt

Frida also needs frida-server matching the Frida version, pushed to and run on the
target device (root/jailbreak required). This is device-side only and is never
committed here.

## 6. Verification

After installing, confirm everything is present:

python tools/rw.py doctor          # reports JDK, jadx, apktool, adb, tshark; exits 0
python tools/rw.py lint            # 0 problems expected; fails on artifacts/emoji/secrets
python3 -m unittest discover -s tests   # OK, optional-tool tests skip

rw.py doctor exits 0 even when optional tools are missing; it prints what is
available so you know which gates can run.

## 7. What is intentionally NOT installed

- Target APK / firmware / any vendor artifact: never downloaded by setup tooling;
  provide your own sample via --apk and record its SHA-256 in SOURCES.md.
- Frida server, Magisk, KernelSU, APatch, HideDevMode APK: device-side only; install
  on the rooted test device per the device_cloaking and HideDevMode runbooks.
- Emulator system images / AVD snapshots: create your own with avdmanager / Android
  Studio; never committed (.gitignore blocks .so, .apk, images, etc.).

## 8. Restricted / offline networks

If the host cannot reach github.com or api.adoptium.net (common in cloud sessions),
download JDK/jadx/apktool on an allowed machine, note the SHA-256, set
JADX_SHA256/APKTOOL_SHA256 before running setup_tools.py --check to print the
computed hash, then pin it. The emulator feature additionally needs the Android SDK
mirror reachable or a locally copied platform-tools/emulator directory.

## 9. Minimum working set

To run the full reWork suite on any major OS with zero hardware:

python3           # 3.10+
python tools/setup_tools.py --emulation
python tools/rw.py doctor
python tools/rw.py lint
python3 -m unittest discover -s tests

To also run the emulator/AVD path I added:

# on top of the minimum set
export ANDROID_HOME=$HOME/Android/Sdk   # or where you installed it
export PATH=$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH
emulator -list-avds                     # confirm an AVD exists
python tools/emulator_launch.py launch --avd <AVD_NAME> --tcp-port 5557 --dry-run

The dry-run needs no device and validates the launch + stealth + serial path end to end.

