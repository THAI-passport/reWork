#!/usr/bin/env python3
"""emulator_launch.py: Launch an Android AVD over adb-over-TCP with stealth cloaking.

Starts a headless AVD, waits for boot completion, switches adbd to adb-over-TCP
(on a non-default port), connects the host, applies the device_cloaking stealth
layers (resetprop properties + Settings.Global developer-option hiding),
verifies the stealth state, and prints the resulting TCP serial for the dbug
pipeline to consume. A --stop / --restore mode tears an emulator down or
reverts cloaking.

All steps are simulatable with --dry-run (no adb, emulator, AVD, or device
required). Every dynamic stealth claim is best-effort [I]; read-only boot
properties need a pre-cloaked AVD image. See emulator.md for the full spec.
"""

import argparse
import io
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time

DEFAULT_TCP_PORT = 5557
DEFAULT_EMULATOR_PORT = 5554
BOOT_TIMEOUT = 300
BOOT_POLL = 3

DEFAULT_SOFT_BOOT_TIMEOUT = 600


def kvm_available():
    """Return True if KVM acceleration is available (readable /dev/kvm on Linux).

    On Windows/macOS there is no /dev/kvm; those platforms use WHPX /
    Hypervisor.framework and are assumed capable unless --no-kvm is passed.
    Most cloud Linux instances do NOT expose /dev/kvm, so emulator boot
    without KVM relies on software rendering and is slow.
    """
    try:
        return os.access("/dev/kvm", os.R_OK | os.W_OK)
    except OSError:
        return False


def android_home():
    """Return the first of ANDROID_HOME / ANDROID_SDK_ROOT that is set, or ''."""
    return os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or ""


def android_tool_hint(name):
    """Per-OS hint for installing a missing Android SDK tool."""
    hints = {
        "linux": "sudo apt install android-sdk-platform-tools (adb) and install "
                 "the emulator via Android Studio SDK Manager, or set ANDROID_HOME "
                 "to a manually downloaded cmdline-tools + platform-tools + emulator",
        "mac": "brew install android-platform-tools (adb); install the emulator via "
               "Android Studio SDK Manager, or set ANDROID_HOME to a manually "
               "downloaded cmdline-tools directory",
        "windows": "winget install Google.AndroidSdkPlatformTools (adb); install the "
                   "emulator via Android Studio SDK Manager",
    }
    s, _ = ("linux", "x64")  # placeholder; real host detected in caller
    return hints.get("linux", "install Android SDK platform-tools + emulator")
TCP_SERIAL_RX = re.compile(r"^SERIAL:\s*(\S+)\s*$", re.MULTILINE)

DEVICE_CLOAKING = "device_cloaking"
HIDE_DEV_SCRIPT = os.path.join(DEVICE_CLOAKING, "hide_dev_options.sh")
STEALTH_PROPS_SCRIPT = os.path.join(DEVICE_CLOAKING, "apply_stealth_props.sh")
EMULATOR_STEALTH_SCRIPT = os.path.join(DEVICE_CLOAKING, "apply_emulator_stealth.sh")
VERIFY_SCRIPT = os.path.join(DEVICE_CLOAKING, "verify_stealth_state.py")


class EmulatorLauncherError(Exception):
    """Fatal launcher error (non-zero exit)."""


def find_tool(name):
    """Locate an Android SDK tool (emulator/adb) from ANDROID_HOME* or PATH."""
    for root in (os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT")):
        if not root:
            continue
        for sub in ("platform-tools", "emulator", ""):
            for cand in (os.path.join(root, sub, name),
                         os.path.join(root, sub, name + ".exe")):
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    return cand
    probe = name + ".exe" if os.name == "nt" else name
    return shutil.which(probe) or shutil.which(name)


def which_adb():
    return find_tool("adb")


def which_emulator():
    return find_tool("emulator")


def adb_base(serial):
    base = ["adb"]
    if serial:
        base.extend(["-s", serial])
    return base


def run(cmd, dry_run=False, check=False, capture=True, timeout=None):
    """Run a command, or print what would be run in dry-run mode."""
    cmd_str = " ".join(shlex.quote(str(c)) for c in cmd)
    if dry_run:
        print("[DRY-RUN] %s" % cmd_str)
        return 0, ""
    print("[*] %s" % cmd_str)
    try:
        proc = subprocess.run(cmd, capture_output=capture, text=True,
                              timeout=timeout, check=False)
    except FileNotFoundError:
        raise EmulatorLauncherError("tool not found: %s" % cmd[0])
    except subprocess.TimeoutExpired:
        raise EmulatorLauncherError("command timed out: %s" % cmd_str)
    if capture:
        return proc.returncode, proc.stdout
    return proc.returncode, None


def run_checked(cmd, dry_run=False, timeout=None, label="command"):
    code, out = run(cmd, dry_run=dry_run, capture=True, timeout=timeout)
    if code != 0:
        raise EmulatorLauncherError("%s failed (exit %d): %s" % (label, code, out.strip()[:500]))
    return out


class EmulatorLauncher(object):
    def __init__(self, avd=None, serial=None, tcp_port=DEFAULT_TCP_PORT,
                 emulator_port=DEFAULT_EMULATOR_PORT, dry_run=False,
                 adb=None, emulator=None, headless=True, gpu="off",
                 audio="no", no_snapshot=True, wipe_data=False,
                 apply_stealth=True, keep_emulator=False, boot_timeout=None,
                 no_kvm=False, auto_headless=True):
        self.avd = avd
        self.serial = serial
        self.tcp_port = int(tcp_port)
        self.emulator_port = int(emulator_port)
        self.emulator_serial = "emulator-%d" % self.emulator_port
        self.dry_run = dry_run
        self.headless = headless
        self.gpu = gpu
        self.adb = adb or which_adb()
        self.emulator_bin = emulator or which_emulator()
        self.android_home = android_home()
        self.kvm = kvm_available()
        # Cloud/Linux instances rarely expose /dev/kvm; fall back to software
        # rendering with a longer boot timeout unless the user explicitly opts out.
        self.no_kvm = bool(no_kvm) or (not self.kvm and not self.dry_run)
        # Auto headless when there is no display (typical cloud/container).
        if auto_headless and self.headless and "DISPLAY" not in os.environ:
            self.headless = True
        if self.headless and not self.gpu:
            self.gpu = "off"
        self.audio = audio
        self.no_snapshot = no_snapshot
        self.wipe_data = wipe_data
        self.stealth_enabled = apply_stealth
        self.keep_emulator = keep_emulator
        if boot_timeout is None:
            boot_timeout = DEFAULT_SOFT_BOOT_TIMEOUT if self.no_kvm else BOOT_TIMEOUT
        self.boot_timeout = int(boot_timeout)
        self.proc = None
        self.tcp_serial = None

    # -- discovery ---------------------------------------------------
    def list_avds(self):
        """Print available AVD names (dry-run prints an example list)."""
        if self.dry_run:
            print("[DRY-RUN] emulator -list-avds (simulated)")
            print("Pixel_6_API_34")
            print("Pixel_7_API_33")
            return 0
        if not self.emulator_bin:
            raise EmulatorLauncherError("emulator not found (set ANDROID_HOME or add to PATH)")
        code, out = run([self.emulator_bin, "-list-avds"], dry_run=False, capture=True)
        for line in out.splitlines():
            line = line.strip()
            if line:
                print(line)
        return code

    def avd_exists(self, name):
        if self.dry_run:
            return True
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        found = []
        try:
            self.list_avds()
        finally:
            sys.stdout = old_stdout
        for line in buf.getvalue().splitlines():
            line = line.strip()
            if line:
                found.append(line)
        return name in found

    # -- launch -------------------------------------------------------
    def _emulator_cmd(self):
        """Build the headless emulator launch command line.

        Cloud/Linux instances without /dev/kvm cannot use hardware
        acceleration, so software rendering (-gpu swiftshader_indirect) and
        no acceleration flags keep the emulator bootable headlessly.
        """
        bin_ = self.emulator_bin or "emulator"
        cmd = [bin_, "-avd", self.avd, "-port", str(self.emulator_port)]
        if self.headless:
            cmd.extend(["-no-window", "-no-audio"])
        if self.gpu:
            cmd.extend(["-gpu", self.gpu])
        if self.no_kvm:
            # Software rendering; disable hardware acceleration features that
            # require KVM / a host GPU on headless cloud instances.
            cmd.append("-no-accel")
        if self.no_snapshot:
            cmd.append("-no-snapshot")
        if self.wipe_data:
            cmd.append("-wipe-data")
        return cmd

    def _push_device_script(self, local_path, remote_name):
        """Push a device_cloaking script to /data/local/tmp and make it executable."""
        remote = "/data/local/tmp/%s" % remote_name
        run_checked(self.adb_base(self.serial) + ["push", local_path, remote],
                    dry_run=self.dry_run, label="push %s" % local_path)
        run_checked(self.adb_base(self.serial) + ["shell", "chmod", "755", remote],
                    dry_run=self.dry_run, label="chmod %s" % remote)
        return remote

    def _shell_root(self, inner_cmd):
        """Run inner_cmd on the device via `su -c`, routed to self.serial."""
        quoted = " ".join(shlex.quote(a) for a in inner_cmd)
        return self.adb_base(self.serial) + ["shell", "su", "-c", quoted]

    def wait_boot(self):
        """Wait until sys.boot_completed reads "1" (dry-run returns immediately)."""
        if self.dry_run:
            print("[DRY-RUN] waiting for sys.boot_completed (simulated: ok)")
            return True
        deadline = time.time() + self.boot_timeout
        while time.time() < deadline:
            code, out = run(self.adb_base(self.emulator_serial) +
                            ["shell", "getprop", "sys.boot_completed"],
                            dry_run=False, capture=True, timeout=10)
            if out.strip() == "1":
                print("[+] Emulator booted (sys.boot_completed == 1)")
                return True
            time.sleep(BOOT_POLL)
        raise EmulatorLauncherError("emulator did not finish booting within %d s" % self.boot_timeout)

    def tcpip_connect(self):
        """Switch adbd to adb-over-TCP and return the host-side tcp serial."""
        if self.dry_run:
            self.tcp_serial = "127.0.0.1:%d" % self.tcp_port
            print("[DRY-RUN] adb -s %s tcpip %d (simulated)" % (self.emulator_serial, self.tcp_port))
            print("[DRY-RUN] adb connect 127.0.0.1:%d (simulated)" % self.tcp_port)
            print("SERIAL: %s" % self.tcp_serial)
            return self.tcp_serial
        run_checked(self.adb_base(self.emulator_serial) + ["tcpip", str(self.tcp_port)],
                    dry_run=False, label="adb tcpip %d" % self.tcp_port, timeout=30)
        # Clear any prior connection, then connect over TCP.
        run(self.adb_base(None) + ["disconnect"], dry_run=False, capture=True, timeout=15)
        run_checked(self.adb_base(None) + ["connect", "127.0.0.1:%d" % self.tcp_port],
                    dry_run=False, label="adb connect 127.0.0.1:%d" % self.tcp_port, timeout=30)
        self.tcp_serial = "127.0.0.1:%d" % self.tcp_port
        print("[+] adb-over-TCP established at %s" % self.tcp_serial)
        print("SERIAL: %s" % self.tcp_serial)
        return self.tcp_serial

    def apply_stealth(self, serial):
        """Apply all three stealth layers against a running device/emulator."""
        if not self.stealth_enabled:
            print("[*] Stealth cloaking disabled (--no-stealth).")
            return
        if self.dry_run:
            print("[DRY-RUN] would push and apply stealth layers to %s" % serial)
            print("[DRY-RUN]   %s apply" % STEALTH_PROPS_SCRIPT)
            print("[DRY-RUN]   %s apply" % EMULATOR_STEALTH_SCRIPT)
            print("[DRY-RUN]   %s apply" % HIDE_DEV_SCRIPT)
            print("[+] Stealth cloaking simulated on %s" % serial)
            return
        # Layer A: kernel/property masking (resetprop).
        self._push_device_script(STEALTH_PROPS_SCRIPT, "apply_stealth_props.sh")
        run_checked(self._shell_root(["sh", "/data/local/tmp/apply_stealth_props.sh", "apply"]),
                    dry_run=False, label="apply_stealth_props.sh apply", timeout=60)
        # Layer C: emulator-indicator masking (resetprop).
        self._push_device_script(EMULATOR_STEALTH_SCRIPT, "apply_emulator_stealth.sh")
        run_checked(self._shell_root(["sh", "/data/local/tmp/apply_emulator_stealth.sh", "apply"]),
                    dry_run=False, label="apply_emulator_stealth.sh apply", timeout=60)
        # Layer B: Settings.Global developer-option hiding.
        self._push_device_script(HIDE_DEV_SCRIPT, "hide_dev_options.sh")
        run_checked(self._shell_root(["sh", "/data/local/tmp/hide_dev_options.sh", "apply"]),
                    dry_run=False, label="hide_dev_options.sh apply", timeout=60)
        print("[+] Stealth layers applied on %s" % serial)

    def verify(self, serial):
        """Verify stealth state against a running device/emulator (Gate G1 audit)."""
        if self.dry_run:
            print("[DRY-RUN] verify_stealth_state.py --serial %s (simulated: pass)" % serial)
            print("[+] Stealth verification simulated on %s" % serial)
            return True
        if not os.path.exists(VERIFY_SCRIPT):
            raise EmulatorLauncherError("verify_stealth_state.py not found at %s" % VERIFY_SCRIPT)
        code, out = run([sys.executable, VERIFY_SCRIPT, "--config", "config/lab_config.yaml",
                         "--serial", serial, "--no-dev-hide"],
                        dry_run=False, capture=True, timeout=120)
        print(out, end="")
        ok = code == 0
        print("[+] Stealth verification %s on %s" % ("passed" if ok else "FAILED", serial))
        return ok

    def stop(self, serial=None):
        """Stop a running emulator (kill the emulator process or adb emu kill)."""
        serial = serial or self.serial or self.tcp_serial or self.emulator_serial
        if self.dry_run:
            print("[DRY-RUN] stop emulator %s (simulated)" % serial)
            return 0
        if self.proc is not None:
            print("[*] Terminating emulator process (pid %d)..." % self.proc.pid)
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None
            print("[+] Emulator process stopped.")
            return 0
        # Fallback: ask adb to kill the emulator instance.
        for target in (serial, self.emulator_serial):
            if not target:
                continue
            run(self.adb_base(target) + ["emu", "kill"], dry_run=False, capture=True, timeout=20)
        print("[+] Emulator stop requested for %s." % serial)
        return 0

    def restore(self, serial=None):
        """Revert stealth properties to developer defaults on a device/emulator."""
        serial = serial or self.serial or self.tcp_serial or self.emulator_serial
        if self.dry_run:
            print("[DRY-RUN] would restore stealth properties on %s (simulated)" % serial)
            return 0
        for script in (STEALTH_PROPS_SCRIPT, EMULATOR_STEALTH_SCRIPT, HIDE_DEV_SCRIPT):
            self._push_device_script(script, os.path.basename(script))
            run_checked(self._shell_root(["sh", "/data/local/tmp/" + os.path.basename(script), "restore"]),
                        dry_run=False, label="%s restore" % os.path.basename(script), timeout=60)
        print("[+] Stealth properties restored on %s" % serial)

    def launch(self):
        """Full launch sequence: start AVD, boot, tcpip, stealth, verify, print SERIAL."""
        if self.dry_run:
            print("[DRY-RUN] emulator launch sequence (simulated):")
            if self.avd:
                print("[DRY-RUN]   %s" % " ".join(self._emulator_cmd()))
            else:
                print("[DRY-RUN]   (no --avd given)")
            self.wait_boot()
            self.tcpip_connect()
            self.apply_stealth(self.tcp_serial)
            self.verify(self.tcp_serial)
            print("[+] Dry-run launch complete; serial %s" % self.tcp_serial)
            return 0

        if not self.avd:
            raise EmulatorLauncherError("--avd is required to launch an emulator")
        if not self.emulator_bin:
            raise EmulatorLauncherError("emulator not found (set ANDROID_HOME or add to PATH)")
        if not which_adb():
            raise EmulatorLauncherError("adb not found (set ANDROID_HOME or add to PATH)")
        if not self.avd_exists(self.avd):
            raise EmulatorLauncherError("AVD not found: %s (run `emulator -list-avds`)" % self.avd)

        print("[*] Launching AVD %s (emulator port %d)..." % (self.avd, self.emulator_port))
        print("    ANDROID_HOME: %s" % (self.android_home or "(not set)"))
        print("    KVM available: %s" % ("yes" if self.kvm else "no"))
        if self.no_kvm:
            print("    [warning] no KVM / host GPU detected; using software rendering "
                  "(-gpu off, -no-accel). Boot will be slow on cloud instances "
                  "without nested virtualization.")
        print("    launch command: %s" % " ".join(self._emulator_cmd()))
        self.proc = subprocess.Popen(self._emulator_cmd())
        try:
            self.wait_boot()
            self.tcpip_connect()
            if self.stealth_enabled:
                self.apply_stealth(self.tcp_serial)
                if not self.verify(self.tcp_serial):
                    raise EmulatorLauncherError("Gate G1 stealth verification failed on %s" % self.tcp_serial)
            print("[+] Launch complete. Emulator serial: %s" % self.tcp_serial)
        except Exception:
            # On failure, tear down the emulator we started so nothing lingers.
            self.stop()
            raise
        return 0


def _common_opts():
    c = argparse.ArgumentParser(add_help=False)
    c.add_argument("--dry-run", action="store_true",
                   help="Simulate every step without adb/emulator/AVD/device")
    c.add_argument("--adb", default=None, help="Path to adb binary (default: ANDROID_HOME/PATH)")
    c.add_argument("--emulator-bin", default=None,
                   help="Path to emulator binary (default: ANDROID_HOME/PATH)")
    c.add_argument("--tcp-port", type=int, default=DEFAULT_TCP_PORT,
                   help="adb-over-TCP port (non-default, stealth; default %d)" % DEFAULT_TCP_PORT)
    c.add_argument("--emulator-port", type=int, default=DEFAULT_EMULATOR_PORT,
                   help="emulator base port (default %d)" % DEFAULT_EMULATOR_PORT)
    c.add_argument("--no-stealth", action="store_true",
                   help="Skip stealth cloaking (not recommended for analysis)")
    c.add_argument("--keep-emulator", action="store_true",
                   help="Leave the emulator running after the pipeline (stop by default)")
    c.add_argument("--no-window", action="store_true", default=True,
                   help="Run headless (default on)")
    c.add_argument("--window", action="store_false", dest="no_window",
                   help="Show the emulator window")
    c.add_argument("--gpu", default="off", help="GPU mode for the emulator (default off)")
    c.add_argument("--audio", default="no", help="audio on/off (default no)")
    c.add_argument("--no-snapshot", action="store_true", default=True, help="Disable snapshot (default on)")
    c.add_argument("--snapshot", action="store_false", dest="no_snapshot", help="Enable snapshot")
    c.add_argument("--wipe-data", action="store_true", help="Wipe AVD data on launch")
    c.add_argument("--boot-timeout", type=int, default=None,
                   help="Boot wait timeout in seconds (default %d normally, %d "
                   "without KVM)" % (BOOT_TIMEOUT, DEFAULT_SOFT_BOOT_TIMEOUT))
    c.add_argument("--no-kvm", action="store_true",
                   help="Force software rendering (for cloud/headless hosts "
                   "without KVM / nested virtualization)")
    return c


def emulator_doctor(dry_run=False, adb=None, emulator_bin=None):
    """Check emulator/adb readiness and print per-OS install hints.

    Returns 0 when adb and emulator are found, 1 otherwise. In dry-run mode
    prints what would be checked without requiring any Android tooling.
    """
    sysname = platform.system()
    adb_path = adb or which_adb()
    emu_path = emulator_bin or which_emulator()
    print("=" * 65)
    print("emulator_launch doctor: Android SDK / emulator readiness")
    print("=" * 65)
    print("Host OS:        %s %s (%s)" % (sysname, platform.release(), platform.machine()))
    print("ANDROID_HOME:   %s" % (android_home() or "(not set)"))
    print("KVM available:  %s" % ("yes" if kvm_available() else "no"))
    if dry_run:
        print("[DRY-RUN] would check adb and emulator binaries")
        print("[DRY-RUN] adb:      would-resolve-from-PATH/ANDROID_HOME")
        print("[DRY-RUN] emulator: would-resolve-from-PATH/ANDROID_HOME")
        print("[DRY-RUN] AVDs:     (simulated) Pixel_6_API_34, Pixel_7_API_33")
        print("[+] Dry-run doctor complete (no Android tooling required)")
        return 0

    missing = []
    print("-" * 65)
    if adb_path:
        print("adb:            FOUND %s" % adb_path)
    else:
        print("adb:            MISSING")
        missing.append("adb")
    if emu_path:
        print("emulator:       FOUND %s" % emu_path)
    else:
        print("emulator:       MISSING")
        missing.append("emulator")
    if not kvm_available() and sysname == "Linux":
        print("KVM:            NOT AVAILABLE (software rendering will be used; "
              "boot is slow without nested virtualization)")
    else:
        print("KVM:            available (or non-Linux host)")
    print("-" * 65)
    if missing:
        print("Missing Android SDK tools: %s" % ", ".join(missing))
        print()
        print("Install per OS:")
        print("  Linux : sudo apt install android-sdk-platform-tools  (adb)")
        print("          emulator: Android Studio SDK Manager -> SDK Tools ->")
        print("          Android Emulator, Android SDK Command-line Tools")
        print("  macOS : brew install android-platform-tools  (adb)")
        print("          emulator: Android Studio SDK Manager")
        print("  Windows: winget install Google.AndroidSdkPlatformTools (adb)")
        print("          emulator: Android Studio SDK Manager")
        print()
        print("Then create a rootable AVD, e.g.:")
        print('  avdmanager create avd -n Pixel_6_API_34 -k '
              '"system-images;android-34;google_apis;x86_64"')
        print("  emulator -list-avds")
        print()
        print("Or run the launcher in dry-run mode to validate without a device:")
        print("  python tools/emulator_launch.py launch --avd Pixel_6_API_34 --dry-run")
        return 1
    print("[+] adb and emulator found; emulator/AVD path is ready to use.")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        description="Launch an Android AVD over adb-over-TCP with stealth cloaking, "
                    "and hand the TCP serial to the dbug pipeline. See emulator.md.")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = _common_opts()

    sp = sub.add_parser("launch", parents=[common],
                        help="Launch an AVD, enable adb-over-TCP, cloak, verify, print SERIAL")
    sp.add_argument("--avd", default=None, help="AVD name to launch (required unless --dry-run)")

    sp = sub.add_parser("stop", parents=[common], help="Stop a running emulator")
    sp.add_argument("--serial", default=None, help="adb serial (host:port or emulator-NNNN)")
    sp.add_argument("--avd", default=None, help="AVD name (derives serial as emulator-<port>)")

    sp = sub.add_parser("status", parents=[common], help="Print boot/connectivity status for a serial")
    sp.add_argument("--serial", default=None, help="adb serial (required)")

    sp = sub.add_parser("verify", parents=[common], help="Verify stealth state against a running serial")
    sp.add_argument("--serial", default=None, help="adb serial (required)")

    sp = sub.add_parser("restore", parents=[common], help="Revert stealth properties to developer defaults")
    sp.add_argument("--serial", default=None, help="adb serial")

    sp = sub.add_parser("list-avds", parents=[common], help="List available AVD names")

    sp = sub.add_parser("doctor", parents=[common], help="Check emulator/adb readiness "
                   "and print per-OS install hints")
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    launch_kwargs = dict(
        dry_run=args.dry_run,
        adb=args.adb,
        emulator=args.emulator_bin,
        tcp_port=args.tcp_port,
        emulator_port=args.emulator_port,
        apply_stealth=not args.no_stealth,
        keep_emulator=args.keep_emulator,
        headless=args.no_window,
        gpu=args.gpu,
        audio=args.audio,
        no_snapshot=args.no_snapshot,
        wipe_data=args.wipe_data,
        boot_timeout=args.boot_timeout,
        no_kvm=args.no_kvm,
    )

    if args.cmd == "list-avds":
        launcher = EmulatorLauncher(dry_run=args.dry_run, emulator=args.emulator_bin,
                                    adb=args.adb)
        return launcher.list_avds()

    if args.cmd == "doctor":
        return emulator_doctor(dry_run=args.dry_run, adb=args.adb,
                               emulator_bin=args.emulator_bin)

    if args.cmd == "launch":
        launcher = EmulatorLauncher(avd=args.avd, **launch_kwargs)
        return launcher.launch()

    serial = args.serial
    if serial is None and args.avd:
        serial = "emulator-%d" % args.emulator_port
    if args.cmd in ("stop", "verify", "restore") and serial is None:
        parser.error("%s requires --serial or --avd" % args.cmd)
    if args.cmd == "status" and serial is None:
        parser.error("status requires --serial")

    launcher = EmulatorLauncher(serial=serial, **launch_kwargs)
    if args.cmd == "stop":
        return launcher.stop(serial)
    if args.cmd == "status":
        code, out = run(adb_base(serial) + ["shell", "getprop", "sys.boot_completed"],
                        dry_run=args.dry_run, capture=True, timeout=15)
        print(out.strip())
        return 0 if args.dry_run or code == 0 else 1
    if args.cmd == "verify":
        ok = launcher.verify(serial)
        return 0 if ok else 1
    if args.cmd == "restore":
        launcher.restore(serial)
        return 0
    parser.error("unknown command: %s" % args.cmd)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except EmulatorLauncherError as exc:
        print("[!] %s" % exc, file=sys.stderr)
        sys.exit(1)

