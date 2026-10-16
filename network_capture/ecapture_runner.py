#!/usr/bin/env python3
"""ecapture_runner.py: Manages eBPF uprobe TLS plaintext capture and master secret extraction.

Controls the static ARM64 eCapture binary running on the rooted Android physical device.
Hooks Conscrypt's libssl.so at the Linux kernel layer, generating sslkey.log and
decrypted pcapng streams with zero in-process malware memory modifications.
"""

import argparse
import os
import re
import signal
import subprocess
import sys
import time

# Optional PyYAML support with regex fallback
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def parse_lab_config(config_path):
    """Parses lab_config.yaml using PyYAML or regex fallback."""
    if not os.path.exists(config_path):
        return {}

    if HAS_YAML:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"[-] Warning: Failed to parse YAML via PyYAML: {e}", file=sys.stderr)

    config = {"lab_environment": {"device": {}, "network": {}, "telemetry": {"ecapture": {}}}}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
        serial_m = re.search(r'serial:\s*["\']?([^"\'\s#]*)', content)
        if serial_m and serial_m.group(1):
            config["lab_environment"]["device"]["serial"] = serial_m.group(1)
        iface_m = re.search(r'target_interface:\s*["\']?([^"\'\s#]*)', content)
        if iface_m and iface_m.group(1):
            config["lab_environment"]["network"]["target_interface"] = iface_m.group(1)
    except Exception as e:
        print(f"[-] Warning: Fallback config parser error: {e}", file=sys.stderr)

    return config


class ECaptureRunner:
    def __init__(self, serial=None, binary_path="/data/local/tmp/ecapture",
                 target_libssl="/apex/com.android.conscrypt/lib64/libssl.so",
                 remote_pcap="/data/local/tmp/tls_decrypted.pcapng",
                 remote_keylog="/data/local/tmp/sslkey.log",
                 dry_run=False):
        self.serial = serial
        self.binary_path = binary_path
        self.target_libssl = target_libssl
        self.remote_pcap = remote_pcap
        self.remote_keylog = remote_keylog
        self.dry_run = dry_run

    def run_adb(self, cmd_args, check=False):
        """Executes an ADB command with optional serial routing."""
        base = ["adb"]
        if self.serial:
            base.extend(["-s", self.serial])
        full_cmd = base + cmd_args

        if self.dry_run:
            print(f"[DRY-RUN] {' '.join(full_cmd)}")
            return "SUCCESS"

        try:
            res = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                check=check
            )
            return res.stdout.strip()
        except FileNotFoundError:
            print("[!] Error: 'adb' executable not found in PATH.", file=sys.stderr)
            return ""
        except subprocess.CalledProcessError as e:
            return e.stdout.strip() if e.stdout else ""
        except Exception as e:
            print(f"[!] ADB execution exception: {e}", file=sys.stderr)
            return ""

    def verify_prerequisites(self):
        """Checks for root su, static ecapture binary, and libssl library."""
        print("[*] Verifying eCapture prerequisites on Android device...")
        if self.dry_run:
            print("[+] [DRY-RUN] Prerequisites simulated: All present.")
            return True

        # Check binary
        chk_bin = self.run_adb(["shell", "su", "-c", f"[ -x '{self.binary_path}' ] && echo OK || echo MISSING"])
        if "OK" not in chk_bin:
            print(f"[!] eCapture binary not found or not executable at '{self.binary_path}'.", file=sys.stderr)
            print(f"    Deploy static ARM64 binary: adb push ecapture {self.binary_path} && adb shell chmod 755 {self.binary_path}")
            return False

        # Check target Conscrypt library
        chk_lib = self.run_adb(["shell", "su", "-c", f"[ -f '{self.target_libssl}' ] && echo OK || echo MISSING"])
        if "OK" not in chk_lib:
            # Try 32-bit fallback
            fallback_32 = "/apex/com.android.conscrypt/lib/libssl.so"
            chk_32 = self.run_adb(["shell", "su", "-c", f"[ -f '{fallback_32}' ] && echo OK || echo MISSING"])
            if "OK" in chk_32:
                print(f"  [*] 64-bit libssl not found; switching to 32-bit: {fallback_32}")
                self.target_libssl = fallback_32
            else:
                print(f"[!] Conscrypt libssl.so not found at '{self.target_libssl}'.", file=sys.stderr)
                return False

        print(f"  [+] eCapture binary: {self.binary_path} (Ready)")
        print(f"  [+] Conscrypt libssl: {self.target_libssl} (Found)")
        return True

    def start(self, iface="wlan0"):
        """Launches ecapture in background via kernel eBPF uprobes."""
        print(f"[*] Launching eBPF TLS capture via eCapture on interface {iface}...")

        # Purge stale capture artifacts
        self.run_adb(["shell", "su", "-c", f"rm -f {self.remote_keylog} {self.remote_pcap} /data/local/tmp/ecapture.log"])

        cmd = (
            f"nohup {self.binary_path} tls -m pcap -i {iface} "
            f"--pcapfile={self.remote_pcap} --sslkeylog={self.remote_keylog} "
            f"--libssl={self.target_libssl} > /data/local/tmp/ecapture.log 2>&1 &"
        )
        self.run_adb(["shell", "su", "-c", cmd])

        if not self.dry_run:
            time.sleep(2)
            # Verify process is running
            pid = self.run_adb(["shell", "pidof ecapture"])
            if pid:
                print(f"[+] eCapture running successfully (PID {pid}).")
            else:
                print("[-] Warning: eCapture process not detected in pidof. Check /data/local/tmp/ecapture.log")
        else:
            print("[+] [DRY-RUN] eCapture attached to Conscrypt libssl.so uprobes.")

    def stop(self):
        """Flushes buffers and stops ecapture process cleanly via SIGINT/SIGTERM."""
        print("[*] Stopping eCapture process on device...")
        # Send SIGINT first to allow eCapture to flush NSS keylog and pcapng headers
        self.run_adb(["shell", "su", "-c", "pkill -2 ecapture 2>/dev/null || pkill -15 ecapture 2>/dev/null || true"])
        if not self.dry_run:
            time.sleep(2)
        print("[+] eCapture stopped. In-kernel buffers flushed.")

    def pull_captures(self, host_output_dir):
        """Pulls sslkey.log and tls_decrypted.pcapng to host session directory."""
        print(f"[*] Retrieving TLS captures from device to {host_output_dir}...")
        os.makedirs(host_output_dir, exist_ok=True)

        local_keylog = os.path.join(host_output_dir, "sslkey.log")
        local_pcap = os.path.join(host_output_dir, "tls_decrypted.pcapng")

        self.run_adb(["pull", self.remote_keylog, local_keylog])
        self.run_adb(["pull", self.remote_pcap, local_pcap])

        if self.dry_run:
            print(f"[+] [DRY-RUN] Captures saved: {local_keylog}, {local_pcap}")
            return True

        if os.path.exists(local_keylog) and os.path.getsize(local_keylog) > 0:
            print(f"  [+] TLS Master Secrets retrieved: {local_keylog} ({os.path.getsize(local_keylog)} bytes)")
        else:
            print(f"  [-] Notice: sslkey.log is empty or not yet populated.")

        if os.path.exists(local_pcap) and os.path.getsize(local_pcap) > 0:
            print(f"  [+] Decrypted PCAPNG retrieved: {local_pcap} ({os.path.getsize(local_pcap)} bytes)")
        else:
            print(f"  [-] Notice: tls_decrypted.pcapng is empty or not yet populated.")

        return True

    def status(self):
        """Checks if ecapture is actively running on device."""
        print("[*] Checking on-device eCapture status...")
        if self.dry_run:
            print("[+] [DRY-RUN] eCapture status: ACTIVE (eBPF uprobes hooked)")
            return True

        pid = self.run_adb(["shell", "pidof ecapture"])
        if pid:
            print(f"[+] eCapture is actively RUNNING (PID {pid}).")
            return True
        else:
            print("[-] eCapture is NOT running.")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="dbug eCapture eBPF TLS Plaintext & Keylog Runner (Gate G3)"
    )
    parser.add_argument("action", choices=["start", "stop", "status", "pull"], help="Action to execute")
    parser.add_argument("--config", default="config/lab_config.yaml", help="Path to lab_config.yaml")
    parser.add_argument("--serial", default=None, help="ADB device serial number")
    parser.add_argument("--iface", default="wlan0", help="Device network interface (default: wlan0)")
    parser.add_argument("--output-dir", default="./sessions/current_capture", help="Host directory for capture artifacts")
    parser.add_argument("--dry-run", action="store_true", help="Simulate execution without physical hardware")
    args = parser.parse_args()

    cfg = parse_lab_config(args.config)
    dev_cfg = cfg.get("lab_environment", {}).get("device", {})
    net_cfg = cfg.get("lab_environment", {}).get("network", {})
    ecap_cfg = cfg.get("lab_environment", {}).get("telemetry", {}).get("ecapture", {})

    serial = args.serial or dev_cfg.get("serial") or None
    iface = args.iface or net_cfg.get("target_interface", "wlan0")
    bin_path = ecap_cfg.get("remote_binary", "/data/local/tmp/ecapture")
    libssl = ecap_cfg.get("target_libssl", "/apex/com.android.conscrypt/lib64/libssl.so")
    remote_pcap = ecap_cfg.get("pcap_out", "/data/local/tmp/tls_decrypted.pcapng")
    remote_key = ecap_cfg.get("keylog_out", "/data/local/tmp/sslkey.log")

    runner = ECaptureRunner(
        serial=serial,
        binary_path=bin_path,
        target_libssl=libssl,
        remote_pcap=remote_pcap,
        remote_keylog=remote_key,
        dry_run=args.dry_run
    )

    # Setup host signal handling
    def sig_handler(sig, frame):
        print("\n[!] Interrupted by signal. Stopping eCapture...")
        runner.stop()
        runner.pull_captures(args.output_dir)
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    if args.action == "start":
        runner.verify_prerequisites()
        runner.start(iface=iface)
    elif args.action == "stop":
        runner.stop()
        runner.pull_captures(args.output_dir)
    elif args.action == "status":
        runner.status()
    elif args.action == "pull":
        runner.pull_captures(args.output_dir)


if __name__ == "__main__":
    main()
