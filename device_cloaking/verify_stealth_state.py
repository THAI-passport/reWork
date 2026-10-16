#!/usr/bin/env python3
"""verify_stealth_state.py: Host-Side Pre-Flight Stealth State Audit Suite (Gate G1).

Audits system properties, SettingsProvider developer flags, network interfaces,
and open ports on the physical Android test device before malware launch.
Ensures zero analysis artifacts leak into the target process space.
"""

import argparse
import os
import re
import shlex
import subprocess
import sys

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

    config = {"lab_environment": {"device": {}, "telemetry": {}}}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
        serial_m = re.search(r'serial:\s*["\']?([^"\'\s#]*)', content)
        if serial_m and serial_m.group(1):
            config["lab_environment"]["device"]["serial"] = serial_m.group(1)
        tmp_m = re.search(r'remote_tmp_dir:\s*["\']?([^"\'\s#]*)', content)
        if tmp_m and tmp_m.group(1):
            config["lab_environment"]["device"]["remote_tmp_dir"] = tmp_m.group(1)
    except Exception as e:
        print(f"[-] Warning: Fallback config parser error: {e}", file=sys.stderr)

    return config


class StealthAuditor:
    def __init__(self, serial=None, dry_run=False):
        self.serial = serial
        self.dry_run = dry_run

    def run_adb(self, cmd_args, check=False):
        """Executes an ADB command with optional serial routing."""
        base = ["adb"]
        if self.serial:
            base.extend(["-s", self.serial])
        full_cmd = base + cmd_args

        if self.dry_run:
            cmd_str = " ".join(cmd_args)
            if "getprop ro.debuggable" in cmd_str:
                return "0"
            if "getprop ro.secure" in cmd_str:
                return "1"
            if "getprop ro.build.type" in cmd_str:
                return "user"
            if "getprop ro.build.tags" in cmd_str:
                return "release-keys"
            if "getprop sys.usb.state" in cmd_str:
                return "mtp"
            if "getprop sys.usb.config" in cmd_str:
                return "mtp"
            if "getprop init.svc.adbd" in cmd_str:
                return "stopped"
            if "getprop http.proxyHost" in cmd_str:
                return ""
            if "settings get global adb_enabled" in cmd_str:
                return "0"
            if "settings get global development_settings_enabled" in cmd_str:
                return "0"
            if "ip -o link show" in cmd_str:
                return "1: lo: <LOOPBACK> \n2: wlan0: <BROADCAST,MULTICAST,UP> "
            if "/proc/net/tcp" in cmd_str:
                return "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
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

    def push_and_apply_props(self, script_path="device_cloaking/apply_stealth_props.sh"):
        """Pushes apply_stealth_props.sh to device and executes it via root."""
        print("[*] Pushing and applying stealth cloaking properties...")
        if self.dry_run:
            print(f"[DRY-RUN] adb push {script_path} /data/local/tmp/apply_stealth_props.sh")
            print("[DRY-RUN] adb shell su -c 'sh /data/local/tmp/apply_stealth_props.sh apply'")
            print("[+] [DRY-RUN] Stealth properties applied successfully.")
            return True

        if not os.path.exists(script_path):
            print(f"[!] Error: Script '{script_path}' not found on host.", file=sys.stderr)
            return False

        # Push script to device tmp
        push_out = self.run_adb(["push", script_path, "/data/local/tmp/apply_stealth_props.sh"])
        self.run_adb(["shell", "chmod", "755", "/data/local/tmp/apply_stealth_props.sh"])

        # Execute via su -c
        out = self.run_adb(["shell", "su", "-c", "sh /data/local/tmp/apply_stealth_props.sh apply"])
        print(out)
        return True

    def restore_props(self, script_path="device_cloaking/apply_stealth_props.sh"):
        """Reverts stealth properties to standard developer debugging state."""
        print("[*] Restoring standard developer debug properties on device...")
        if self.dry_run:
            print("[DRY-RUN] adb shell su -c 'sh /data/local/tmp/apply_stealth_props.sh restore'")
            print("[+] [DRY-RUN] Properties restored to developer defaults.")
            return True

        self.run_adb(["push", script_path, "/data/local/tmp/apply_stealth_props.sh"])
        self.run_adb(["shell", "chmod", "755", "/data/local/tmp/apply_stealth_props.sh"])
        out = self.run_adb(["shell", "su", "-c", "sh /data/local/tmp/apply_stealth_props.sh restore"])
        print(out)
        return True

    def audit(self):
        """Executes full multi-layer stealth state audit."""
        print("=" * 65)
        print("[*] STARTING PRE-FLIGHT STEALTH STATE AUDIT (Gate G1)")
        print("=" * 65)
        failures = []
        warnings = []

        # ---------------------------------------------------------
        # Layer 1: System Properties via getprop
        # ---------------------------------------------------------
        print("[*] Layer 1: Auditing System Properties (Kernel/Init Memory)...")
        expected_props = {
            "ro.debuggable": "0",
            "ro.secure": "1",
            "ro.build.type": "user",
            "ro.build.tags": "release-keys",
            "sys.usb.state": "mtp",
            "sys.usb.config": "mtp",
            "init.svc.adbd": "stopped"
        }

        for prop, expected in expected_props.items():
            actual = self.run_adb(["shell", "getprop", prop])
            if actual != expected:
                failures.append(f"System Property '{prop}' is '{actual}' (expected '{expected}')")
                print(f"  [-] {prop} = '{actual}' [FAIL: expected '{expected}']")
            else:
                print(f"  [+] {prop} = '{actual}' (PASS)")

        # ---------------------------------------------------------
        # Layer 2: Settings.Global Developer Flags
        # ---------------------------------------------------------
        print("[*] Layer 2: Auditing Settings.Global Developer Flags...")
        adb_setting = self.run_adb(["shell", "settings", "get", "global", "adb_enabled"])
        dev_setting = self.run_adb(["shell", "settings", "get", "global", "development_settings_enabled"])

        if adb_setting not in ("0", "null", ""):
            failures.append(f"Settings.Global.adb_enabled reports '{adb_setting}' (expected '0' or unexposed)")
            print(f"  [-] Settings.Global.adb_enabled = '{adb_setting}' [FAIL]")
        else:
            print(f"  [+] Settings.Global.adb_enabled = '{adb_setting}' (PASS)")

        if dev_setting not in ("0", "null", ""):
            warnings.append(f"Settings.Global.development_settings_enabled is '{dev_setting}' (recommend '0')")
            print(f"  [*] Settings.Global.development_settings_enabled = '{dev_setting}' (WARN)")
        else:
            print(f"  [+] Settings.Global.development_settings_enabled = '{dev_setting}' (PASS)")

        # ---------------------------------------------------------
        # Layer 3: Network Interfaces & Proxy
        # ---------------------------------------------------------
        print("[*] Layer 3: Auditing Network Hygiene (VPN & Proxy Interfaces)...")
        link_output = self.run_adb(["shell", "ip -o link show 2>/dev/null | awk -F': ' '{print $2}'"])
        links = link_output.split() if link_output else []

        vpn_ifaces = [iface for iface in links if iface.startswith(("tun", "ppp", "p2p"))]
        if vpn_ifaces:
            for vpn in vpn_ifaces:
                failures.append(f"Forbidden VPN/P2P network interface detected: '{vpn}'")
                print(f"  [-] VPN Interface detected: '{vpn}' [FAIL]")
        else:
            clean_links = ", ".join(links) if links else "lo, wlan0"
            print(f"  [+] No VPN/tun interfaces active. Active: {clean_links} (PASS)")

        proxy = self.run_adb(["shell", "getprop", "http.proxyHost"])
        if proxy:
            failures.append(f"Android system proxy property detected: http.proxyHost='{proxy}'")
            print(f"  [-] http.proxyHost = '{proxy}' [FAIL]")
        else:
            print("  [+] No system HTTP proxy configured (PASS)")

        # ---------------------------------------------------------
        # Layer 4: Port Hygiene (Frida & Remote ADB)
        # ---------------------------------------------------------
        print("[*] Layer 4: Auditing Port Exposure (Frida & ADB Ports)...")
        tcp_dump = self.run_adb(["shell", "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null"])

        # 27042 in hex is 69A2
        if ":69A2" in tcp_dump or "27042" in tcp_dump:
            failures.append("Default Frida port 27042 (:69A2) is OPEN on device! Use stealth port 38921.")
            print("  [-] Default Frida port 27042 is OPEN [FAIL]")
        else:
            print("  [+] Default Frida port 27042 is CLOSED (PASS)")

        # 5555 in hex is 15B3 (remote TCP ADB)
        if ":15B3" in tcp_dump:
            warnings.append("ADB TCP port 5555 (:15B3) is open on device. Ensure isolated subnet routing.")
            print("  [*] ADB TCP port 5555 is listening (WARN)")
        else:
            print("  [+] ADB TCP port 5555 is not exposed (PASS)")

        # ---------------------------------------------------------
        # Layer 5: ADB Automation Viability
        # ---------------------------------------------------------
        print("[*] Layer 5: Verifying ADB Transport Viability...")
        test_uid = self.run_adb(["shell", "id -u"])
        if test_uid:
            print(f"  [+] ADB transport functional (caller UID={test_uid}) (PASS)")
        else:
            failures.append("ADB transport unresponsive after property masking.")
            print("  [-] ADB transport unresponsive [FAIL]")

        # ---------------------------------------------------------
        # Audit Summary & Gate Determination
        # ---------------------------------------------------------
        print("-" * 65)
        if warnings:
            print("[!] Operational Warnings:")
            for w in warnings:
                print(f"  - {w}")

        if failures:
            print("[!] PRE-FLIGHT STEALTH AUDIT FAILED (Gate G1 Blocked):")
            for f in failures:
                print(f"  [X] {f}")
            print("=" * 65)
            print("Action Required: Run 'python3 device_cloaking/verify_stealth_state.py --push-and-apply'")
            print("or check LSPosed HideDevMode configuration before launching malware.")
            return False
        else:
            print("[+] ALL PRE-FLIGHT STEALTH CHECKS PASSED (Gate G1 Clear).")
            print("    Device is clean, masked, and authorized for malware detonation.")
            print("=" * 65)
            return True


def main():
    parser = argparse.ArgumentParser(
        description="dbug Host-Side Pre-Flight Stealth State Audit Suite (Gate G1)"
    )
    parser.add_argument("--config", default="config/lab_config.yaml", help="Path to lab_config.yaml")
    parser.add_argument("--serial", default=None, help="ADB device serial number")
    parser.add_argument("--dry-run", action="store_true", help="Simulate audit checks without physical hardware")
    parser.add_argument("--push-and-apply", action="store_true", help="Push and apply stealth properties via root before auditing")
    parser.add_argument("--restore", action="store_true", help="Revert device properties to developer defaults")
    args = parser.parse_args()

    # Load configuration
    cfg = parse_lab_config(args.config)
    dev_cfg = cfg.get("lab_environment", {}).get("device", {})
    serial = args.serial or dev_cfg.get("serial") or None

    auditor = StealthAuditor(serial=serial, dry_run=args.dry_run)

    if args.restore:
        ok = auditor.restore_props()
        sys.exit(0 if ok else 1)

    if args.push_and_apply:
        auditor.push_and_apply_props()

    passed = auditor.audit()
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
