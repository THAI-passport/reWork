#!/usr/bin/env python3
"""sanitize_device_state.py: Dedicated Device State Sanitizer & Teardown for dbug.

Audits and returns the physical Android test device to a pristine baseline
between analysis modes, ensuring no debugging artifacts leak into stealth
malware runs.

Six sanitization tiers:

  Tier 1 - Trust Anchors:   purge user-installed CA certificates from
                            /data/misc/user/*/cacerts-added/ and
                            /data/misc/keychain/cacerts-added/.
  Tier 2 - Proxy Configs:   clear Settings.Global http_proxy,
                            global_http_proxy_host, and system properties
                            http.proxyHost / http.proxyPort.
  Tier 3 - Lingering Daemons: SIGKILL orphaned frida-server, ecapture, tcpdump.
  Tier 4 - Target App Teardown: am force-stop, pm clear, pm uninstall <package>.
  Tier 5 - Canary Scrubbing:  invoke seed_canaries.py --clean.
  Tier 6 - Property Enforcement: verify stealth cloaking props, or restore
                            developer defaults when --restore-props is requested.
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
    config = {"lab_environment": {"device": {}}}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
        serial_m = re.search(r'serial:\s*[\"\']?([^\"\'\s#]*)', content)
        if serial_m and serial_m.group(1):
            config["lab_environment"]["device"]["serial"] = serial_m.group(1)
        root_m = re.search(r'use_root:\s*(true|false)', content, re.IGNORECASE)
        if root_m:
            config["lab_environment"]["device"]["use_root"] = root_m.group(1).lower() == "true"
    except Exception as e:
        print(f"[-] Warning: Fallback config parser error: {e}", file=sys.stderr)
    return config


class DeviceSanitizer:
    def __init__(self, serial=None, use_root=True, dry_run=False, package_name=None,
                 restore_props=False):
        self.serial = serial
        self.use_root = use_root
        self.dry_run = dry_run
        self.package_name = package_name
        self.restore_props = restore_props
        self.tiers = {
            1: "Trust Anchors (user CA certificates)",
            2: "Proxy Configurations",
            3: "Lingering Daemons",
            4: "Target App Teardown",
            5: "Canary Scrubbing",
            6: "Property Enforcement",
        }
        self.results = {}

    def run_adb(self, cmd_args, as_root=False, check=False):
        """Executes an ADB command with optional root elevation and serial routing."""
        base = ["adb"]
        if self.serial:
            base.extend(["-s", self.serial])

        if as_root and self.use_root:
            effective_args = cmd_args[1:] if cmd_args and cmd_args[0] == "shell" else cmd_args
            inner_cmd = " ".join(shlex.quote(arg) for arg in effective_args)
            full_cmd = base + ["shell", "su", "-c", inner_cmd]
        else:
            full_cmd = base + cmd_args

        if self.dry_run:
            print(f"[DRY-RUN] {' '.join(full_cmd)}")
            return "SUCCESS"

        try:
            res = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                check=check,
            )
            return res.stdout.strip()
        except FileNotFoundError:
            print("[!] Error: 'adb' executable not found in PATH.", file=sys.stderr)
            return ""
        except subprocess.CalledProcessError as e:
            print(f"[!] ADB command failed: {e}", file=sys.stderr)
            return e.stdout.strip() if e.stdout else ""
        except Exception as e:
            print(f"[!] ADB execution exception: {e}", file=sys.stderr)
            return ""

    # ------------------------------------------------------------------
    # Tier 1 - Trust Anchors: user-installed CA certificates
    # ------------------------------------------------------------------
    def tier1_trust_anchors(self):
        print("\n[*] Tier 1: Auditing & purging user-installed CA certificates...")
        ca_dirs = [
            "/data/misc/user/0/cacerts-added/",
            "/data/misc/keychain/cacerts-added/",
        ]
        purged = []
        for ca_dir in ca_dirs:
            if self.dry_run:
                print(f"    [DRY-RUN] Would list & remove CA certs in {ca_dir}")
                continue
            listing = self.run_adb(["shell", "ls", "-la", ca_dir], as_root=True)
            if listing and "No such file" not in listing and "No such file or directory" not in listing:
                print(f"    Found CA certificate directory: {ca_dir}")
                self.run_adb(
                    ["shell", "rm", "-f", ca_dir + "*"], as_root=True, check=True
                )
                purged.append(ca_dir)
                print(f"    [+] Purged user CA certificates in {ca_dir}")
            else:
                print(f"    [+] No user CA certificates found in {ca_dir}")
        self.results[1] = {"status": "PASS", "purged_dirs": purged}
        return self.results[1]

    # ------------------------------------------------------------------
    # Tier 2 - Proxy Configurations
    # ------------------------------------------------------------------
    def tier2_proxy_configs(self):
        print("\n[*] Tier 2: Clearing HTTP proxy configurations & properties...")
        cleared = []
        for setting in ["http_proxy", "global_http_proxy_host"]:
            self.run_adb(
                ["shell", "settings", "delete", "global", setting], as_root=True
            )
            cleared.append(setting)
            print(f"    [+] Deleted Settings.Global.{setting}")
        for prop in ["http.proxyHost", "http.proxyPort"]:
            if self.dry_run:
                print(f"    [DRY-RUN] Would resetprop {prop} ''")
                continue
            self.run_adb(["shell", "resetprop", prop, ""], as_root=True, check=True)
        # --- Settings.Global adb_enabled / development_settings_enabled ---
        for setting, val in [("adb_enabled", "0"), ("development_settings_enabled", "0")]:
            if self.dry_run:
                print(f"    [DRY-RUN] Would settings put global {setting} {val}")
                continue
            self.run_adb(
                ["shell", "settings", "put", "global", setting, val],
                as_root=True, check=True
            )
            cleared.append(f"Settings.Global.{setting}={val}")
            print(f"    [+] settings put global {setting} {val}")

        self.results[2] = {"status": "PASS", "cleared": cleared}
        return self.results[2]

    # ------------------------------------------------------------------
    # Tier 3 - Lingering Daemons
    # ------------------------------------------------------------------
    def tier3_daemons(self):
        print("\n[*] Tier 3: Terminating lingering background daemons...")
        daemons = ["frida-server", "ecapture", "tcpdump"]
        killed = []
        for daemon in daemons:
            if self.dry_run:
                print(f"    [DRY-RUN] Would pkill -9 {daemon}")
                continue
            self.run_adb(["shell", "pkill", "-9", daemon], as_root=True)
            killed.append(daemon)
            print(f"    [+] Sent SIGKILL to {daemon}")
        self.results[3] = {"status": "PASS", "killed": killed}
        return self.results[3]

    # ------------------------------------------------------------------
    # Tier 4 - Target App Teardown
    # ------------------------------------------------------------------
    def tier4_app_teardown(self):
        print("\n[*] Tier 4: Target application teardown...")
        if not self.package_name:
            print("    [!] No package name supplied; skipping app teardown.")
            self.results[4] = {"status": "SKIP", "reason": "no package name"}
            return self.results[4]
        actions = [
            (["shell", "am", "force-stop", self.package_name], "force-stop"),
            (["shell", "pm", "clear", self.package_name], "pm clear"),
            (["shell", "pm", "uninstall", self.package_name], "pm uninstall"),
        ]
        completed = []
        for cmd, label in actions:
            if self.dry_run:
                print(f"    [DRY-RUN] Would adb {' '.join(cmd)}")
                completed.append(label)
                continue
            self.run_adb(cmd, as_root=True)
            completed.append(label)
            print(f"    [+] {label} -> {self.package_name}")
        self.results[4] = {"status": "PASS", "actions": completed}
        return self.results[4]

    # ------------------------------------------------------------------
    # Tier 5 - Canary Scrubbing
    # ------------------------------------------------------------------
    def tier5_canary_scrubbing(self, config_path):
        print("\n[*] Tier 5: Scrubbing synthetic canary data...")
        clean_cmd = ["python3", "config/seed_canaries.py", "--clean", "--config", config_path]
        if self.dry_run:
            clean_cmd.append("--dry-run")
        if self.serial:
            clean_cmd.extend(["--serial", self.serial])
        if self.dry_run:
            print("    [DRY-RUN] Would run: " + " ".join(clean_cmd))
            self.results[5] = {"status": "PASS", "dry_run": True}
            return self.results[5]
        try:
            res = subprocess.run(clean_cmd, capture_output=True, text=True, check=False)
            print(res.stdout)
            if res.returncode != 0:
                print(res.stderr, file=sys.stderr)
            self.results[5] = {"status": "PASS" if res.returncode == 0 else "FAIL",
                               "rc": res.returncode}
        except Exception as e:
            print(f"[!] Canary scrubbing exception: {e}", file=sys.stderr)
            self.results[5] = {"status": "FAIL", "error": str(e)}
        return self.results[5]

    # ------------------------------------------------------------------
    # Tier 6 - Property Enforcement
    # ------------------------------------------------------------------
    def tier6_property_enforcement(self):
        print("\n[*] Tier 6: Property enforcement...")
        stealth_props = {
            "ro.debuggable": "0",
            "ro.secure": "1",
            "ro.build.type": "user",
            "ro.build.tags": "release-keys",
            "sys.usb.state": "mtp",
            "sys.usb.config": "mtp",
            "persist.sys.usb.config": "mtp",
            "init.svc.adbd": "stopped",
        }
        if self.restore_props:
            print("    --restore-props requested: reverting to developer defaults...")
            restore_props = {
                "ro.debuggable": "1",
                "sys.usb.state": "adb",
                "sys.usb.config": "adb",
                "init.svc.adbd": "running",
            }
            for prop, val in restore_props.items():
                if self.dry_run:
                    print(f"    [DRY-RUN] Would resetprop {prop} {val}")
                    continue
                self.run_adb(["shell", "resetprop", prop, val], as_root=True, check=True)
                print(f"    [+] resetprop {prop} -> {val}")
            self.results[6] = {"status": "PASS", "mode": "restore"}
            return self.results[6]

        failures = []
        for prop, expected in stealth_props.items():
            if self.dry_run:
                print(f"    [DRY-RUN] Would verify {prop} == {expected}")
                continue
            actual = self.run_adb(["shell", "getprop", prop])
            if actual != expected:
                failures.append(f"{prop}: expected={expected}, actual={actual}")
                print(f"    [-] {prop} = {actual} (expected {expected}) [FAIL]")
            else:
                print(f"    [+] {prop} = {expected} [PASS]")
        if failures:
            self.results[6] = {"status": "FAIL", "failures": failures}
            print("    [!] Stealth property verification FAILED.")
        else:
            self.results[6] = {"status": "PASS", "mode": "verify"}
            print("    [+] All stealth properties verified.")
        return self.results[6]

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------
    def run_all(self, config_path):
        print("=" * 65)
        print("dbug DEVICE STATE SANITIZER - Six-Tier Teardown Sequence")
        print("=" * 65)
        self.tier1_trust_anchors()
        self.tier2_proxy_configs()
        self.tier3_daemons()
        self.tier4_app_teardown()
        self.tier5_canary_scrubbing(config_path)
        self.tier6_property_enforcement()
        print("=" * 65)
        print("SANITIZATION SUMMARY")
        print("=" * 65)
        all_pass = True
        for tier_num in sorted(self.tiers):
            res = self.results.get(tier_num, {})
            status = res.get("status", "UNKNOWN")
            marker = "[+]" if status == "PASS" else ("[-]" if status == "FAIL" else "[*]")
            print(f"  {marker} Tier {tier_num} ({self.tiers[tier_num]}): {status}")
            if status == "FAIL":
                all_pass = False
        print("=" * 65)
        if all_pass:
            print("[+] Device returned to pristine baseline. Safe for stealth analysis.")
        else:
            print("[!] One or more tiers failed. Review output before launching target.")
        return all_pass


def main():
    parser = argparse.ArgumentParser(
        description="dbug Dedicated Device State Sanitizer & Teardown"
    )
    parser.add_argument("--config", default="config/lab_config.yaml",
                        help="Path to lab_config.yaml")
    parser.add_argument("--serial", default=None, help="ADB device serial number")
    parser.add_argument("--package", default=None,
                        help="Target package name for app teardown (Tier 4)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simulate sanitization without modifying device")
    parser.add_argument("--restore-props", action="store_true",
                        help="Restore developer-default properties instead of verifying stealth")
    parser.add_argument("--tier", type=int, default=None,
                        help="Run only a specific tier (1-6)")
    args = parser.parse_args()

    cfg = parse_lab_config(args.config)
    dev_cfg = cfg.get("lab_environment", {}).get("device", {})
    serial = args.serial or dev_cfg.get("serial") or None
    use_root = dev_cfg.get("use_root", True)

    sanitizer = DeviceSanitizer(
        serial=serial,
        use_root=use_root,
        dry_run=args.dry_run,
        package_name=args.package,
        restore_props=args.restore_props,
    )

    if args.tier:
        tier_map = {
            1: sanitizer.tier1_trust_anchors,
            2: sanitizer.tier2_proxy_configs,
            3: sanitizer.tier3_daemons,
            4: sanitizer.tier4_app_teardown,
            5: lambda: sanitizer.tier5_canary_scrubbing(args.config),
            6: sanitizer.tier6_property_enforcement,
        }
        if args.tier not in tier_map:
            print(f"[!] Invalid tier: {args.tier}. Choose 1-6.", file=sys.stderr)
            sys.exit(1)
        tier_map[args.tier]()
        sys.exit(0)

    ok = sanitizer.run_all(args.config)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
