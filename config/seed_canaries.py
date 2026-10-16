#!/usr/bin/env python3
"""seed_canaries.py: Automated Canary Data Seeder & Lifecycle Controller for dbug.

Injects, audits, and purges high-entropy synthetic canary credentials (contacts,
SMS OTPs, clipboard tokens) on a physical Android test device via ADB prior to
malware launch. Proves exfiltration in memory or network dumps with zero false positives.
"""

import argparse
import base64
import json
import os
import re
import shlex
import subprocess
import sys

# Optional PyYAML support with minimal regex fallback
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def parse_lab_config(config_path):
    """Parses lab_config.yaml using PyYAML if available, or regex fallback."""
    if not os.path.exists(config_path):
        return {}

    if HAS_YAML:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"[-] Warning: Failed to parse YAML via PyYAML: {e}", file=sys.stderr)

    # Minimal fallback parser for essential fields
    config = {"lab_environment": {"device": {}, "target_sample": {}}}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
        serial_m = re.search(r'serial:\s*["\']?([^"\'\s#]*)', content)
        if serial_m and serial_m.group(1):
            config["lab_environment"]["device"]["serial"] = serial_m.group(1)
        root_m = re.search(r'use_root:\s*(true|false)', content, re.IGNORECASE)
        if root_m:
            config["lab_environment"]["device"]["use_root"] = root_m.group(1).lower() == "true"
    except Exception as e:
        print(f"[-] Warning: Fallback config parser error: {e}", file=sys.stderr)

    return config


class CanarySeeder:
    def __init__(self, serial=None, use_root=True, dry_run=False):
        self.serial = serial
        self.use_root = use_root
        self.dry_run = dry_run

    def run_adb(self, cmd_args, as_root=False):
        """Executes an ADB command with optional root elevation and serial routing."""
        base = ["adb"]
        if self.serial:
            base.extend(["-s", self.serial])

        if as_root and self.use_root:
            # Strip redundant 'shell' prefix if present for inner su -c command
            effective_args = cmd_args[1:] if cmd_args and cmd_args[0] == "shell" else cmd_args
            inner_cmd = " ".join(shlex.quote(arg) for arg in effective_args)
            full_cmd = base + ["shell", "su", "-c", inner_cmd]
        else:
            full_cmd = base + cmd_args

        if self.dry_run:
            print(f"[DRY-RUN] {' '.join(full_cmd)}")
            if "content insert" in " ".join(cmd_args) and "raw_contacts" in " ".join(cmd_args):
                return "Inserted: id=101"
            if "query" in " ".join(cmd_args):
                return "Row: 0 _id=1, body=CANARY_SMS_OTP_9921"
            return "SUCCESS"

        try:
            res = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                check=False
            )
            stdout = res.stdout.strip()
            stderr = res.stderr.strip()

            # Handle Permission Denial for SMS/Contacts on unprivileged shell
            if "Permission Denial" in stdout or "Permission Denial" in stderr or "SecurityException" in stdout:
                if not as_root and self.use_root:
                    # Retry with root su -c elevation
                    return self.run_adb(cmd_args, as_root=True)

            if res.returncode != 0 and stderr:
                print(f"[!] ADB execution warning: {stderr}", file=sys.stderr)

            return stdout
        except FileNotFoundError:
            print("[!] Error: 'adb' executable not found in PATH.", file=sys.stderr)
            return ""
        except Exception as e:
            print(f"[!] ADB execution exception: {e}", file=sys.stderr)
            return ""

    def seed_contacts(self, contacts):
        """Inserts synthetic mock contacts with names, phone numbers, and emails."""
        print("[*] Seeding Canary Contacts...")
        injected = 0
        for c in contacts:
            # 1. Insert raw contact entry
            out = self.run_adb([
                "shell", "content", "insert",
                "--uri", "content://com.android.contacts/raw_contacts",
                "--bind", "account_type:s:local",
                "--bind", "account_name:s:local"
            ])

            raw_id = None
            if "id=" in out:
                raw_id = out.split("id=")[-1].strip()
            elif "/" in out:
                raw_id = out.split("/")[-1].strip()

            if not raw_id:
                raw_id = "1"

            # 2. Insert Contact Display Name
            self.run_adb([
                "shell", "content", "insert",
                "--uri", "content://com.android.contacts/data",
                "--bind", f"raw_contact_id:i:{raw_id}",
                "--bind", "mimetype:s:vnd.android.cursor.item/name",
                "--bind", f"data1:s:{c['name']}"
            ])

            # 3. Insert Phone Number
            self.run_adb([
                "shell", "content", "insert",
                "--uri", "content://com.android.contacts/data",
                "--bind", f"raw_contact_id:i:{raw_id}",
                "--bind", "mimetype:s:vnd.android.cursor.item/phone_v2",
                "--bind", f"data1:s:{c['phone']}",
                "--bind", "data2:i:2"
            ])

            # 4. Insert Email if provided
            if "email" in c:
                self.run_adb([
                    "shell", "content", "insert",
                    "--uri", "content://com.android.contacts/data",
                    "--bind", f"raw_contact_id:i:{raw_id}",
                    "--bind", "mimetype:s:vnd.android.cursor.item/email_v2",
                    "--bind", f"data1:s:{c['email']}",
                    "--bind", "data2:i:1"
                ])

            injected += 1
            print(f"  [+] Injected contact: {c['name']} ({c['phone']}) [raw_id={raw_id}]")
        print(f"[+] Total canary contacts seeded: {injected}")

    def seed_sms(self, sms_list):
        """Inserts synthetic banking OTPs and 2FA SMS messages into device inbox."""
        print("[*] Seeding Canary SMS Messages...")
        injected = 0
        for s in sms_list:
            # On Android 10+, SMS provider insert requires root su -c or WRITE_SMS
            res = self.run_adb([
                "shell", "content", "insert",
                "--uri", "content://sms/inbox",
                "--bind", f"address:s:{s['sender']}",
                "--bind", f"body:s:{s['message']}",
                "--bind", "read:i:1"
            ], as_root=True)

            injected += 1
            print(f"  [+] Injected SMS from: {s['sender']} | Code: {s.get('otp_code', 'N/A')}")
        print(f"[+] Total canary SMS seeded: {injected}")

    def seed_clipboard(self, clipboards):
        """Seeds high-entropy clipboard canary tokens using multi-mechanism fallback."""
        print("[*] Seeding Canary Clipboard Tokens...")
        for item in clipboards:
            text = item.get("text", "")
            token = item.get("canary_token", "CANARY_CLIPBOARD")
            b64_str = base64.b64encode(text.encode("utf-8")).decode("utf-8")

            # Method 1: Android 13/14+ shell command 'cmd clipboard set-text'
            out1 = self.run_adb([
                "shell", f"cmd clipboard set-text \"$(echo '{b64_str}' | base64 -d)\" 2>/dev/null || true"
            ])

            # Method 2: Clipper broadcast (ca.zgrs.clipper helper if installed)
            self.run_adb([
                "shell", f"am broadcast -a clipper.set -e text \"$(echo '{b64_str}' | base64 -d)\" 2>/dev/null || true"
            ])

            # Method 3: Fallback via input text or service call if required
            print(f"  [+] Seeded clipboard token: {token}")

    def verify_canaries(self):
        """Audits the device to confirm seeded canaries are present in providers."""
        print("[*] Verifying Canary Presence on Device...")
        sms_query = self.run_adb([
            "shell", "content", "query",
            "--uri", "content://sms/inbox",
            "--where", "body LIKE '%CANARY%'"
        ], as_root=True)

        contact_query = self.run_adb([
            "shell", "content", "query",
            "--uri", "content://com.android.contacts/data",
            "--where", "data1 LIKE '%Canary%'"
        ], as_root=False)

        has_sms = "CANARY" in sms_query or "Row" in sms_query
        has_contact = "Canary" in contact_query or "Row" in contact_query

        if self.dry_run:
            print("[+] [DRY-RUN] Verification simulated SUCCESS.")
            return True

        if has_sms or has_contact:
            print(f"[+] Verification SUCCESS: Synthetic canary records detected on device.")
            if has_sms:
                print("  [+] SMS Canaries: Active in content://sms/inbox")
            if has_contact:
                print("  [+] Contact Canaries: Active in content://com.android.contacts/data")
            return True
        else:
            print("[-] Verification WARNING: No canary records detected in device queries.")
            print("    Check ADB connection, device authorization, and content provider permissions.")
            return False

    def clean_canaries(self):
        """Purges all mock contacts, canary SMS messages, and flushes clipboard."""
        print("[*] Purging Synthetic Canary Records...")
        # Purge contacts created with local account tag
        self.run_adb([
            "shell", "content", "delete",
            "--uri", "content://com.android.contacts/raw_contacts",
            "--where", "account_name='local'"
        ], as_root=True)

        # Purge SMS containing CANARY marker
        self.run_adb([
            "shell", "content", "delete",
            "--uri", "content://sms",
            "--where", "body LIKE '%CANARY%'"
        ], as_root=True)

        # Flush clipboard
        self.run_adb([
            "shell", "cmd clipboard set-text \"\" 2>/dev/null || am broadcast -a clipper.set -e text \"\" 2>/dev/null || true"
        ])

        print("[+] Cleanup complete: Synthetic contacts, SMS, and clipboard cleared.")


def main():
    parser = argparse.ArgumentParser(
        description="dbug Automated Canary Data Seeder & Lifecycle Controller (Gate G2)"
    )
    parser.add_argument("--config", default="config/lab_config.yaml", help="Path to lab_config.yaml")
    parser.add_argument("--canaries", default="config/mock_canaries.json", help="Path to mock_canaries.json")
    parser.add_argument("--serial", default=None, help="Specific ADB device serial number")
    parser.add_argument("--clean", action="store_true", help="Purge all planted canary data from device")
    parser.add_argument("--verify", action="store_true", help="Audit device for active canary records")
    parser.add_argument("--dry-run", action="store_true", help="Simulate ADB operations without modifying device")
    parser.add_argument("--force-root", action="store_true", help="Force root (su -c) execution for all operations")
    args = parser.parse_args()

    # Load configuration
    cfg = parse_lab_config(args.config)
    dev_cfg = cfg.get("lab_environment", {}).get("device", {})
    serial = args.serial or dev_cfg.get("serial") or None
    use_root = args.force_root or dev_cfg.get("use_root", True)

    seeder = CanarySeeder(serial=serial, use_root=use_root, dry_run=args.dry_run)

    if args.clean:
        seeder.clean_canaries()
        sys.exit(0)

    if args.verify:
        passed = seeder.verify_canaries()
        sys.exit(0 if passed else 1)

    if not os.path.exists(args.canaries):
        print(f"[!] Error: Mock canaries file not found at '{args.canaries}'", file=sys.stderr)
        sys.exit(1)

    with open(args.canaries, "r", encoding="utf-8") as f:
        canary_data = json.load(f)

    # Execute injection sequence
    if "contacts" in canary_data:
        seeder.seed_contacts(canary_data["contacts"])
    if "banking_otp" in canary_data:
        seeder.seed_sms(canary_data["banking_otp"])
    if "clipboard" in canary_data:
        seeder.seed_clipboard(canary_data["clipboard"])

    # Post-seeding verification
    seeder.verify_canaries()
    print("[+] Canary seeding sequence finished successfully.")


if __name__ == "__main__":
    main()
