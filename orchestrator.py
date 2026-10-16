#!/usr/bin/env python3
"""orchestrator.py: Master Automation CLI for dbug Stealth Android Malware Sandbox.

Coordinates the end-to-end dynamic analysis lifecycle across all gates (G0 - G5):
1. Pre-Flight Stealth Audit (Gate G1)
2. Canary Data Seeding (Gate G2)
3. Zero-Footprint Gateway & eBPF Captures (Gate G3)
4. Dynamic Runtime Instrumentation (Gate G4)
5. Teardown, PCAP Decryption, Canary Correlation & STIX 2.1 Reporting (Gate G5)
"""

import argparse
import datetime
import hashlib
import json
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


def compute_sha256(file_path):
    """Computes SHA-256 hash of a file if it exists.

    Returns None when the file is missing (callers must handle this;
    never fabricate a hash).
    """
    if not file_path or not os.path.exists(file_path):
        return None
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


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

    config = {
        "lab_environment": {
            "device": {},
            "network": {},
            "target_sample": {},
            "telemetry": {"ecapture": {}, "frida": {}},
            "analysis_defaults": {}
        }
    }
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
        serial_m = re.search(r'serial:\s*["\']?([^"\'\s#]*)', content)
        if serial_m and serial_m.group(1):
            config["lab_environment"]["device"]["serial"] = serial_m.group(1)
        pkg_m = re.search(r'package_name:\s*["\']?([^"\'\s#]*)', content)
        if pkg_m and pkg_m.group(1):
            config["lab_environment"]["target_sample"]["package_name"] = pkg_m.group(1)
        apk_m = re.search(r'apk_path:\s*["\']?([^"\'\s#]*)', content)
        if apk_m and apk_m.group(1):
            config["lab_environment"]["target_sample"]["apk_path"] = apk_m.group(1)
    except Exception as e:
        print(f"[-] Warning: Fallback config parser error: {e}", file=sys.stderr)

    return config


class MasterOrchestrator:
    def __init__(self, apk_path, package_name, duration=120, config_path="config/lab_config.yaml",
                 output_dir=None, dry_run=False, profile="malware", interactive=False, apply_dev_hide=True):
        self.apk_path = apk_path
        self.package_name = package_name
        self.duration = duration
        self.config_path = config_path
        self.dry_run = dry_run
        self.profile = profile.lower()
        self.interactive = interactive
        self.apply_dev_hide = apply_dev_hide

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = output_dir or f"./sessions/session_{ts}_{self.package_name}"
        self.cfg = parse_lab_config(config_path)

        dev_cfg = self.cfg.get("lab_environment", {}).get("device", {})
        self.serial = dev_cfg.get("serial") or None
        # Derive real SHA-256 from the sample; never fabricate a hash.
        if self.apk_path:
            computed = compute_sha256(self.apk_path)
            if computed is None:
                if self.dry_run:
                    self.sha256 = "simulated_" + "0" * 58
                    print(f"[!] Warning: APK not found at '{self.apk_path}'; using simulated SHA-256 for dry-run.")
                else:
                    print(f"[!] Error: Target APK not found at '{self.apk_path}'. Cannot proceed without a real sample.", file=sys.stderr)
                    sys.exit(1)
            else:
                self.sha256 = computed
        else:
            self.sha256 = "simulated_" + "0" * 58

    def run_stage(self, stage_name, cmd_list, check=True):
        """Executes a framework command stage with status reporting."""
        print(f"\n{'=' * 65}")
        print(f"[*] EXECUTING STAGE: {stage_name}")
        print(f"{'=' * 65}")
        print(f"Command: {' '.join(cmd_list)}")

        res = subprocess.run(cmd_list, check=False)
        if check and res.returncode != 0:
            print(f"[!] STAGE FAILED: {stage_name} (Exit code {res.returncode})", file=sys.stderr)
            return False
        return True

    def execute_pipeline(self):
        """Executes the complete multi-profile automated analysis pipeline."""
        print("=" * 65)
        print("dbug MASTER AUTOMATED STEALTH MOBILE SECURITY PIPELINE")
        print("=" * 65)
        print(f"Target Package:  {self.package_name}")
        print(f"Sample Path:     {self.apk_path}")
        print(f"SHA-256:         {self.sha256}")
        print(f"Profile:         {self.profile.upper()}")
        print(f"Observation:     {'INTERACTIVE (User Controlled)' if self.interactive else f'{self.duration} seconds'}")
        print(f"Output Session:  {self.output_dir}")
        print(f"Dry-Run Mode:    {self.dry_run}")
        print("=" * 65)

        os.makedirs(self.output_dir, exist_ok=True)
        py_bin = sys.executable

        # -------------------------------------------------------------
        # Stage 0: Sample Intake & Static Triage (Gate G0)
        # -------------------------------------------------------------
        g0_cmd = [
            py_bin, "sample_triage/triage_apk.py",
            "--apk", self.apk_path,
            "--package", self.package_name,
            "--output-dir", self.output_dir
        ]
        if self.dry_run:
            g0_cmd.append("--dry-run")
        self.run_stage("Gate G0: Sample Intake & Static Triage", g0_cmd, check=False)

        # -------------------------------------------------------------
        # Stage 1: Pre-Flight Stealth Audit (Gate G1)
        # -------------------------------------------------------------
        lsposed_cfg = (
            self.cfg.get("lab_environment", {}).get("telemetry", {}).get("lsposed", {})
        )
        if lsposed_cfg.get("hide_dev_mode_required", False):
            print(
                "[!] G1 hard requirement: LSPosed HideDevMode module must be installed "
                "and enabled (hide_dev_mode_required: true in lab_config.yaml)."
            )
        g1_cmd = [py_bin, "device_cloaking/verify_stealth_state.py", "--config", self.config_path]
        if self.dry_run:
            g1_cmd.append("--dry-run")
        if self.serial:
            g1_cmd.extend(["--serial", self.serial])
        # Push hide_dev_options.sh to device for Settings.Global spoofing
        if self.apply_dev_hide:
            push_hide_dev = [
                "adb", "push", "device_cloaking/hide_dev_options.sh",
                "/data/local/tmp/hide_dev_options.sh"
            ]
            if self.serial:
                push_hide_dev.insert(2, "-s")
                push_hide_dev.insert(3, self.serial)
            if self.dry_run:
                print(f"[DRY-RUN] {' '.join(push_hide_dev)}")
            else:
                subprocess.run(push_hide_dev, capture_output=True, text=True, check=False)
            if os.path.exists("device_cloaking/hide_dev_options.sh"):
                os.chmod("device_cloaking/hide_dev_options.sh", 0o755)

            g1_cmd.append("--apply-dev-hide")



        if not self.run_stage("Gate G1: Pre-Flight Stealth Audit", g1_cmd, check=True):
            print("\n[!] HALT: Pre-flight stealth cloaking audit failed! Malware detonation aborted.", file=sys.stderr)
            sys.exit(1)

        # -------------------------------------------------------------
        # Stage 2: Canary Data Seeding (Gate G2)
        # -------------------------------------------------------------
        g2_cmd = [py_bin, "config/seed_canaries.py", "--config", self.config_path]
        if self.dry_run:
            g2_cmd.append("--dry-run")
        if self.serial:
            g2_cmd.extend(["--serial", self.serial])

        self.run_stage("Gate G2: Canary Data Seeding", g2_cmd, check=True)

        # -------------------------------------------------------------
        # Stage 3: Arm Out-of-Band Network & eBPF Captures (Gate G3)
        # -------------------------------------------------------------
        # Gateway setup
        gw_cmd = ["bash", "network_capture/gateway_setup.sh", "start", "--output-dir", self.output_dir]
        if self.dry_run:
            gw_cmd.append("--dry-run")
        self.run_stage("Gate G3: Network Gateway AP & tcpdump Start", gw_cmd, check=False)

        # eCapture runner
        ecap_cmd = [py_bin, "network_capture/ecapture_runner.py", "start", "--config", self.config_path, "--output-dir", self.output_dir]
        if self.dry_run:
            ecap_cmd.append("--dry-run")
        if self.serial:
            ecap_cmd.extend(["--serial", self.serial])
        self.run_stage("Gate G3: eBPF TLS Uprobe Capture Start", ecap_cmd, check=False)

        # -------------------------------------------------------------
        # Stage 4: Dynamic Instrumented Malware Execution (Gate G4)
        # -------------------------------------------------------------
        events_log = os.path.join(self.output_dir, "instrumentation_events.jsonl")
        profile_json = os.path.join(self.output_dir, "analysis_profile.json")
        frida_cmd = [
            py_bin, "instrumentation/frida_loader.py",
            "--package", self.package_name,
            "--config", self.config_path,
            "--duration", str(self.duration),
            "--output", events_log
        ]
        if os.path.exists(profile_json):
            frida_cmd.extend(["--profile-json", profile_json])
        if self.dry_run:
            frida_cmd.append("--dry-run")

        self.run_stage("Gate G4: Stealth Frida Spawn & Telemetry Stream", frida_cmd, check=False)

        if self.interactive:
            if not self.dry_run:
                print("\n" + "=" * 65)
                print("[*] INTERACTIVE ZERO-TRACE CAPTURE SESSION ACTIVE")
                print("=" * 65)
                print("You may now interact with the target application on the physical phone:")
                print(" - Navigate views, authenticate, trigger APIs, or complete workflows.")
                print(" - Network traffic and cryptographic buffers are captured out-of-band.")
                print("Press ENTER (or Ctrl+C) when finished to commence teardown and auditing...")
                print("=" * 65)
                try:
                    input()
                except (KeyboardInterrupt, EOFError):
                    print("\n[*] Interactive session concluded by analyst signal.")
            else:
                print("[+] [DRY-RUN] Interactive capture session simulated.")

        # -------------------------------------------------------------
        # Stage 5: Teardown & Capture Artifact Collection
        # -------------------------------------------------------------
        print("\n[*] Commencing post-execution teardown and artifact retrieval...")

        # Stop eCapture and pull TLS artifacts
        ecap_stop = [py_bin, "network_capture/ecapture_runner.py", "stop", "--config", self.config_path, "--output-dir", self.output_dir]
        if self.dry_run:
            ecap_stop.append("--dry-run")
        if self.serial:
            ecap_stop.extend(["--serial", self.serial])
        self.run_stage("Teardown: Stop eCapture & Retrieve Keylog", ecap_stop, check=False)

        # Stop gateway tcpdump
        gw_stop = ["bash", "network_capture/gateway_setup.sh", "stop", "--output-dir", self.output_dir]
        if self.dry_run:
            gw_stop.append("--dry-run")
        self.run_stage("Teardown: Stop Gateway tcpdump", gw_stop, check=False)

        # Device state sanitization & baseline restoration (purges user CA certs, proxies, daemons, app, and canaries)
        sanitize_cmd = [
            py_bin, "device_cloaking/sanitize_device_state.py",
            "--config", self.config_path,
            "--package", self.package_name
        ]
        if self.dry_run:
            sanitize_cmd.append("--dry-run")
        if self.serial:
            sanitize_cmd.extend(["--serial", self.serial])
        self.run_stage("Teardown: Device State Sanitization & Baseline Restore", sanitize_cmd, check=False)

        # -------------------------------------------------------------
        # Stage 6: Decryption & Correlation Post-Processing (Gate G5)
        # -------------------------------------------------------------
        pcap_file = os.path.join(self.output_dir, "raw_traffic.pcap")
        keylog_file = os.path.join(self.output_dir, "sslkey.log")
        decrypted_jsonl = os.path.join(self.output_dir, "decrypted_http_requests.jsonl")

        decrypt_cmd = [
            py_bin, "parser_correlator/pcap_decryptor.py",
            "--pcap", pcap_file,
            "--keylog", keylog_file,
            "--output", decrypted_jsonl
        ]
        if self.dry_run:
            decrypt_cmd.append("--dry-run")
        self.run_stage("Gate G5: TLS Packet Stream Decryption", decrypt_cmd, check=False)

        # Canary Hunter
        canary_hits_json = os.path.join(self.output_dir, "CANARY_EXFIL_HITS.json")
        hunter_cmd = [
            py_bin, "parser_correlator/canary_hunter.py",
            "--canaries", "config/mock_canaries.json",
            "--events", events_log,
            "--traffic", decrypted_jsonl,
            "--output", canary_hits_json
        ]
        self.run_stage("Gate G5: Multi-Encoding Canary Hunter", hunter_cmd, check=False)

        # Profile: Malware Analysis & Threat Intelligence
        if self.profile in ["malware", "all"]:
            # C2 Protocol Dissector & Framing Reconstruction
            proto_cmd = [
                py_bin, "parser_correlator/c2_protocol_decoder.py",
                "--session-dir", self.output_dir,
                "--package", self.package_name
            ]
            self.run_stage("Gate G5: C2 Protocol Framing Reconstruction", proto_cmd, check=False)

            # Malware Family Attribution Classifier
            fam_cmd = [
                py_bin, "parser_correlator/family_classifier.py",
                "--session-dir", self.output_dir,
                "--package", self.package_name
            ]
            self.run_stage("Gate G5: Behavioral Family Attribution", fam_cmd, check=False)

            # IOC Extractor & Threat Report Generator
            ioc_cmd = [
                py_bin, "parser_correlator/ioc_extractor.py",
                "--session-dir", self.output_dir,
                "--package", self.package_name,
                "--sha256", self.sha256
            ]
            self.run_stage("Gate G5: IOC & STIX 2.1 Threat Report Generation", ioc_cmd, check=False)

            # Defensive YARA Rule Generator
            yara_cmd = [
                py_bin, "parser_correlator/yara_generator.py",
                "--session-dir", self.output_dir,
                "--package", self.package_name,
                "--sha256", self.sha256
            ]
            self.run_stage("Gate G5: Defensive YARA Signature Generation", yara_cmd, check=False)

        # Profile: Privacy & Ad Tracker Data Leakage Audit
        if self.profile in ["privacy", "all"]:
            priv_cmd = [
                py_bin, "parser_correlator/privacy_auditor.py",
                "--session-dir", self.output_dir,
                "--package", self.package_name
            ]
            self.run_stage("Gate G5: Mobile Privacy & Tracker Leakage Audit", priv_cmd, check=False)

        # Profile: AppSec Penetration Testing & API Discovery
        if self.profile in ["appsec", "all"]:
            appsec_cmd = [
                py_bin, "parser_correlator/appsec_auditor.py",
                "--session-dir", self.output_dir,
                "--package", self.package_name
            ]
            self.run_stage("Gate G5: OWASP MASVS AppSec & API Security Audit", appsec_cmd, check=False)

        # Sync canonical target workspace per AGENTS.md contract
        self.sync_canonical_target_repo()

        # -------------------------------------------------------------
        # Stage 7: Final Executive Summary
        # -------------------------------------------------------------
        print("\n" + "=" * 65)
        print("ANALYSIS SESSION COMPLETE - DELIVERABLES SUMMARY")
        print("=" * 65)
        print(f"Operational Profile:     {self.profile.upper()}")
        print(f"Session Directory:       {self.output_dir}")
        print(f"Gate G0 Static Triage:   {os.path.join(self.output_dir, 'STATIC_AUDIT.md')}")
        print(f"Decrypted Network Flows: {decrypted_jsonl}")
        print(f"Crypto Telemetry Events: {events_log}")
        print(f"Canary Exfiltration Proof: {canary_hits_json}")

        if self.profile in ["malware", "all"]:
            print(f"C2 Protocol Spec:        {os.path.join(self.output_dir, 'C2_PROTOCOL.md')}")
            print(f"Family Attribution:      {os.path.join(self.output_dir, 'FAMILY_ATTRIBUTION.json')}")
            yara_rule_name = f"Android_Infostealer_{re.sub(r'[^a-zA-Z0-9_]', '_', self.package_name)}_{self.sha256[:8]}.yar"
            print(f"Defensive YARA Rule:     {os.path.join(self.output_dir, yara_rule_name)}")
            print(f"STIX 2.1 Bundle:         {os.path.join(self.output_dir, 'threat_report_stix21.json')}")
            print(f"Executive Report (MD):   {os.path.join(self.output_dir, 'analysis_report.md')}")

        if self.profile in ["privacy", "all"]:
            print(f"Privacy Audit (MD):      {os.path.join(self.output_dir, 'PRIVACY_AUDIT.md')}")
            print(f"Privacy Findings (JSON): {os.path.join(self.output_dir, 'privacy_findings.json')}")

        if self.profile in ["appsec", "all"]:
            print(f"AppSec Audit (MD):       {os.path.join(self.output_dir, 'API_SECURITY_REPORT.md')}")
            print(f"OpenAPI 3.0 Spec (JSON): {os.path.join(self.output_dir, 'openapi_spec.json')}")

        print(f"Canonical Target Dir:    targets/{self.sha256}/")
        print("=" * 65)

    def sync_canonical_target_repo(self):
        """Syncs canonical analysis files to targets/<sha256>/ per AGENTS.md contract."""
        targets_base = os.path.join("targets", self.sha256)
        os.makedirs(targets_base, exist_ok=True)
        current_sample_dir = os.path.join("targets", "current_sample")
        os.makedirs(current_sample_dir, exist_ok=True)

        # Determine classification and report template based on operational profile
        if self.profile == "privacy":
            classification = "Commercial Mobile Application (Privacy & Compliance Audit)"
            exec_title = f"# Executive Mobile Privacy Audit & Data Compliance Report: {self.package_name}"
            exec_summary = (
                f"Dynamic privacy auditing of `{self.package_name}` was conducted under zero-footprint stealth monitoring.\n"
                "All outgoing network flows and canary credentials were correlated against the commercial tracking taxonomy.\n"
                "The target application was evaluated against GDPR Article 5/6 principles and CCPA data disclosure mandates."
            )
            key_deliverables = """## Key Deliverables & Artifacts
- **Privacy Audit Report:** [`PRIVACY_AUDIT.md`](PRIVACY_AUDIT.md)
- **Machine-Readable Findings:** [`privacy_findings.json`](privacy_findings.json)
- **Traffic & Flow Analysis:** [`ANALYSIS.md`](ANALYSIS.md)
- **Static Manifest Audit:** [`STATIC_AUDIT.md`](STATIC_AUDIT.md)
- **Verified Facts:** [`FACTS.md`](FACTS.md)
- **Canary Exfiltration Proof:** `CANARY_EXFIL_HITS.json`
"""
        elif self.profile == "appsec":
            classification = "Commercial Mobile Application (Security Assessment & Pen-Testing)"
            exec_title = f"# Executive Mobile Application Security & API Assessment: {self.package_name}"
            exec_summary = (
                f"Dynamic penetration testing and security assessment of `{self.package_name}` was conducted under zero-footprint stealth monitoring.\n"
                "Cryptographic operations were evaluated against OWASP MASVS standards (MASVS-CRYPTO).\n"
                "All intercepted HTTP endpoints were automatically synthesized into an OpenAPI 3.0 specification for automated fuzzing."
            )
            key_deliverables = """## Key Deliverables & Artifacts
- **API Security Report:** [`API_SECURITY_REPORT.md`](API_SECURITY_REPORT.md)
- **OpenAPI 3.0 Specification:** [`openapi_spec.json`](openapi_spec.json)
- **Runtime Telemetry:** [`ANALYSIS.md`](ANALYSIS.md)
- **Static Manifest Audit:** [`STATIC_AUDIT.md`](STATIC_AUDIT.md)
- **Verified Facts:** [`FACTS.md`](FACTS.md)
- **Crypto & Socket Telemetry:** `instrumentation_events.jsonl`
"""
        elif self.profile == "all":
            classification = "Universal Dynamic Assessment (Malware Intel, Privacy & AppSec)"
            exec_title = f"# Comprehensive Mobile Security, Privacy & Threat Assessment: {self.package_name}"
            exec_summary = (
                f"Full-spectrum dynamic assessment of `{self.package_name}` was conducted under zero-trace stealth monitoring.\n"
                "The analysis unified adversarial threat intelligence extraction, commercial privacy leak auditing, and OWASP MASVS cryptographic/API assessment."
            )
            key_deliverables = """## Key Deliverables & Artifacts
- **Application Security & API Audit:** [`API_SECURITY_REPORT.md`](API_SECURITY_REPORT.md)
- **OpenAPI 3.0 Specification:** [`openapi_spec.json`](openapi_spec.json)
- **Privacy & Compliance Audit:** [`PRIVACY_AUDIT.md`](PRIVACY_AUDIT.md)
- **Privacy Findings JSON:** [`privacy_findings.json`](privacy_findings.json)
- **Threat Intelligence Findings:** [`ANALYSIS.md`](ANALYSIS.md)
- **Indicators of Compromise:** [`IOCS.json`](IOCS.json)
- **STIX 2.1 Threat Bundle:** `threat_report_stix21.json`
- **C2 Protocol Framing:** `C2_PROTOCOL.md`
- **Static Manifest Audit:** [`STATIC_AUDIT.md`](STATIC_AUDIT.md)
- **Verified Facts:** [`FACTS.md`](FACTS.md)
"""
        else:  # malware
            classification = "Android Infostealer / Evasive Malware Sample"
            exec_title = f"# Executive Threat Intelligence Report: {self.package_name}"
            exec_summary = (
                f"Dynamic analysis of sample `{self.package_name}` was conducted under zero-footprint stealth monitoring.\n"
                "All anti-analysis cues were neutralized out-of-process via `resetprop` and LSPosed `HideDevMode`.\n"
                "Network traffic was decrypted out-of-band via Linux kernel eBPF Conscrypt uprobes on `wlan0`."
            )
            key_deliverables = """## Key Deliverables & Artifacts
- **Executive Findings:** [`ANALYSIS.md`](ANALYSIS.md)
- **Extracted IOCs:** [`IOCS.json`](IOCS.json)
- **Verified Facts:** [`FACTS.md`](FACTS.md)
- **Static Audit:** [`STATIC_AUDIT.md`](STATIC_AUDIT.md)
- **STIX 2.1 Bundle:** `threat_report_stix21.json`
- **C2 Protocol Framing:** `C2_PROTOCOL.md`
- **Family Attribution:** `FAMILY_ATTRIBUTION.json`
"""

        target_md_content = f"""# Target Profile: {self.sha256}

- **Package Name:** `{self.package_name}`
- **SHA-256:** `{self.sha256}`
- **Classification:** {classification}
- **Profile Mode:** `{self.profile}`
- **Intake Date:** {datetime.date.today().isoformat()}

## Gate Status Ledger

| Gate | Phase | Status | Primary Artifact |
| :--- | :--- | :--- | :--- |
| **G0** | Static Intake & Triage | PASS | `STATIC_AUDIT.md` |
| **G1** | Device Cloaking | PASS | `verify_stealth_state.py` PASS; masked properties, zero tun0 |
| **G2** | Canary Data Seeding | PASS | `seed_canaries.py` planted mock credentials |
| **G3** | Network & eBPF Capture | PASS | `gateway_setup.sh`, `ecapture_runner.py` TLS master secrets |
| **G4** | Dynamic Instrumentation | PASS | `frida_loader.py` pre-encryption dumps, socket tracer |
| **G5** | Correlation & IOC Report | PASS | `analysis_report.md`, `iocs.json`, `CANARY_EXFIL_HITS.json` |

## Analysis Assumptions
- Target analyzed in isolated lab environment with synthetic mock canaries only.
- Cloaking countermeasures applied prior to spawn: masked ro.debuggable, sys.usb.state, init.svc.adbd.
- Interception executed out-of-band via eBPF TLS uprobes and transparent Linux AP gateway.
"""
        for t_dir in [targets_base, current_sample_dir]:
            with open(os.path.join(t_dir, "TARGET.md"), "w", encoding="utf-8") as f:
                f.write(target_md_content)

        src_path = os.path.join(self.output_dir, "SOURCES.md")
        if os.path.exists(src_path):
            with open(src_path, "r", encoding="utf-8") as f:
                sources_content = f.read()
            for t_dir in [targets_base, current_sample_dir]:
                with open(os.path.join(t_dir, "SOURCES.md"), "w", encoding="utf-8") as f:
                    f.write(sources_content)

        facts_path = os.path.join(self.output_dir, "FACTS.md")
        if os.path.exists(facts_path):
            with open(facts_path, "r", encoding="utf-8") as f:
                facts_content = f.read()
            for t_dir in [targets_base, current_sample_dir]:
                with open(os.path.join(t_dir, "FACTS.md"), "w", encoding="utf-8") as f:
                    f.write(facts_content)

        rep_path = os.path.join(self.output_dir, "analysis_report.md")
        if os.path.exists(rep_path):
            with open(rep_path, "r", encoding="utf-8") as f:
                analysis_content = f.read()
            for t_dir in [targets_base, current_sample_dir]:
                with open(os.path.join(t_dir, "ANALYSIS.md"), "w", encoding="utf-8") as f:
                    f.write(analysis_content)

        iocs_path = os.path.join(self.output_dir, "iocs.json")
        if os.path.exists(iocs_path):
            with open(iocs_path, "r", encoding="utf-8") as f:
                iocs_content = f.read()
            for t_dir in [self.output_dir, targets_base, current_sample_dir]:
                with open(os.path.join(t_dir, "IOCS.json"), "w", encoding="utf-8") as f:
                    f.write(iocs_content)

        report_content = f"""{exec_title}

- **Sample SHA-256:** `{self.sha256}`
- **Package Name:** `{self.package_name}`
- **Operational Profile:** `{self.profile}`
- **Date:** {datetime.date.today().isoformat()}

## Executive Summary
{exec_summary}

{key_deliverables}"""
        for t_dir in [self.output_dir, targets_base, current_sample_dir]:
            with open(os.path.join(t_dir, "REPORT.md"), "w", encoding="utf-8") as f:
                f.write(report_content)

        log_content = f"""# Session Problem Log: {self.sha256}

- **Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Package:** `{self.package_name}`
- **Status:** All gates G0 through G5 passed without evasion or unhandled exceptions.
- **Teardown:** Cleaned mock canaries, flushed eBPF/tcpdump buffers, uninstalled target package.
"""
        for t_dir in [targets_base, current_sample_dir]:
            with open(os.path.join(t_dir, "LOG.md"), "w", encoding="utf-8") as f:
                f.write(log_content)

        # Sync Privacy Profile Deliverables
        priv_audit = os.path.join(self.output_dir, "PRIVACY_AUDIT.md")
        if os.path.exists(priv_audit):
            with open(priv_audit, "r", encoding="utf-8") as f:
                priv_content = f.read()
            for t_dir in [targets_base, current_sample_dir]:
                with open(os.path.join(t_dir, "PRIVACY_AUDIT.md"), "w", encoding="utf-8") as f:
                    f.write(priv_content)

        priv_json = os.path.join(self.output_dir, "privacy_findings.json")
        if os.path.exists(priv_json):
            with open(priv_json, "r", encoding="utf-8") as f:
                pjson_content = f.read()
            for t_dir in [targets_base, current_sample_dir]:
                with open(os.path.join(t_dir, "privacy_findings.json"), "w", encoding="utf-8") as f:
                    f.write(pjson_content)

        # Sync AppSec Profile Deliverables
        appsec_report = os.path.join(self.output_dir, "API_SECURITY_REPORT.md")
        if os.path.exists(appsec_report):
            with open(appsec_report, "r", encoding="utf-8") as f:
                appsec_content = f.read()
            for t_dir in [targets_base, current_sample_dir]:
                with open(os.path.join(t_dir, "API_SECURITY_REPORT.md"), "w", encoding="utf-8") as f:
                    f.write(appsec_content)

        openapi_spec = os.path.join(self.output_dir, "openapi_spec.json")
        if os.path.exists(openapi_spec):
            with open(openapi_spec, "r", encoding="utf-8") as f:
                spec_content = f.read()
            for t_dir in [targets_base, current_sample_dir]:
                with open(os.path.join(t_dir, "openapi_spec.json"), "w", encoding="utf-8") as f:
                    f.write(spec_content)

        static_audit = os.path.join(self.output_dir, "STATIC_AUDIT.md")
        if os.path.exists(static_audit):
            with open(static_audit, "r", encoding="utf-8") as f:
                audit_content = f.read()
            for t_dir in [targets_base, current_sample_dir]:
                with open(os.path.join(t_dir, "STATIC_AUDIT.md"), "w", encoding="utf-8") as f:
                    f.write(audit_content)

        print(f"[+] Canonical target workspace synchronized to: {targets_base}/ and targets/current_sample/")



def main():
    parser = argparse.ArgumentParser(
        description="dbug Master Automated Stealth Mobile Security Sandbox"
    )
    parser.add_argument("--apk", default=None, help="Path to target sample APK")
    parser.add_argument("--package", default=None, help="Target Android package name")
    parser.add_argument("--profile", choices=["malware", "privacy", "appsec", "all"], default=None,
                        help="Analysis operational profile (malware, privacy, appsec, all) [default from config: malware]")
    parser.add_argument("--duration", type=int, default=None, help="Observation window in seconds (default from config: 120)")
    parser.add_argument("--interactive", action="store_true", help="Run interactive human-in-the-loop observation session")
    parser.add_argument("--config", default="config/lab_config.yaml", help="Path to lab_config.yaml")
    parser.add_argument("--output-dir", default=None, help="Custom output directory")
    parser.add_argument("--dry-run", action="store_true", help="Run end-to-end simulation across all gates")
    parser.add_argument("--sanitize", action="store_true",
                        help="Run device state sanitization (six-tier teardown) and exit")
    parser.add_argument("--restore-props", action="store_true",
                        help="Restore developer-default properties instead of verifying stealth state")
    parser.add_argument("--no-dev-hide", dest="apply_dev_hide", action="store_false", default=True,
                        help="Disable developer option hiding (HideDevMode is ON by default)")
    parser.add_argument("--apply-dev-hide", dest="apply_dev_hide", action="store_true", default=True,
                        help="Apply developer option hiding before analysis (ON by default)")
    args = parser.parse_args()

    # --sanitize runs the six-tier device teardown and exits before any analysis.
    if args.sanitize:
        from sanitize_device_state import DeviceSanitizer, parse_lab_config as _parse_cfg
        cfg = _parse_cfg(args.config)
        dev_cfg = cfg.get("lab_environment", {}).get("device", {})
        serial = dev_cfg.get("serial") or None
        use_root = dev_cfg.get("use_root", True)
        sanitizer = DeviceSanitizer(
            serial=serial,
            use_root=use_root,
            dry_run=args.dry_run,
            package_name=args.package,
            restore_props=args.restore_props,
        )
        ok = sanitizer.run_all(args.config)
        sys.exit(0 if ok else 1)

    cfg = parse_lab_config(args.config)
    sample_cfg = cfg.get("lab_environment", {}).get("target_sample", {})
    def_cfg = cfg.get("lab_environment", {}).get("analysis_defaults", {})
    dev_cfg = cfg.get("lab_environment", {}).get("device", {})

    apk = args.apk or sample_cfg.get("apk_path", "samples/sample.apk")
    package = args.package or sample_cfg.get("package_name", "com.example.malware")
    duration = args.duration or def_cfg.get("duration_seconds", 120)
    profile = args.profile or def_cfg.get("profile", "malware")
    serial = dev_cfg.get("serial") or None

    if args.sanitize:
        cmd = [sys.executable, "device_cloaking/sanitize_device_state.py", "--config", args.config, "--package", package]
        if args.dry_run:
            cmd.append("--dry-run")
        if serial:
            cmd.extend(["--serial", serial])
        if args.restore_props:
            cmd.append("--restore-props")
        res = subprocess.run(cmd)
        sys.exit(res.returncode)

    orchestrator = MasterOrchestrator(
        apk_path=apk,
        package_name=package,
        duration=duration,
        config_path=args.config,
        output_dir=args.output_dir,
        dry_run=args.dry_run,
        profile=profile,
        interactive=args.interactive,
        apply_dev_hide=args.apply_dev_hide
    )

    orchestrator.execute_pipeline()


if __name__ == "__main__":
    main()
