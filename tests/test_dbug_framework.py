#!/usr/bin/env python3
"""test_framework_e2e.py: Comprehensive Automated End-to-End Test Suite for dbug.

Verifies all pipeline stages, tool interfaces, defensive telemetry generators,
parsers, and threat intelligence exporters across Gates G0 through G5.
Designed to run in offline/CI environments with 100% test reproducibility.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


PYTHON_BIN = sys.executable
WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestDbugFramework(unittest.TestCase):

    def run_cmd(self, cmd_args, check=True):
        """Helper to run a shell command inside the dbug workspace."""
        res = subprocess.run(
            cmd_args,
            cwd=WORKSPACE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if check and res.returncode != 0:
            print(f"FAILED: {' '.join(cmd_args)}\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}", file=sys.stderr)
        return res

    def test_01_canary_seeding_dry_run(self):
        """Gate G2: Test canary data injection, verification, and cleaning simulation."""
        # Test Seeding
        res = self.run_cmd([PYTHON_BIN, "config/seed_canaries.py", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("Total canary contacts seeded", res.stdout)
        self.assertIn("Canary seeding sequence finished successfully", res.stdout)

        # Test Verification
        res_v = self.run_cmd([PYTHON_BIN, "config/seed_canaries.py", "--verify", "--dry-run"])
        self.assertEqual(res_v.returncode, 0)
        self.assertIn("[DRY-RUN] Verification simulated SUCCESS", res_v.stdout)

        # Test Cleaning
        res_c = self.run_cmd([PYTHON_BIN, "config/seed_canaries.py", "--clean", "--dry-run"])
        self.assertEqual(res_c.returncode, 0)
        self.assertIn("Cleanup complete: Synthetic contacts, SMS, and clipboard cleared", res_c.stdout)

    def test_02_device_cloaking_preflight(self):
        """Gate G1: Test 5-layer stealth pre-flight audit in dry-run mode."""
        res = self.run_cmd([PYTHON_BIN, "device_cloaking/verify_stealth_state.py", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("ALL PRE-FLIGHT STEALTH CHECKS PASSED", res.stdout)
        self.assertIn("Layer 1: Auditing System Properties", res.stdout)
        self.assertIn("Layer 2: Auditing Settings.Global Developer Flags", res.stdout)
        self.assertIn("Layer 3: Auditing Network Hygiene", res.stdout)
        self.assertIn("Layer 4: Auditing Port Exposure", res.stdout)
        self.assertIn("Layer 5: Verifying ADB Transport Viability", res.stdout)

    def test_03_static_triage_apk(self):
        """Gate G0: Test static APK/DEX unpacking and anti-analysis auditor."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            res = self.run_cmd([
                PYTHON_BIN, "sample_triage/triage_apk.py",
                "--apk", "samples/sample.apk",
                "--package", "com.example.malware",
                "--output-dir", tmp_dir,
                "--dry-run"
            ])
            self.assertEqual(res.returncode, 0)
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "STATIC_AUDIT.md")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "TARGET.md")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "SOURCES.md")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "FACTS.md")))

    def test_04_native_aarch64_emulator(self):
        """Gate G0: Test AArch64 native string decryptor emulation."""
        res = self.run_cmd([PYTHON_BIN, "sample_triage/native_emulator.py", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("AARCH64 NATIVE STRING DECRYPTION EMULATION", res.stdout)
        self.assertIn("https://api.telegram.org/bot", res.stdout)

    def test_05_network_gateway_setup_script(self):
        """Gate G3: Test Linux Wi-Fi AP gateway shell manager."""
        res = self.run_cmd(["bash", "network_capture/gateway_setup.sh", "status", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("[DRY-RUN] Gateway status simulated: ACTIVE", res.stdout)

    def test_06_ecapture_runner_status(self):
        """Gate G3: Test static ARM64 eCapture eBPF uprobe runner."""
        res = self.run_cmd([PYTHON_BIN, "network_capture/ecapture_runner.py", "status", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("[DRY-RUN] eCapture status: ACTIVE", res.stdout)

    def test_07_frida_loader_dry_run(self):
        """Gate G4: Test custom-port Frida loader and telemetry stream simulation."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ev_file = os.path.join(tmp_dir, "events.jsonl")
            res = self.run_cmd([
                PYTHON_BIN, "instrumentation/frida_loader.py",
                "--package", "com.example.malware",
                "--duration", "1",
                "--output", ev_file,
                "--dry-run"
            ])
            self.assertEqual(res.returncode, 0)
            self.assertTrue(os.path.exists(ev_file))
            with open(ev_file, "r") as f:
                lines = f.readlines()
                self.assertGreater(len(lines), 0)
                first_event = json.loads(lines[0])
                self.assertIn("event", first_event)

    def test_08_pcap_decryptor(self):
        """Gate G5: Test TLS packet decryptor with synthetic flows."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            dec_file = os.path.join(tmp_dir, "decrypted.jsonl")
            res = self.run_cmd([
                PYTHON_BIN, "parser_correlator/pcap_decryptor.py",
                "--pcap", os.path.join(tmp_dir, "fake.pcap"),
                "--keylog", os.path.join(tmp_dir, "fake.keylog"),
                "--output", dec_file,
                "--dry-run"
            ])
            self.assertEqual(res.returncode, 0)
            self.assertTrue(os.path.exists(dec_file))

    def test_09_canary_hunter_multi_encoding(self):
        """Gate G5: Test multi-encoding canary correlation against mock data."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            hits_file = os.path.join(tmp_dir, "CANARY_EXFIL_HITS.json")
            events_file = os.path.join(tmp_dir, "events.jsonl")
            traffic_file = os.path.join(tmp_dir, "traffic.jsonl")

            # Write test synthetic event with base64 encoded canary
            with open(events_file, "w") as f:
                f.write(json.dumps({
                    "timestamp": 1729080000.0,
                    "event": "CIPHER_DOFINAL",
                    "algorithm": "AES/CBC/PKCS5Padding",
                    "plaintext_hex": "43414e4152595f534d535f4f54505f39393231" # CANARY_SMS_OTP_9921
                }) + "\n")

            with open(traffic_file, "w") as f:
                f.write(json.dumps({
                    "timestamp": 1729080001.0,
                    "src_ip": "10.42.0.50",
                    "dst_ip": "198.51.100.24",
                    "payload": "user_otp=Q0FOQVJZX1NNU19PVFBfOTkyMQ==" # base64 CANARY_SMS_OTP_9921
                }) + "\n")

            res = self.run_cmd([
                PYTHON_BIN, "parser_correlator/canary_hunter.py",
                "--canaries", "config/mock_canaries.json",
                "--events", events_file,
                "--traffic", traffic_file,
                "--output", hits_file
            ])
            self.assertEqual(res.returncode, 0)
            self.assertTrue(os.path.exists(hits_file))
            with open(hits_file, "r") as f:
                data = json.load(f)
                self.assertGreater(data.get("total_exfiltration_hits", 0), 0)
                self.assertGreater(len(data.get("hits", [])), 0)

    def test_10_c2_protocol_decoder(self):
        """Gate G5: Test C2 framing reconstruction and specification generation."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            traffic_file = os.path.join(tmp_dir, "decrypted_http_requests.jsonl")
            with open(traffic_file, "w") as f:
                f.write(json.dumps({
                    "uri": "https://api.telegram.org/bot6829104812:AAH9fCANARYTokenMockSecretKey/sendMessage",
                    "method": "POST",
                    "payload": '{"cmd":"bot_register","device":"pixel7"}'
                }) + "\n")

            proto_doc = os.path.join(tmp_dir, "C2_PROTOCOL.md")
            res = self.run_cmd([
                PYTHON_BIN, "parser_correlator/c2_protocol_decoder.py",
                "--session-dir", tmp_dir,
                "--package", "com.example.malware",
                "--output", proto_doc
            ])
            self.assertEqual(res.returncode, 0)
            self.assertTrue(os.path.exists(proto_doc))
            with open(proto_doc, "r") as f:
                content = f.read()
                self.assertIn("Command and Control (C2) Protocol Specification", content)
                self.assertIn("Telegram Bot API", content)

    def test_11_family_classifier(self):
        """Gate G5: Test behavioral malware family scoring."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            iocs_file = os.path.join(tmp_dir, "iocs.json")
            with open(iocs_file, "w") as f:
                json.dump({
                    "network_indicators": {"telegram_bot_tokens": ["6829104812:AAH9fCANARYTokenMockSecretKey"]},
                    "cryptography": {"observed_keys": [{"algorithm": "AES/CBC"}]}
                }, f)

            attr_file = os.path.join(tmp_dir, "FAMILY_ATTRIBUTION.json")
            res = self.run_cmd([
                PYTHON_BIN, "parser_correlator/family_classifier.py",
                "--session-dir", tmp_dir,
                "--package", "com.example.malware",
                "--output", attr_file
            ])
            self.assertEqual(res.returncode, 0)
            self.assertTrue(os.path.exists(attr_file))
            with open(attr_file, "r") as f:
                data = json.load(f)
                self.assertIn("attributed_family", data)
                self.assertGreater(data.get("confidence_percentage", 0), 0)

    def test_12_master_orchestrator_dry_run(self):
        """Master: Test full end-to-end multi-gate analysis pipeline."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            res = self.run_cmd([
                PYTHON_BIN, "orchestrator.py",
                "--output-dir", tmp_dir,
                "--duration", "1",
                "--dry-run"
            ])
            self.assertEqual(res.returncode, 0)
            self.assertIn("ANALYSIS SESSION COMPLETE - DELIVERABLES SUMMARY", res.stdout)
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "STATIC_AUDIT.md")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "C2_PROTOCOL.md")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "FAMILY_ATTRIBUTION.json")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "CANARY_EXFIL_HITS.json")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "iocs.json")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "threat_report_stix21.json")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "analysis_report.md")))

            # Verify target directory sync per AGENTS.md contract
            sample_hash = "4a8f9c01823901b2c3d4e5f6071829304a8f9c01823901b2c3d4e5f607182930"
            target_dir = os.path.join(WORKSPACE_DIR, "targets", sample_hash)
            self.assertTrue(os.path.exists(os.path.join(target_dir, "TARGET.md")))
            self.assertTrue(os.path.exists(os.path.join(target_dir, "SOURCES.md")))
            self.assertTrue(os.path.exists(os.path.join(target_dir, "FACTS.md")))
            self.assertTrue(os.path.exists(os.path.join(target_dir, "ANALYSIS.md")))
            self.assertTrue(os.path.exists(os.path.join(target_dir, "REPORT.md")))
            self.assertTrue(os.path.exists(os.path.join(target_dir, "LOG.md")))
            self.assertTrue(os.path.exists(os.path.join(target_dir, "IOCS.json")))

    def test_13_privacy_auditor(self):
        """Profile Privacy: Test mobile app tracker audit and PII leakage detection."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            res = self.run_cmd([
                PYTHON_BIN, "parser_correlator/privacy_auditor.py",
                "--session-dir", tmp_dir,
                "--package", "com.example.app"
            ])
            self.assertEqual(res.returncode, 0)
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "PRIVACY_AUDIT.md")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "privacy_findings.json")))
            with open(os.path.join(tmp_dir, "privacy_findings.json"), "r") as f:
                data = json.load(f)
                self.assertIn("overall_privacy_risk", data)
                self.assertIn("trackers", data)

    def test_14_appsec_auditor(self):
        """Profile AppSec: Test OWASP MASVS crypto audit and OpenAPI 3.0 specification synthesis."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            res = self.run_cmd([
                PYTHON_BIN, "parser_correlator/appsec_auditor.py",
                "--session-dir", tmp_dir,
                "--package", "com.example.bank"
            ])
            self.assertEqual(res.returncode, 0)
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "API_SECURITY_REPORT.md")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "openapi_spec.json")))
            with open(os.path.join(tmp_dir, "openapi_spec.json"), "r") as f:
                spec = json.load(f)
                self.assertEqual(spec.get("openapi"), "3.0.3")
                self.assertIn("paths", spec)

    def test_15_orchestrator_multi_profile(self):
        """Master: Test orchestrator execution with --profile all."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            res = self.run_cmd([
                PYTHON_BIN, "orchestrator.py",
                "--output-dir", tmp_dir,
                "--profile", "all",
                "--duration", "1",
                "--dry-run"
            ])
            self.assertEqual(res.returncode, 0)
            self.assertIn("Operational Profile:     ALL", res.stdout)
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "PRIVACY_AUDIT.md")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "API_SECURITY_REPORT.md")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "openapi_spec.json")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "C2_PROTOCOL.md")))

    def test_16_orchestrator_interactive_dry_run(self):
        """Master: Test orchestrator execution with --interactive in dry-run mode."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            res = self.run_cmd([
                PYTHON_BIN, "orchestrator.py",
                "--output-dir", tmp_dir,
                "--interactive",
                "--dry-run"
            ])
            self.assertEqual(res.returncode, 0)
            self.assertIn("Interactive capture session simulated", res.stdout)


if __name__ == "__main__":
    unittest.main()
