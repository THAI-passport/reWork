#!/usr/bin/env python3
"""test_framework_e2e.py: Comprehensive Automated End-to-End Test Suite for dbug.

Verifies all pipeline stages, tool interfaces, defensive telemetry generators,
parsers, and threat intelligence exporters across Gates G0 through G5.
Designed to run in offline/CI environments with 100% test reproducibility.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

try:
    import frida as _frida  # noqa: F401
    _HAVE_FRIDA = True
except Exception:
    _HAVE_FRIDA = False


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
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "analysis_profile.json")))

            with open(os.path.join(tmp_dir, "STATIC_AUDIT.md"), "r") as f:
                audit_md = f.read()
                self.assertIn("## 5. Emulated Native AArch64 Strings (Gate G0)", audit_md)

            with open(os.path.join(tmp_dir, "analysis_profile.json"), "r") as f:
                profile = json.load(f)
                self.assertIn("target", profile)
                self.assertIn("hook_recommendations", profile)
                self.assertIn("detected_cues", profile)
                self.assertIn("emulated_native_strings", profile)
                self.assertIn("risk_score", profile)
                self.assertTrue(profile["hook_recommendations"].get("settings_global_spoofing"))
                self.assertTrue(profile["hook_recommendations"].get("procfs_spoofing"))

    def test_04_native_aarch64_emulator(self):
        """Gate G0: Test AArch64 native string decryptor emulation."""
        res = self.run_cmd([PYTHON_BIN, "sample_triage/native_emulator.py", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("AARCH64 NATIVE STRING DECRYPTION EMULATION", res.stdout)
        self.assertIn("https://api.telegram.org/bot", res.stdout)

    @unittest.skipIf(os.name == "nt", "shell scripts target Linux/macOS; not run on Windows")
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
            # Check canonical template target (always synced regardless of hash)
            target_dir = os.path.join(WORKSPACE_DIR, "targets", "current_sample")
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

    def test_17_device_state_sanitizer(self):
        """Sanitizer: Test six-tier device state teardown in dry-run mode."""
        res = self.run_cmd([
            PYTHON_BIN, "sanitize_device_state.py",
            "--dry-run"
        ])
        self.assertEqual(res.returncode, 0)
        self.assertIn("Tier 1", res.stdout)
        self.assertIn("Tier 2", res.stdout)
        self.assertIn("Tier 3", res.stdout)
        self.assertIn("Tier 4", res.stdout)
        self.assertIn("Tier 5", res.stdout)
        self.assertIn("Tier 6", res.stdout)
        self.assertIn("pristine baseline", res.stdout)

    @unittest.skipIf(os.name == "nt", "shell scripts target Linux/macOS; not run on Windows")
    def test_18_hide_dev_options_dry_run(self):
        """Sanitizer: Test hide_dev_options.sh dry-run mode."""
        res = self.run_cmd([
            "bash", "device_cloaking/hide_dev_options.sh", "--dry-run", "apply"
        ])
        self.assertEqual(res.returncode, 0)
        self.assertIn("[DRY-RUN]", res.stdout)

    def test_19_hide_devmode_preflight_layer(self):
        """Gate G1: Layer 6 LSPosed HideDevMode module audit is present and passes in dry-run."""
        res = self.run_cmd([
            PYTHON_BIN, "device_cloaking/verify_stealth_state.py", "--dry-run"
        ])
        self.assertEqual(res.returncode, 0)
        self.assertIn("Layer 6: Auditing LSPosed HideDevMode Module", res.stdout)
        self.assertIn("LSPosed module package", res.stdout)
        self.assertIn("simulated: INSTALLED, ENABLED", res.stdout)
        self.assertIn("ALL PRE-FLIGHT STEALTH CHECKS PASSED", res.stdout)

    def test_20_analysis_profile_handoff(self):
        """Gate G0 -> Gate G4: Test static profile consumption by FridaLoader."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            profile_path = os.path.join(tmp_dir, "analysis_profile.json")
            events_path = os.path.join(tmp_dir, "events.jsonl")
            mock_profile = {
                "target": {"package_name": "com.example.malware"},
                "detected_cues": ["adb_enabled", "TracerPid"],
                "hook_recommendations": {
                    "procfs_spoofing": True,
                    "settings_global_spoofing": True
                }
            }
            with open(profile_path, "w") as f:
                json.dump(mock_profile, f)

            res = self.run_cmd([
                PYTHON_BIN, "instrumentation/frida_loader.py",
                "--package", "com.example.malware",
                "--profile-json", profile_path,
                "--output", events_path,
                "--dry-run"
            ])
            self.assertEqual(res.returncode, 0)
            self.assertIn("Loaded Static Analysis Profile", res.stdout)
            self.assertIn("Hook Recommendation: Procfs status/maps cloaking ACTIVE", res.stdout)
            self.assertTrue(os.path.exists(events_path))

    def test_21_requirements_specification(self):
        """Packaging: Test requirements.txt exists and specifies core and emulation dependencies."""
        req_path = os.path.join(WORKSPACE_DIR, "requirements.txt")
        self.assertTrue(os.path.exists(req_path))
        with open(req_path, "r") as f:
            content = f.read()
            self.assertIn("pyyaml", content)
            self.assertIn("frida", content)
            self.assertIn("pyelftools", content)
            self.assertIn("unicorn", content)
            self.assertIn("capstone", content)

    def test_22_orchestrator_e2e_handoff(self):
        """Master: Test orchestrator pipeline end-to-end generates analysis_profile.json and passes all gates."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            res = self.run_cmd([
                PYTHON_BIN, "orchestrator.py",
                "--output-dir", tmp_dir,
                "--profile", "malware",
                "--duration", "1",
                "--dry-run"
            ])
            self.assertEqual(res.returncode, 0)
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "analysis_profile.json")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "STATIC_AUDIT.md")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "instrumentation_events.jsonl")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "REPORT.md")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "IOCS.json")))

    @unittest.skipUnless(_HAVE_FRIDA, "frida not installed (tool-dependent; lab machine only)")
    def test_23_frida_module_available(self):
        """Frida Integration: Test frida Python module imports and exposes a usable version."""
        import frida
        self.assertIsNotNone(frida.__version__)
        self.assertTrue(frida.__version__.startswith(("16.", "17.")))

    @unittest.skipUnless(_HAVE_FRIDA, "frida not installed (tool-dependent; lab machine only)")
    def test_24_frida_device_manager(self):
        """Frida Integration: Test frida device manager enumerates devices (no Android required)."""
        import frida
        mgr = frida.get_device_manager()
        devices = mgr.enumerate_devices()
        self.assertIsInstance(devices, list)
        self.assertGreaterEqual(len(devices), 1)

    @unittest.skipUnless(_HAVE_FRIDA, "frida not installed (tool-dependent; lab machine only)")
    def test_25_frida_loader_no_device_graceful(self):
        """Frida Integration: Test loader exits gracefully when frida-server is not reachable."""
        res = self.run_cmd([
            PYTHON_BIN, "instrumentation/frida_loader.py",
            "--package", "com.example.malware",
            "--duration", "1",
        ], check=False)
        # No frida-server on 127.0.0.1:38921 -> spawn fails, returns nonzero, no crash
        self.assertNotEqual(res.returncode, None)
        self.assertNotEqual(res.returncode, 0)
        self.assertTrue(
            "frida-server" in res.stderr or "Failed to connect" in res.stderr or "Failed to spawn" in res.stderr,
            "Expected a frida-server/connection error in stderr, got: %s" % res.stderr,
        )


if __name__ == "__main__":
    unittest.main()
