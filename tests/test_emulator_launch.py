import contextlib
import io
import os
import stat
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import emulator_launch  # noqa: E402


def run_main(argv):
    buf = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        code = emulator_launch.main(argv)
    return code, buf.getvalue(), err.getvalue()


class DryRunLaunch(unittest.TestCase):
    def test_dry_run_launch_prints_tcp_serial(self):
        code, out, err = run_main(["launch", "--avd", "Pixel_6_API_34",
                                   "--tcp-port", "5557", "--dry-run"])
        self.assertEqual(code, 0, err)
        self.assertIn("SERIAL: 127.0.0.1:5557", out)
        self.assertIn("[DRY-RUN] adb -s emulator-5554 tcpip 5557", out)
        self.assertIn("[DRY-RUN] adb connect 127.0.0.1:5557", out)
        self.assertIn("[+] Stealth cloaking simulated", out)
        self.assertIn("[+] Stealth verification simulated", out)

    def test_dry_run_launch_default_tcp_port(self):
        code, out, _ = run_main(["launch", "--avd", "Pixel_6_API_34", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("SERIAL: 127.0.0.1:5557", out)

    def test_dry_run_launch_no_avd_allowed(self):
        # dry-run does not require a real AVD or emulator binary
        code, out, _ = run_main(["launch", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("(no --avd given)", out)

    def test_launch_requires_avd_when_not_dry_run(self):
        with self.assertRaises(emulator_launch.EmulatorLauncherError):
            run_main(["launch"])

    def test_dry_run_stop_verify_restore_status(self):
        for cmd in (["stop", "--serial", "127.0.0.1:5557", "--dry-run"],
                    ["verify", "--serial", "127.0.0.1:5557", "--dry-run"],
                    ["restore", "--serial", "127.0.0.1:5557", "--dry-run"],
                    ["status", "--serial", "127.0.0.1:5557", "--dry-run"]):
            code, out, err = run_main(cmd)
            self.assertEqual(code, 0, "%s failed: %s" % (cmd, err))

    def test_list_avds_dry_run(self):
        code, out, _ = run_main(["list-avds", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("Pixel_6_API_34", out)
        self.assertIn("Pixel_7_API_33", out)

    def test_no_stealth_flag(self):
        code, out, _ = run_main(["launch", "--avd", "Pixel_6_API_34",
                                 "--no-stealth", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("Stealth cloaking disabled", out)
        self.assertNotIn("[DRY-RUN]   device_cloaking/apply_stealth_props.sh apply", out)


class LauncherMethods(unittest.TestCase):
    def test_tcpip_connect_dry_run_sets_serial(self):
        launcher = emulator_launch.EmulatorLauncher(
            avd="Pixel_6_API_34", tcp_port=5599, dry_run=True)
        serial = launcher.tcpip_connect()
        self.assertEqual(serial, "127.0.0.1:5599")
        self.assertEqual(launcher.tcp_serial, "127.0.0.1:5599")

    def test_emulator_cmd_headless_flags(self):
        launcher = emulator_launch.EmulatorLauncher(avd="A", dry_run=True)
        cmd = launcher._emulator_cmd()
        self.assertEqual(cmd[0], "emulator")
        self.assertIn("-avd", cmd)
        self.assertIn("A", cmd)
        self.assertIn("-no-window", cmd)
        self.assertIn("-gpu", cmd)
        self.assertIn("off", cmd)

    def test_run_dry_run_returns_zero(self):
        code, out = emulator_launch.run(["adb", "devices"], dry_run=True)
        self.assertEqual(code, 0)
        self.assertEqual(out, "")

    def test_find_tool_missing_returns_none(self):
        self.assertIsNone(emulator_launch.find_tool("definitely-not-a-real-tool-xyz"))


class DeviceScriptTests(unittest.TestCase):
    def test_emulator_stealth_script_exists_and_executable(self):
        path = os.path.join(ROOT, "device_cloaking", "apply_emulator_stealth.sh")
        self.assertTrue(os.path.isfile(path))
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertTrue(mode & stat.S_IXUSR, "script must be executable")


if __name__ == "__main__":
    unittest.main()
