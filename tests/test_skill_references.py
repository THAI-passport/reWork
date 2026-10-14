"""The reference code bundled with skills must run, not only compile."""
import asyncio
import importlib.util
import os
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF = os.path.join(ROOT, ".claude", "skills", "re-client-sim", "references", "safe_write_and_link.py")
spec = importlib.util.spec_from_file_location("safe_ref", REF)
ref = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ref)


class GuardRef(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.g = ref.SafeWriteGuard(self.d, max_daily_writes=2, min_interval_sec=0)

    def test_delta_cap_and_no_delta(self):
        self.g.check("AA", b"x"); self.g.record_success("AA", b"x")
        with self.assertRaises(ref.GuardRefused):
            self.g.check("AA", b"x")
        self.g.check("AA", b"x", no_delta=True)
        self.g.record_success("AA", b"y")
        with self.assertRaises(ref.GuardRefused):
            self.g.check("AA", b"z")

    def test_dry_run_not_counted_and_corrupt_fails_closed(self):
        self.g.record_success("BB", b"x", dry_run=True)
        self.assertEqual(os.listdir(self.d), [])
        self.g.record_success("BB", b"x")
        open(os.path.join(self.d, os.listdir(self.d)[0]), "w").write("{bad")
        with self.assertRaises(ref.GuardRefused):
            self.g.check("BB", b"q")

    def test_recording_link(self):
        link = ref.RecordingLink(services=["180a"])
        asyncio.run(link.write("ae01", b"\x01"))
        self.assertEqual(link.writes, [("ae01", b"\x01", False)])


if __name__ == "__main__":
    unittest.main()
