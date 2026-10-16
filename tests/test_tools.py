import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import btcap  # noqa: E402
import crcfind  # noqa: E402
import rw  # noqa: E402


def run(fn, argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        code = fn(argv)
    return code, buf.getvalue()


def sandbox():
    d = tempfile.mkdtemp()
    shutil.copytree(os.path.join(ROOT, "templates"), os.path.join(d, "templates"))
    return d


class InitHashLint(unittest.TestCase):
    def test_init_creates_workspace_and_substitutes(self):
        d = sandbox()
        a = type("A", (), dict(slug="t900", name="T900 watch", goal="sync steps"))
        self.assertEqual(rw.cmd_init(a, root=d), 0)
        text = open(os.path.join(d, "targets", "t900", "TARGET.md")).read()
        self.assertIn("T900 watch", text)
        self.assertIn("sync steps", text)
        self.assertNotIn("{{", text)
        self.assertTrue(os.path.isdir(os.path.join(d, "targets", "t900", "artifacts")))
        self.assertEqual(rw.cmd_init(a, root=d), 1)

    def test_bad_slug_rejected(self):
        a = type("A", (), dict(slug="Bad Slug", name=None, goal=None))
        self.assertEqual(rw.cmd_init(a, root=sandbox()), 2)

    def test_hash_records_xapk_manifest(self):
        d = sandbox()
        rw.cmd_init(type("A", (), dict(slug="x", name="x", goal="g")), root=d)
        xapk = os.path.join(d, "targets", "x", "artifacts", "app.xapk")
        with zipfile.ZipFile(xapk, "w") as z:
            z.writestr("manifest.json", '{"package_name":"com.example","version_name":"1.2","split_apks":[{"id":"base"}]}')
            z.writestr("com.example.apk", b"x")
        a = type("A", (), dict(file=xapk, slug="x"))
        self.assertEqual(rw.cmd_hash(a, root=d), 0)
        src = open(os.path.join(d, "targets", "x", "SOURCES.md")).read()
        self.assertIn("app.xapk", src)
        self.assertIn("sha256", src)

    def test_lint_flags_artifacts_and_emoji(self):
        d = tempfile.mkdtemp()
        open(os.path.join(d, "a.apk"), "wb").write(b"x")
        open(os.path.join(d, "n.md"), "w", encoding="utf-8").write("ok \U0001F600\n")
        probs = rw.lint(d)
        kinds = " ".join(w for _, w in probs)
        self.assertIn("artifact", kinds)
        self.assertIn("emoji", kinds)

    def test_repo_itself_is_lint_clean(self):
        self.assertEqual(rw.lint(ROOT), [])


class CliDispatch(unittest.TestCase):
    """Verify argparse CLI dispatch works end-to-end for every subcommand,
    including hash/recon which require setup_parser arguments."""

    def run_main(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = rw.main(argv)
        return code, buf.getvalue()

    def test_all_subcommands_dispatch(self):
        # init
        d = sandbox()
        code, _ = self.run_main(["init", "t900", "--name", "T900", "--goal", "cli test", "--root", d])
        self.assertEqual(code, 0)
        # hash
        xapk = os.path.join(d, "targets", "t900", "artifacts", "app.xapk")
        import zipfile
        with zipfile.ZipFile(xapk, "w") as z:
            z.writestr("manifest.json", '{"package_name":"com.example","version_name":"1.2"}')
        code, _ = self.run_main(["hash", xapk, "--slug", "t900", "--root", d])
        self.assertEqual(code, 0)
        # recon
        code, out = self.run_main(["recon", d, "--slug", "t900", "--limit", "2", "--root", d])
        self.assertEqual(code, 0)
        # lint
        code, _ = self.run_main(["lint", "--root", ROOT])
        self.assertEqual(code, 0)
        # doctor (may report missing optional tools, but exits 0)
        code, _ = self.run_main(["doctor"])
        self.assertEqual(code, 0)


class Recon(unittest.TestCase):
    def test_recon_splits_app_and_library(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "com", "vendor"))
        os.makedirs(os.path.join(d, "androidx", "x"))
        open(os.path.join(d, "com", "vendor", "A.java"), "w").write('UUID.fromString("0000fff0-0000-1000-8000-00805f9b34fb");\nsock = new Socket(host, 8080);\n')
        open(os.path.join(d, "androidx", "x", "B.java"), "w").write('gatt.writeCharacteristic(c);\n')
        a = type("A", (), dict(dir=d, slug=None, libs=False, limit=5))
        code, out = run(lambda _: rw.cmd_recon(a), None)
        self.assertEqual(code, 0)
        import re
        self.assertRegex(out, r"uuid-literal\s+app=1\s+lib=0")
        self.assertRegex(out, r"socket-http\s+app=1\s+lib=0")
        self.assertRegex(out, r"ble-api\s+app=0\s+lib=1")


class Crc(unittest.TestCase):
    def test_catalogue_check_values(self):
        for name, p in crcfind.CATALOG.items():
            self.assertEqual(crcfind.crc(b"123456789", *p[:6]), p[6], name)

    def test_identify(self):
        self.assertIn("CRC-16/CCITT-FALSE", crcfind.candidates([(b"123456789", 0x29B1)]))
        self.assertIn("CRC-32", crcfind.candidates([(b"123456789", 0xCBF43926)]))


class Capture(unittest.TestCase):
    def test_btcap_reads_synthetic_capture(self):
        path = os.path.join(HERE, "fixtures", "synthetic_gatt.btsnoop")
        rows = btcap.summarize(list(btcap.att_events(btcap.read_capture(path))))
        self.assertGreater(len(rows), 3)
        self.assertEqual({r["uuid"] for r in rows if r["kind"] == "W"}, {"01f1"})
        self.assertTrue(any(r["kind"] == "N" and r["uuid"] == "01f2" for r in rows))

    def test_rejects_non_capture(self):
        p = os.path.join(tempfile.mkdtemp(), "x")
        open(p, "wb").write(b"not a capture")
        with self.assertRaises(ValueError):
            btcap.read_capture(p)


if __name__ == "__main__":
    unittest.main()
