"""tools/rebuild-analysis.sh: argument parsing, SOURCES parsing and the hash safety paths, all offline."""
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(ROOT, "tools", "rebuild_analysis.py")
HAVE = True
PY = sys.executable


def sha(b):
    return hashlib.sha256(b).hexdigest()


class Rebuild(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.t = os.path.join(self.d, "targets", "demo")
        os.makedirs(self.t)

    def make_xapk(self):
        p = os.path.join(self.d, "fake.xapk")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("app.apk", b"fake base")
            z.writestr("config.arm64_v8a.apk", b"fake abi")
        return p

    def sources(self, name="SOURCES", **over):
        x = self.xapk = self.make_xapk()
        f = dict(NAME_FILE="fake.xapk", VERSION="1.0", KIND="xapk", URL="http://127.0.0.1:9/never",
                 SHA256=sha(open(x, "rb").read()), INNER_APK="app.apk", INNER_SHA256=sha(b"fake base"),
                 ABI_APK="config.arm64_v8a.apk", ABI_SHA256=sha(b"fake abi"), JADX_VERSION="1.5.6")
        f.update(over)
        body = "".join("%s=%s\n" % (k, v) for k, v in f.items() if v is not None)
        if name == "SOURCES.md":
            body = "# Sources\n\n| a | b |\n\n<!-- rebuild:begin -->\n# comment\n" + body + "<!-- rebuild:end -->\n\ntext\nBAD LINE OUTSIDE\n"
        open(os.path.join(self.t, name), "w").write(body)
        return x

    def tools(self, version="1.5.6", rc=0):
        if sys.platform == "win32":
            self.skipTest("fake jadx/java are shell scripts")
        b = os.path.join(self.d, "bin")
        os.makedirs(b, exist_ok=True)
        open(os.path.join(b, "jadx"), "w").write(
            '#!/bin/sh\nif [ "$1" = "--version" ]; then echo %s; exit 0; fi\n'
            'while [ $# -gt 0 ]; do [ "$1" = "-d" ] && mkdir -p "$2/sources"; shift; done\n'
            'echo "ran $JAVA_OPTS" >> "%s/calls"\nexit %d\n' % (version, self.d, rc))
        open(os.path.join(b, "java"), "w").write("#!/bin/sh\necho 'openjdk version \"17.0.1\" 2024-01-01' >&2\n")
        for f in os.listdir(b):
            os.chmod(os.path.join(b, f), os.stat(os.path.join(b, f)).st_mode | stat.S_IEXEC)
        return b

    def run_(self, *args, path=None, plain=False):
        env = dict(os.environ, HOME=os.path.join(self.d, "home"), JAVA_HOME=os.path.join(self.d, "nojdk"))
        if path:
            env["PATH"] = path + os.pathsep + env["PATH"]
        if plain:
            env["PATH"] = "/usr/bin:/bin"
        return subprocess.run([PY, SCRIPT, "--root", self.d, *args], capture_output=True, text=True, env=env)

    def calls(self):
        p = os.path.join(self.d, "calls")
        return open(p).read().count("ran") if os.path.exists(p) else 0

    # arguments and sources -----------------------------------------------------------------------------------
    def test_help_and_bad_arguments(self):
        r = subprocess.run([PY, SCRIPT, "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        for w in ("--accept-new-hash", "--dry-run", "--recover", "SOURCES"):
            self.assertIn(w, r.stdout)
        for args, msg in ((["--bogus"], "unknown option"), ([], "target name required"), (["a", "b"], "only one target"),
                          (["--local-file"], "needs a value"), (["Bad_Name"], "lowercase")):
            r = subprocess.run([PY, SCRIPT, *args], capture_output=True, text=True)
            self.assertEqual(r.returncode, 2, args)
            self.assertIn(msg, r.stderr)

    def test_missing_target_and_sources(self):
        self.assertIn("no such target", self.run_("nope").stderr)
        self.assertIn("no SOURCES", self.run_("demo").stderr)
        self.sources()
        r = self.run_("demo", "--local-file", os.path.join(self.d, "missing"))
        self.assertEqual(r.returncode, 2)
        self.assertIn("--local-file not found", r.stderr)

    def test_sources_validation(self):
        for over, msg in ((dict(VERSION=None), "missing VERSION"), (dict(SHA256="ABC"), "lowercase 64-digit"),
                          (dict(KIND="zip"), "KIND must be"), (dict(INNER_APK=None), "needs INNER_APK"),
                          (dict(NAME_FILE="../x"), "must not contain"), (dict(ABI_SHA256=None), "needs ABI_SHA256")):
            self.sources(**over)
            r = self.run_("demo", "--dry-run")
            self.assertEqual(r.returncode, 2, over)
            self.assertIn(msg, r.stderr)

    def test_markdown_block_is_read_and_text_outside_is_ignored(self):
        x = self.sources(name="SOURCES.md")
        r = self.run_("demo", "--dry-run", "--local-file", x)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("sha256 ok: artifact", r.stdout)

    def test_sources_are_parsed_not_executed(self):
        x = self.sources()
        marker = os.path.join(self.d, "pwned")
        open(os.path.join(self.t, "SOURCES"), "a").write("X=$(touch %s)\n" % marker)
        self.run_("demo", "--dry-run", "--local-file", x)
        self.assertFalse(os.path.exists(marker))

    # hash safety ---------------------------------------------------------------------------------------------
    def test_artifact_hash_mismatch_refuses_and_writes_nothing(self):
        x = self.sources(SHA256="0" * 64)
        r = self.run_("demo", "--local-file", x, path=self.tools())
        self.assertEqual(r.returncode, 3)
        for w in ("sha256 mismatch for artifact", "expected: " + "0" * 64, "refusing to continue"):
            self.assertIn(w, r.stderr)
        self.assertEqual(sorted(os.listdir(self.t)), ["SOURCES"])

    def test_inner_apk_mismatch_refuses(self):
        x = self.sources(INNER_SHA256="1" * 64)
        r = self.run_("demo", "--local-file", x, path=self.tools())
        self.assertEqual(r.returncode, 3)
        self.assertIn("inner base APK", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.t, "BUILD-INFO.txt")))

    def test_accept_new_hash_continues_and_edits_nothing(self):
        x = self.sources(SHA256="0" * 64)
        before = open(os.path.join(self.t, "SOURCES")).read()
        r = self.run_("demo", "--local-file", x, "--accept-new-hash", path=self.tools())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("actual:   " + sha(open(x, "rb").read()), r.stderr)
        self.assertIn("no file was edited", r.stderr)
        self.assertEqual(open(os.path.join(self.t, "SOURCES")).read(), before)
        self.assertIn("accepted_new_hash=1", open(os.path.join(self.t, "BUILD-INFO.txt")).read())

    # behaviour -----------------------------------------------------------------------------------------------
    def test_dry_run_writes_nothing(self):
        x = self.sources()
        r = self.run_("demo", "--dry-run", "--local-file", x, path=self.tools())
        self.assertEqual(r.returncode, 0)
        self.assertIn("would run: jadx", r.stdout)
        self.assertEqual(sorted(os.listdir(self.t)), ["SOURCES"])
        self.assertEqual(self.calls(), 0)

    def test_full_run_and_idempotence(self):
        x = self.sources()
        tools = self.tools(rc=3)
        r = self.run_("demo", "--local-file", x, path=tools)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(open(os.path.join(self.t, "work", "app.apk"), "rb").read(), b"fake base")
        self.assertTrue(os.path.isdir(os.path.join(self.t, "decompiled", "sources")))
        info = open(os.path.join(self.t, "BUILD-INFO.txt")).read()
        for k in ("built_at=", "target=demo", "artifact_sha256=" + sha(open(x, "rb").read()), "jadx=1.5.6", "kind=xapk"):
            self.assertIn(k, info)
        self.assertEqual(self.calls(), 1)
        r = self.run_("demo", path=tools)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("already built", r.stdout)
        self.assertEqual(self.calls(), 1)
        self.assertEqual(self.run_("demo", "--force", "--local-file", x, path=tools).returncode, 0)
        self.assertEqual(self.calls(), 2)

    def test_plain_apk_kind(self):
        apk = os.path.join(self.d, "plain.apk")
        open(apk, "wb").write(b"plain apk bytes")
        self.sources(KIND="apk", NAME_FILE="plain.apk", SHA256=sha(b"plain apk bytes"), INNER_APK=None, INNER_SHA256=None,
                     ABI_APK=None, ABI_SHA256=None)
        r = self.run_("demo", "--local-file", apk, path=self.tools())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls(), 1)

    def test_other_kind_verifies_only(self):
        f = os.path.join(self.d, "fw.bin")
        open(f, "wb").write(b"firmware")
        self.sources(KIND="other", NAME_FILE="fw.bin", SHA256=sha(b"firmware"), INNER_APK=None, INNER_SHA256=None,
                     ABI_APK=None, ABI_SHA256=None)
        r = self.run_("demo", "--local-file", f)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no decompile", r.stdout)
        self.assertEqual(self.calls(), 0)

    def test_tool_pin_enforced_and_force_downgrades(self):
        x = self.sources()
        tools = self.tools(version="9.9.9")
        r = self.run_("demo", "--local-file", x, path=tools)
        self.assertEqual(r.returncode, 4)
        self.assertIn("jadx version is '9.9.9'", r.stderr)
        r = self.run_("demo", "--local-file", x, "--force", path=tools)
        self.assertEqual(r.returncode, 0)
        self.assertIn("warning: jadx version", r.stderr)

    def test_missing_tools_and_jadx_failure(self):
        x = self.sources()
        r = self.run_("demo", "--local-file", x, plain=True)
        self.assertEqual(r.returncode, 4)
        self.assertRegex(r.stderr, "java not found|jadx not found")
        r = self.run_("demo", "--local-file", x, path=self.tools(rc=1))
        self.assertEqual(r.returncode, 5)
        self.assertIn("jadx failed with exit 1", r.stderr)

    def test_missing_url_only_matters_when_a_download_is_needed(self):
        x = self.sources(URL=None)
        r = self.run_("demo", "--dry-run")
        self.assertEqual(r.returncode, 2)
        self.assertIn("no URL", r.stderr)
        self.assertEqual(self.run_("demo", "--local-file", x, path=self.tools()).returncode, 0)
        self.assertEqual(self.run_("demo", path=self.tools()).returncode, 0)     # artifact now present, no URL needed

    def test_heap_option_and_validation(self):
        x = self.sources()
        r = self.run_("demo", "--local-file", x, "--max-heap", "2g", path=self.tools())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("-Xmx2g", open(os.path.join(self.d, "calls")).read())
        r = self.run_("demo", "--local-file", x, "--max-heap", "lots", "--force", path=self.tools())
        self.assertEqual(r.returncode, 2)
        self.assertIn("heap must look like", r.stderr)

    def test_heap_from_sources_and_killed_jadx_hint(self):
        x = self.sources(JADX_HEAP="1g")
        r = self.run_("demo", "--local-file", x, path=self.tools(rc=137))
        self.assertEqual(r.returncode, 5)
        self.assertIn("-Xmx1g", open(os.path.join(self.d, "calls")).read())
        self.assertIn("out of memory", r.stderr)

    def test_url_override_downloads_and_verifies(self):
        x = self.sources(URL="http://127.0.0.1:9/never")
        moved = x + ".src"
        shutil.copyfile(x, moved)
        os.remove(x)
        url = ("file:///" + moved.replace(os.sep, "/").lstrip("/"))
        r = self.run_("demo", "--url", url, path=self.tools())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(os.path.join(self.t, "artifacts", "fake.xapk")))

    def test_recover_needs_a_class(self):
        x = self.sources()
        r = self.run_("demo", "--local-file", x, "--recover", path=self.tools())
        self.assertEqual(r.returncode, 2)
        self.assertIn("RECOVER_CLASS", r.stderr)

    def test_fallback_url_is_tried_when_first_download_has_wrong_hash(self):
        x = self.sources(URL=None)
        good = x + ".good"
        shutil.copyfile(x, good)
        os.remove(x)
        wrong = os.path.join(self.d, "wrong.bin")
        open(wrong, "wb").write(b"a newer release")
        with open(os.path.join(self.t, "SOURCES"), "a") as f:
            f.write("URL=file:///%s\nURL2=file:///%s\n" % (wrong.lstrip("/"), good.lstrip("/")))
        r = self.run_("demo", path=self.tools())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("trying the next URL", r.stdout)

    def test_mismatch_explains_the_version_in_the_downloaded_xapk(self):
        self.sources()
        newer = os.path.join(self.d, "newer.xapk")
        with zipfile.ZipFile(newer, "w") as z:
            z.writestr("manifest.json", '{"version_name": "9.9.9", "version_code": 99}')
        r = self.run_("demo", "--local-file", newer)
        self.assertEqual(r.returncode, 3)
        self.assertIn("9.9.9", r.stderr)
        self.assertIn("pins version 1.0", r.stderr)

    # repo wiring ---------------------------------------------------------------------------------------------
    def test_template_has_machine_readable_block_that_parses(self):
        text = open(os.path.join(ROOT, "templates", "SOURCES.md")).read()
        self.assertIn("<!-- rebuild:begin -->", text)
        self.assertIn("<!-- rebuild:end -->", text)
        for k in ("NAME_FILE", "VERSION", "KIND", "URL", "SHA256", "INNER_APK", "INNER_SHA256", "JADX_VERSION"):
            self.assertIn("# %s=" % k, text)

    def test_build_info_is_git_ignored_and_docs_reference_the_tool(self):
        self.assertIn("targets/*/BUILD-INFO.txt", open(os.path.join(ROOT, ".gitignore")).read())
        for rel in ("AGENTS.md", ".claude/skills/re-acquire/SKILL.md", ".claude/skills/re-workflow/SKILL.md", "README.md"):
            self.assertIn("rebuild-analysis.sh", open(os.path.join(ROOT, rel)).read(), rel)


if __name__ == "__main__":
    unittest.main()
