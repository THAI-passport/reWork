#!/usr/bin/env python3
"""Rebuild a target's artifacts and decompiled tree from targets/<name>/SOURCES (or SOURCES.md). No sudo. Idempotent.
Pure Python 3 standard library: runs the same on Linux, macOS and Windows (tools/rebuild-analysis.sh is a thin wrapper).

Usage: tools/rebuild-analysis.sh <name> [options]      (or: python tools/rebuild_analysis.py <name> [options])
  --local-file PATH   use this artifact instead of downloading it (hash is still verified)
  --url URL           download from this URL instead of the URL in SOURCES (hash is still verified)
  --accept-new-hash   on a hash mismatch print the new hash and continue; never edits any file
  --recover           after jadx, run tools/recover-failed-methods.sh (needs RECOVER_CLASS or --recover-class; needs bash)
  --recover-class C   fully qualified class for --recover (overrides RECOVER_CLASS)
  --recover-dex D     dex name for --recover (overrides RECOVER_DEX, default classes.dex)
  --max-heap SIZE     JVM heap for jadx, for example 3g (overrides JADX_HEAP; default: 3g when the machine has under 8 GiB RAM)
  --force             redo every step; a tool version mismatch becomes a warning
  --dry-run           print what would happen; no download, extraction or decompile
  --root DIR          repository root (default: parent of tools/); used by tests
  -h, --help          this text
SOURCES fields (KEY=VALUE, one per line; in SOURCES.md only between <!-- rebuild:begin --> and <!-- rebuild:end -->):
  required: NAME_FILE (artifact file name), SHA256, VERSION; URL unless --local-file is used
  optional: COPY_LOCATION (where the owner-controlled exact copy lives, no secrets), KIND (apk, xapk or other; default apk), PACKAGE, INNER_APK + INNER_SHA256 (for xapk), ABI_APK + ABI_SHA256,
            JADX_VERSION, JAVA_MAJOR, JADX_ARGS (default "-j 4"), JADX_HEAP, RECOVER_CLASS, RECOVER_DEX
Exit codes: 0 ok, 2 usage or SOURCES error, 3 hash mismatch, 4 missing tool or tool version, 5 step failed.
Output (all git-ignored): targets/<name>/artifacts, work, decompiled, BUILD-INFO.txt.
"""
import datetime
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile

SELF_DIR = os.path.dirname(os.path.abspath(__file__))
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class Fail(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code, self.msg = code, msg


def say(msg):
    print("[rebuild] " + msg, flush=True)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()



def version_note(path, pinned):
    """If `path` is an XAPK with a manifest.json, say which version it really is (explains a hash mismatch after a vendor update)."""
    try:
        with zipfile.ZipFile(path) as z:
            m = json.loads(z.read("manifest.json"))
        return "the file says version_name=%s version_code=%s; SOURCES pins version %s" % (m.get("version_name"), m.get("version_code"), pinned)
    except Exception:  # noqa: BLE001
        return ""


def tool_path():
    """PATH with the user-space toolchain installed by tools/setup_tools.py in front (works on all platforms)."""
    home = os.path.expanduser("~/tools")
    java_home = os.environ.get("JAVA_HOME") or os.path.join(home, "jdk")
    extra = [os.path.join(java_home, "bin"), os.path.join(home, "jadx", "bin"), os.path.join(home, "apktool")]
    return os.pathsep.join(extra + [os.environ.get("PATH", "")])


def total_ram_gib():
    try:
        return os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / 2 ** 30
    except (AttributeError, ValueError, OSError):
        return None


def parse_sources(path, root):
    rel = os.path.relpath(path, root).replace(os.sep, "/")
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = [ln.rstrip("\r\n") for ln in f]
    has_markers = any(ln == "<!-- rebuild:begin -->" for ln in lines)
    inblock = not has_markers
    s = {}
    for line in lines:
        if line == "<!-- rebuild:begin -->":
            inblock = True
            continue
        if line == "<!-- rebuild:end -->":
            inblock = False
            continue
        if not inblock or not line or line.startswith("#") or line.startswith("```"):
            continue
        m = re.match(r"^([A-Z0-9_]+)=(.*)$", line)
        if not m:
            raise Fail(2, "bad line in %s: %s" % (rel, line))
        s[m.group(1)] = m.group(2)
    for k in ("NAME_FILE", "SHA256", "VERSION"):
        if not s.get(k):
            raise Fail(2, "%s: missing %s" % (rel, k))
    kind = s.get("KIND", "apk")
    if kind not in ("apk", "xapk", "other"):
        raise Fail(2, "KIND must be apk, xapk or other, got '%s'" % kind)
    if kind == "xapk":
        for k in ("INNER_APK", "INNER_SHA256"):
            if not s.get(k):
                raise Fail(2, "%s: KIND=xapk needs %s" % (rel, k))
    for k in ("SHA256", "INNER_SHA256", "ABI_SHA256"):
        if s.get(k) and not HEX64.match(s[k]):
            raise Fail(2, "%s: %s is not a lowercase 64-digit sha256" % (rel, k))
    if s.get("ABI_APK") and not s.get("ABI_SHA256"):
        raise Fail(2, "%s: ABI_APK needs ABI_SHA256" % rel)
    names = s["NAME_FILE"] + s.get("INNER_APK", "") + s.get("ABI_APK", "")
    if "/" in names or "\\" in names or ".." in names:
        raise Fail(2, "file names in SOURCES must not contain / or ..")
    return s, rel, kind


def pin_warnings(S):
    """Pinning rule: exact version, SHA-256, a versioned or mirrored URL and an owner-controlled copy."""
    w = []
    urls = [S[k] for k in ("URL", "URL2", "URL3", "URL4") if S.get(k)]
    if urls and all(re.search(r"latest", u, re.I) for u in urls):
        w.append("every URL looks like a floating 'latest' link; only the SHA-256 protects this pin. Add a versioned or mirrored URL as URL2 "
                 "and keep an owner-controlled copy (COPY_LOCATION).")
    if not S.get("COPY_LOCATION"):
        w.append("COPY_LOCATION is not set: note where the owner-controlled exact copy of the artifact lives (path or location, no secrets).")
    return w


def parse_args(argv):
    o = dict(target=None, local=None, url=None, accept=False, recover=False, force=False, dry=False,
             rclass="", rdex="", heap="", root=os.path.dirname(SELF_DIR), help=False)
    valued = {"--local-file": "local", "--url": "url", "--root": "root", "--recover-class": "rclass",
              "--recover-dex": "rdex", "--max-heap": "heap"}
    flags = {"--accept-new-hash": "accept", "--recover": "recover", "--force": "force", "--dry-run": "dry"}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            o["help"] = True
        elif a in valued:
            if i + 1 >= len(argv):
                raise Fail(2, "%s needs a value" % a)
            o[valued[a]] = argv[i + 1]
            i += 1
        elif a in flags:
            o[flags[a]] = True
        elif a.startswith("-"):
            raise Fail(2, "unknown option: %s (try --help)" % a)
        elif o["target"] is not None:
            raise Fail(2, "only one target name allowed (got '%s' and '%s')" % (o["target"], a))
        else:
            o["target"] = a
        i += 1
    return o


class Run:
    def __init__(self, o):
        self.o = o
        self.mismatch_accepted = False
        self.pinned = ""

    def verify(self, path, expected, label):
        got = sha256_file(path)
        if got == expected:
            say("sha256 ok: " + label)
            return
        sys.stderr.write("error: sha256 mismatch for %s\n  expected: %s\n  actual:   %s\n" % (label, expected, got))
        note = version_note(path, self.pinned)
        if note:
            sys.stderr.write("  note: %s. A moved 'latest' URL is the usual cause: find the exact file, then pass --local-file or add it as URL2.\n" % note)
        if self.o["accept"]:
            sys.stderr.write("  --accept-new-hash given: continuing for inspection only; this is not a pin and no file was edited. "
                             "A new vendor release needs a NEW pinned entry (new version, new hash); never edit the old hash. Tell the user.\n")
            return
        sys.stderr.write("  refusing to continue. Restore the pinned file (--local-file or URL2). If the vendor shipped a new release, add a NEW pinned "
                         "entry with the new version and hash; do not edit this hash. --accept-new-hash is for inspection only.\n")
        raise Fail(3, None)

    def download(self, url, dest):
        say("download " + url)
        if self.o["dry"]:
            say("would run: download %s -> %s" % (url, dest))
            return
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        part = dest + ".part"
        last = None
        for attempt in range(3):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=60) as r, open(part, "wb") as f:
                    shutil.copyfileobj(r, f, 1 << 20)
                os.replace(part, dest)
                return
            except Exception as e:  # noqa: BLE001
                last = e
                time.sleep(1 + attempt)
        raise Fail(5, "download failed: %s" % last)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        return rebuild(argv)
    except Fail as f:
        if f.msg:
            sys.stderr.write("error: %s\n" % f.msg)
        return f.code


def rebuild(argv):
    o = parse_args(argv)
    if o["help"]:
        print(__doc__.split("Usage: ", 1)[1].rstrip())
        return 0
    if not o["target"]:
        raise Fail(2, "target name required (try --help)")
    if not re.match(r"^[a-z0-9][a-z0-9-]*$", o["target"]):
        raise Fail(2, "target name must be lowercase letters, digits and dashes: %s" % o["target"])
    if o["local"] and not os.path.isfile(o["local"]):
        raise Fail(2, "--local-file not found: %s" % o["local"])
    root = os.path.abspath(o["root"])
    T = os.path.join(root, "targets", o["target"])
    if not os.path.isdir(T):
        raise Fail(2, "no such target: targets/%s (create it with: python tools/rw.py init %s)" % (o["target"], o["target"]))
    src = next((c for c in (os.path.join(T, "SOURCES"), os.path.join(T, "SOURCES.md")) if os.path.isfile(c)), None)
    if not src:
        raise Fail(2, "no SOURCES or SOURCES.md in targets/%s" % o["target"])
    S, srel, kind = parse_sources(src, root)
    for msg in pin_warnings(S):
        sys.stderr.write("warning: %s\n" % msg)
    r = Run(o)
    r.pinned = S["VERSION"]
    dry, force = o["dry"], o["force"]
    art = os.path.join(T, "artifacts", S["NAME_FILE"])
    W, OUT = os.path.join(T, "work"), os.path.join(T, "decompiled")
    jadx_args = shlex.split(S.get("JADX_ARGS", "-j 4"))
    env = dict(os.environ, PATH=tool_path())

    say("target %s %s (%s)" % (o["target"], S["VERSION"], kind))
    if dry:
        say("dry run: nothing will be written")

    # 1. acquire
    if o["local"]:
        fpath = o["local"]
        say("using local file " + fpath)
    elif os.path.isfile(art) and not force:
        fpath = art
        say("artifact already present: targets/%s/artifacts/%s" % (o["target"], S["NAME_FILE"]))
    else:
        urls = [o["url"]] if o["url"] else [S[k] for k in ("URL", "URL2", "URL3", "URL4") if S.get(k)]
        if not urls:
            raise Fail(2, "%s: no URL and %s not present (add URL or pass --local-file)" % (srel, "artifact"))
        for i, url in enumerate(urls):
            r.download(url, art)
            if dry or not os.path.isfile(art) or sha256_file(art) == S["SHA256"] or i + 1 == len(urls):
                break
            say("hash does not match the file from this URL; trying the next URL (%d of %d)" % (i + 2, len(urls)))
        fpath = art
    if os.path.isfile(fpath):
        r.verify(fpath, S["SHA256"], "artifact")
        if os.path.abspath(fpath) != os.path.abspath(art) and not dry:
            os.makedirs(os.path.dirname(art), exist_ok=True)
            shutil.copyfile(fpath, art)
    elif dry:
        say("(artifact not present yet; hash would be checked after download)")

    # 2. extract (xapk only) and pick the APK to decompile
    base, base_sha = None, S["SHA256"]
    if kind == "xapk":
        base = os.path.join(W, S["INNER_APK"])
        abi = os.path.join(W, S["ABI_APK"]) if S.get("ABI_APK") else None
        ok = (not force and os.path.isfile(base) and sha256_file(base) == S["INNER_SHA256"]
              and (abi is None or (os.path.isfile(abi) and sha256_file(abi) == S["ABI_SHA256"])))
        if ok:
            say("extracted APKs already present and verified")
        else:
            if not dry and not os.path.isfile(fpath):
                raise Fail(5, "artifact missing")
            members = [S["INNER_APK"]] + ([S["ABI_APK"]] if abi else [])
            say("extract %s into targets/%s/work" % (" ".join(members), o["target"]))
            if dry:
                say("would run: extract %s" % " ".join(members))
            else:
                os.makedirs(W, exist_ok=True)
                try:
                    with zipfile.ZipFile(fpath) as z:
                        names = z.namelist()
                        for m in members:
                            cand = [n for n in names if n == m or n.endswith("/" + m)]
                            if not cand:
                                raise KeyError(m)
                            with z.open(cand[0]) as src_f, open(os.path.join(W, m), "wb") as dst:
                                shutil.copyfileobj(src_f, dst)
                except (KeyError, zipfile.BadZipFile, OSError) as e:
                    raise Fail(5, "could not extract %s from the archive (%s)" % (" ".join(members), e))
                r.verify(base, S["INNER_SHA256"], "inner base APK")
                if abi:
                    r.verify(abi, S["ABI_SHA256"], "ABI split")
        base_sha = S["INNER_SHA256"]
    elif kind == "apk":
        base = fpath
    else:
        say("KIND=other: download and verify only, no decompile")

    # 3. tools and jadx (apk kinds only)
    jadx_v = java_v = ""
    if kind != "other":
        def tool_problem(msg):
            if force:
                sys.stderr.write("warning: %s\n" % msg)
            else:
                raise Fail(4, "%s (re-run with --force to accept, or fix with tools/setup-tools.sh)" % msg)
        if not dry:
            if not shutil.which("java", path=env["PATH"]):
                raise Fail(4, "java not found; run tools/setup-tools.sh")
            jadx = shutil.which("jadx", path=env["PATH"])
            if not jadx:
                raise Fail(4, "jadx not found; run tools/setup-tools.sh")
            out = subprocess.run([jadx, "--version"], capture_output=True, text=True, env=env)
            jadx_v = (out.stdout.strip().splitlines() or [""])[0].strip()
            jo = subprocess.run([shutil.which("java", path=env["PATH"]), "-version"], capture_output=True, text=True, env=env)
            java_v = (jo.stderr.strip().splitlines() or [""])[0]
            if S.get("JADX_VERSION") and jadx_v != S["JADX_VERSION"]:
                tool_problem("jadx version is '%s', SOURCES pins %s" % (jadx_v, S["JADX_VERSION"]))
            if S.get("JAVA_MAJOR") and ('"%s' % S["JAVA_MAJOR"]) not in java_v:
                tool_problem("java is '%s', SOURCES pins major %s" % (java_v, S["JAVA_MAJOR"]))
        else:
            say("tool check skipped in dry run (pins: jadx %s, java %s)" % (S.get("JADX_VERSION", "any"), S.get("JAVA_MAJOR", "any")))

        # heap: explicit option, then SOURCES, then a safe default on small machines (jadx was OOM-killed on shared boxes)
        heap = o["heap"] or S.get("JADX_HEAP", "")
        if not heap and "JAVA_OPTS" not in os.environ and "-Xmx" not in os.environ.get("JADX_OPTS", ""):
            ram = total_ram_gib()
            if ram is not None and ram < 8:
                heap = "3g"
        if heap:
            if not re.match(r"^[0-9]+[kKmMgG]$", heap):
                raise Fail(2, "heap must look like 3g or 2048m, got '%s'" % heap)
            env["JAVA_OPTS"] = ("%s -Xmx%s" % (env.get("JAVA_OPTS", ""), heap)).strip()
            say("jadx heap capped at -Xmx%s" % heap)

        mark = os.path.join(W, "jadx.done")
        done = False
        if not force and os.path.isdir(OUT) and os.path.isfile(mark):
            txt = open(mark, encoding="utf-8").read()
            done = ("base_sha256=%s" % base_sha) in txt and re.search(r"^exit=(0|3) ", txt, re.M) is not None
        if done:
            say("decompiled tree already built for this APK (use --force to redo)")
        else:
            cmd = ["jadx"] + jadx_args + ["-d", OUT, base]
            say("jadx %s -> targets/%s/decompiled" % (" ".join(jadx_args), o["target"]))
            if dry:
                say("would run: " + " ".join(cmd))
            else:
                os.makedirs(OUT, exist_ok=True)
                os.makedirs(W, exist_ok=True)
                cmd[0] = shutil.which("jadx", path=env["PATH"])
                start = time.time()
                with open(os.path.join(W, "jadx.log"), "w") as log:
                    rc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, env=env).returncode
                with open(mark, "w") as f:
                    f.write("exit=%d seconds=%d base_sha256=%s\n" % (rc, time.time() - start, base_sha))
                if rc in (0, 3):
                    say("jadx finished (exit %d)" % rc)
                else:
                    hint = ""
                    if rc in (137, -9):
                        hint = " (killed, probably out of memory: retry with --max-heap 2g, or free memory)"
                    raise Fail(5, "jadx failed with exit %d%s, see targets/%s/work/jadx.log" % (rc, hint, o["target"]))

        if o["recover"]:
            rc_cls = o["rclass"] or S.get("RECOVER_CLASS", "")
            rc_dex = o["rdex"] or S.get("RECOVER_DEX", "classes.dex")
            if not rc_cls:
                raise Fail(2, "--recover needs RECOVER_CLASS in SOURCES or --recover-class")
            if not shutil.which("bash"):
                raise Fail(4, "--recover needs bash (Git Bash or WSL on Windows)")
            say("CFR recovery of %s from %s" % (rc_cls, rc_dex))
            cmd = ["bash", os.path.join(SELF_DIR, "recover-failed-methods.sh"), base, rc_dex, rc_cls, os.path.join(W, "recover")]
            if dry:
                say("would run: " + " ".join(cmd))
            elif subprocess.run(cmd, env=env).returncode != 0:
                raise Fail(5, "recovery script failed")

    # 4. build info
    if not dry:
        lines = ["built_at=" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "target=" + o["target"], "version=" + S["VERSION"], "kind=" + kind,
                 "artifact_sha256=" + sha256_file(fpath)]
        if base and os.path.isfile(base):
            lines.append("base_apk_sha256=" + sha256_file(base))
        lines += ["accepted_new_hash=%d" % (1 if o["accept"] else 0), "recover=%d" % (1 if o["recover"] else 0),
                  "jadx=" + jadx_v, "java=" + java_v, "jadx_args=" + " ".join(jadx_args),
                  "host=%s %s" % (platform.system(), platform.machine())]
        with open(os.path.join(T, "BUILD-INFO.txt"), "w") as f:
            f.write("\n".join(lines) + "\n")
        say("wrote targets/%s/BUILD-INFO.txt" % o["target"])
    say("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
