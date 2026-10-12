#!/usr/bin/env python3
"""reWork helper CLI (stdlib only).

    python tools/rw.py init <slug> [--name N] [--goal G]   create targets/<slug>/ from templates/
    python tools/rw.py doctor                              report which RE tools are installed
    python tools/rw.py hash <file> [--slug S]              size + SHA-256 (+ XAPK/APK info); append to SOURCES.md
    python tools/rw.py recon <dir> [--slug S] [--libs]     grep recipe pack over a decompiled tree -> recon.md
    python tools/rw.py lint [--root DIR]                   fail on vendor artifacts, emoji, secret-looking strings
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SLUG_RX = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")


# --- init ------------------------------------------------------------------------------------------
def cmd_init(a, root=ROOT):
    if not SLUG_RX.match(a.slug):
        print("slug must be lowercase letters, digits, dashes (max 41 chars)", file=sys.stderr)
        return 2
    dest = os.path.join(root, "targets", a.slug)
    if os.path.exists(dest):
        print("targets/%s already exists" % a.slug, file=sys.stderr)
        return 1
    subs = {"slug": a.slug, "name": a.name or a.slug, "goal": a.goal or "(fill in)",
            "date": datetime.date.today().isoformat()}
    os.makedirs(dest)
    tdir = os.path.join(root, "templates")
    for fn in sorted(os.listdir(tdir)):
        text = open(os.path.join(tdir, fn), encoding="utf-8").read()
        for k, v in subs.items():
            text = text.replace("{{%s}}" % k, v)
        open(os.path.join(dest, fn), "w", encoding="utf-8").write(text)
    for d in ("artifacts", "work", "decompiled"):
        os.makedirs(os.path.join(dest, d))
    print("created targets/%s (artifacts/, work/, decompiled/ are git-ignored)" % a.slug)
    return 0


# --- doctor ----------------------------------------------------------------------------------------
TOOLS = [("python3", ["python3", "--version"], True), ("git", ["git", "--version"], True),
         ("unzip", ["unzip", "-v"], True), ("curl", ["curl", "--version"], True),
         ("java", ["java", "-version"], False), ("jadx", ["jadx", "--version"], False),
         ("apktool", ["apktool", "--version"], False), ("ffmpeg", ["ffmpeg", "-version"], False),
         ("tshark", ["tshark", "--version"], False), ("adb", ["adb", "version"], False)]


def cmd_doctor(a):
    home = os.path.expanduser("~/tools")
    extra = os.pathsep.join([os.path.join(home, "jdk", "bin"), os.path.join(home, "jadx", "bin"), os.path.join(home, "apktool")])
    env = dict(os.environ, PATH=extra + os.pathsep + os.environ.get("PATH", ""))
    missing_required = 0
    for name, cmd, required in TOOLS:
        if not shutil.which(name, path=env["PATH"]):
            print("%-8s MISSING%s" % (name, " (required)" if required else ""))
            missing_required += required
            continue
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=20, env=env)
            line = ((out.stdout or "") + (out.stderr or "")).strip().splitlines()
            print("%-8s ok  %s" % (name, line[0][:70] if line else ""))
        except Exception as e:  # noqa: BLE001
            print("%-8s error %s" % (name, e))
    for mod in ("bleak", "PIL", "unicorn", "capstone", "elftools"):
        try:
            __import__(mod)
            print("%-8s ok  (python module)" % mod)
        except ImportError:
            print("%-8s absent (python module, optional)" % mod)
    if missing_required:
        return 1
    print("run tools/setup-tools.sh to install jdk, jadx, apktool without sudo")
    return 0


# --- hash ------------------------------------------------------------------------------------------
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def describe(path):
    """Extra identity lines for zip-like artifacts."""
    notes = []
    if not zipfile.is_zipfile(path):
        return notes
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        notes.append("zip entries: %d" % len(names))
        if "manifest.json" in names:
            try:
                m = json.loads(z.read("manifest.json"))
                for k in ("package_name", "name", "version_name", "version_code", "min_sdk_version", "target_sdk_version"):
                    if k in m:
                        notes.append("%s: %s" % (k, m[k]))
                notes.append("splits: %s" % ", ".join(sorted(s.get("id", "?") for s in m.get("split_apks", []))[:12]))
            except Exception:  # noqa: BLE001
                notes.append("manifest.json unreadable")
        apks = [n for n in names if n.endswith(".apk")]
        if apks:
            notes.append("inner apks: %s" % ", ".join(apks[:12]))
        libs = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2})
        if libs:
            notes.append("native ABIs: %s" % ", ".join(libs))
        v1 = [n for n in names if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC"))]
        if names and any(n.endswith("AndroidManifest.xml") for n in names):
            notes.append("v1 signature files: %s" % (", ".join(v1) if v1 else "none (likely v2/v3 signing, unverified)"))
    return notes


def cmd_hash(a, root=ROOT):
    if not os.path.isfile(a.file):
        print("no such file: %s" % a.file, file=sys.stderr)
        return 1
    size, digest = os.path.getsize(a.file), sha256(a.file)
    notes = describe(a.file)
    print("file: %s\nsize: %d\nsha256: %s" % (os.path.basename(a.file), size, digest))
    for n in notes:
        print(n)
    if a.slug:
        path = os.path.join(root, "targets", a.slug, "SOURCES.md")
        if not os.path.isfile(path):
            print("targets/%s/SOURCES.md not found (run init)" % a.slug, file=sys.stderr)
            return 1
        row = "- %s | %s bytes | sha256 %s | %s | recorded %s\n" % (
            os.path.basename(a.file), size, digest, "; ".join(notes) or "no zip info", datetime.date.today().isoformat())
        text = open(path, encoding="utf-8").read()
        marker = "<!-- rw.py hash appends below -->\n"
        text = text.replace(marker, marker + row, 1) if marker in text else text + row
        open(path, "w", encoding="utf-8").write(text)
        print("appended to targets/%s/SOURCES.md" % a.slug)
    return 0


# --- recon -----------------------------------------------------------------------------------------
LIB_PARTS = ("androidx/", "android/support/", "kotlin/", "kotlinx/", "okhttp3/", "okio/", "com/google/", "retrofit2/",
             "com/squareup/", "org/apache/", "io/reactivex/", "com/bumptech/", "com/facebook/", "org/jetbrains/", "dagger/")
RECIPES = [
    ("ble-api", r"BluetoothGattCallback|writeCharacteristic|requestMtu|setCharacteristicNotification|BluetoothLeScanner|ScanFilter|setWriteType|connectGatt"),
    ("uuid-literal", r"UUID\.fromString\(\s*\"[0-9a-fA-F-]{4,36}\"|0000[0-9a-fA-F]{4}-0000-1000-8000-00805[fF]9[bB]34[fF][bB]"),
    ("socket-http", r"new Socket\(|ServerSocket|getOutputStream|DatagramSocket|HttpURLConnection|WifiNetworkSpecifier|WifiManager|NsdManager"),
    ("url", r"https?://[A-Za-z0-9._-]+(?::\d+)?[/A-Za-z0-9._~:?#@!$&'()*+,;=%-]*"),
    ("ip-port", r"\b(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b|\bPORT\w*\s*=\s*\d{2,5}"),
    ("usb-serial", r"UsbManager|UsbDevice|UsbSerial|SerialPort|bulkTransfer|BluetoothSocket|createRfcommSocket"),
    ("crypto", r"Cipher\.getInstance|SecretKeySpec|MessageDigest\.getInstance|\bHmac|\bCRC(?:8|16|32)\b|Mac\.getInstance"),
    ("native-load", r"System\.loadLibrary|System\.load\(|native\s+\w+[\[\]\w<>]*\s+\w+\("),
    ("stored-key", r"MMKV|getSharedPreferences|PreferenceManager|DataStore|encodeString|decodeString|putString\(|getString\("),
    ("bytes-literal", r"new byte\[\]\s*\{\s*(?:\(byte\)\s*)?-?(?:0x)?[0-9a-fA-F]{1,3}\s*,"),
    ("json-field", r"@SerializedName\(\"[^\"]+\"\)|@Json\(name"),
    ("manifest", r"android\.permission\.(?:BLUETOOTH\w*|NEARBY_WIFI_DEVICES|CHANGE_WIFI_STATE|ACCESS_FINE_LOCATION|USB\w*|FOREGROUND_SERVICE\w*)"),
]
SCAN_EXT = (".java", ".kt", ".smali", ".xml", ".json", ".js", ".txt")


def cmd_recon(a, root=ROOT):
    if not os.path.isdir(a.dir):
        print("no such directory: %s" % a.dir, file=sys.stderr)
        return 1
    rx = [(n, re.compile(p)) for n, p in RECIPES]
    hits = {n: {"app": [], "lib": []} for n, _ in rx}
    counts = {n: [0, 0] for n, _ in rx}
    for dp, dn, fns in os.walk(a.dir):
        dn.sort()
        for fn in sorted(fns):
            if not fn.endswith(SCAN_EXT):
                continue
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, a.dir).replace(os.sep, "/")
            is_lib = any(p in rel for p in LIB_PARTS)
            try:
                with open(full, encoding="utf-8", errors="replace") as fh:
                    lines = fh.read().splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines, 1):
                if len(line) > 600:
                    continue
                for n, r in rx:
                    if r.search(line):
                        counts[n][is_lib] += 1
                        bucket = hits[n]["lib" if is_lib else "app"]
                        if len(bucket) < a.limit:
                            bucket.append("%s:%d: %s" % (rel, i, line.strip()[:160]))
    out = ["# Recon: %s" % a.dir, "", "Generated by `tools/rw.py recon`. A map, not findings: every line needs reading in context and an evidence tag.", "",
           "| Recipe | App hits | Library hits |", "|---|---|---|"]
    out += ["| %s | %d | %d |" % (n, counts[n][0], counts[n][1]) for n, _ in rx]
    for n, _ in rx:
        out += ["", "## %s" % n]
        for label, key in (("app code", "app"), ("bundled libraries", "lib")):
            if hits[n][key] and (key == "app" or a.libs):
                out += ["", "### %s (first %d)" % (label, len(hits[n][key])), "```"] + hits[n][key] + ["```"]
    text = "\n".join(out) + "\n"
    if a.slug:
        dest = os.path.join(root, "targets", a.slug, "work", "recon.md")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        open(dest, "w", encoding="utf-8").write(text)
        print("wrote %s" % os.path.relpath(dest, root))
    else:
        print(text)
    for n, _ in rx:
        print("%-14s app=%-6d lib=%d" % (n, counts[n][0], counts[n][1]))
    return 0


# --- lint ------------------------------------------------------------------------------------------
ARTIFACT_EXT = (".apk", ".xapk", ".apks", ".aab", ".ipa", ".dex", ".jar", ".so", ".odex", ".vdex", ".art")
SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache"}
GITIGNORED_PARTS = ("/artifacts/", "/work/", "/decompiled/")
TEXT_EXT = {".md", ".py", ".sh", ".js", ".html", ".yml", ".yaml", ".toml", ".txt", ".json", ".cfg", ""}
EMOJI = [(0x1F000, 0x1FAFF), (0x2600, 0x27BF), (0x2B50, 0x2B55), (0xFE0F, 0xFE0F), (0x200D, 0x200D)]
SECRET_RX = re.compile(r"AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----|(?:token|secret|api[_-]?key)\s*[=:]\s*['\"][A-Za-z0-9_\-]{24,}['\"]", re.I)


def tracked_files(root):
    try:
        out = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True).stdout.split("\n")
        files = [f for f in out if f]
        if files:
            return files
    except Exception:  # noqa: BLE001
        pass
    files = []
    for dp, dn, fns in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for fn in fns:
            rel = os.path.relpath(os.path.join(dp, fn), root).replace(os.sep, "/")
            if not any(("/" + rel).find(p) >= 0 and rel.startswith("targets/") for p in GITIGNORED_PARTS):
                files.append(rel)
    return files


def lint(root):
    problems = []
    for rel in tracked_files(root):
        low = rel.lower()
        if low.endswith(ARTIFACT_EXT):
            problems.append((rel, "vendor artifact extension, must not be committed"))
            continue
        if any(p in "/" + rel for p in GITIGNORED_PARTS) and rel.startswith("targets/"):
            problems.append((rel, "inside a git-ignored work directory"))
            continue
        ext = os.path.splitext(rel)[1].lower()
        if ext not in TEXT_EXT or rel.endswith("package-lock.json") or rel == "tools/rw.py" or rel.startswith("tests/"):
            continue
        try:
            text = open(os.path.join(root, rel), encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if any(a <= ord(c) <= b for c in line for a, b in EMOJI):
                problems.append(("%s:%d" % (rel, i), "emoji"))
            if SECRET_RX.search(line):
                problems.append(("%s:%d" % (rel, i), "secret-looking string"))
    return problems


def cmd_lint(a):
    problems = lint(a.root)
    for where, what in problems:
        print("%s: %s" % (where, what))
    print("lint: %d problem(s)" % len(problems))
    return 1 if problems else 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("init"); s.add_argument("slug"); s.add_argument("--name"); s.add_argument("--goal")
    sub.add_parser("doctor")
    s = sub.add_parser("hash"); s.add_argument("file"); s.add_argument("--slug")
    s = sub.add_parser("recon"); s.add_argument("dir"); s.add_argument("--slug"); s.add_argument("--libs", action="store_true")
    s.add_argument("--limit", type=int, default=15)
    s = sub.add_parser("lint"); s.add_argument("--root", default=ROOT)
    a = p.parse_args(argv)
    return {"init": cmd_init, "doctor": cmd_doctor, "hash": cmd_hash, "recon": cmd_recon, "lint": cmd_lint}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
