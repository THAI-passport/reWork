---
name: re-acquire
description: Find, download, validate and hash the companion app, firmware or binary for a device. Covers going from a hardware model name to the app package, APKPure/APKMirror style mirrors, XAPK/split handling, integrity checks, provenance records, and what never to commit.
---

# re-acquire (gate G1)

## From hardware name to app
1. Search the model number plus words like "app", "companion", "APK", "user manual". The manual or box usually names the app and the QR code points to a store page.
2. The store page gives the package name (`id=` in a Play URL, bundle id on iOS). Search `<package>` for current version and hashes. FCC ID pages (fccid.io) list grantee, internal photos, chip; teardowns name the SoC. All of this is `[W]`.
3. Two models may share one app or use two. Record the mapping in FACTS.md with tags. If the app serves a whole family, its product list is often server-side: expect no model table in code.
4. Record every search that mattered (query, URL, date) in SOURCES.md so it can be repeated.

## Download
- Prefer an official site. Otherwise a reputable mirror (APKPure, APKMirror, Uptodown). Listing sites disagree on version and size; use them as hints only.
- APKPure direct pattern: `https://d.apkpure.com/b/APK/<package>?version=latest` redirects to a tokenised URL. First `curl -sIL -A "Mozilla/5.0"` to read size and filename, then download with `-o targets/<slug>/artifacts/<file>`. Strip tokens before writing URLs to docs.
- Large downloads exceed shell time limits: run in background, wait, read the log.
- Trust the file's own manifest over listing text.

## Validate (before any analysis)
1. `unzip -t file` reports no errors.
2. `.xapk` and `.apks` are zips: base APK plus split APKs (native libs per ABI, language, density) and `manifest.json`. Extract only the base APK first; extract the arm64 split only when native code matters.
3. Identity: `apktool d -s -f --no-res -o work/ap base.apk` then check `package=` in the manifest and versionName/versionCode in `apktool.yml`. Review permissions for anything out of character and note it.
4. No `META-INF/*.RSA|DSA` v1 files usually means v2/v3 signing; verify with `apksigner verify --print-certs` if available. Signature trust is otherwise unverified; say so.
5. If anything fails or looks malicious, stop and report. Never install or run the artifact.

## Record
`python tools/rw.py hash targets/<slug>/artifacts/<file> --slug <slug>` prints size and SHA-256 (and XAPK manifest fields) and appends a row to SOURCES.md. Add the inner base APK too. Run `python tools/rw.py lint` and confirm nothing vendor-owned is tracked (`git ls-files | grep -Ei 'apk|xapk|dex|\.so'` must be empty).

## Pin, do not float
- A "latest" link is a hint, not a source. After download and validation record exact version, SHA-256, a versioned or mirrored URL (`URL2`) and where the owner-controlled exact copy lives (`COPY_LOCATION`, no secrets).
- Rebuilds verify the pinned hash and refuse on mismatch. A new vendor release is a NEW pinned entry (new version, new hash); never edit the old hash. `--accept-new-hash` is for inspection only and the user must be told.

## Make it rebuildable
After hashing, fill the machine-readable block in `targets/<slug>/SOURCES.md` (template fields: NAME_FILE, VERSION, KIND, URL, SHA256, INNER_APK/INNER_SHA256 for an xapk, optional ABI split, tool pins). Then another machine, or a fresh container, can run:
`bash tools/rebuild-analysis.sh <slug> --dry-run` (plan), then `bash tools/rebuild-analysis.sh <slug>` (download, verify, extract, jadx, `targets/<slug>/BUILD-INFO.txt`).
- A hash mismatch stops the run (exit 3). `--accept-new-hash` prints the new hash and continues without editing anything; use it only after telling the user and checking why the file changed, then update SOURCES yourself.
- Several sources: `URL2` to `URL4` in the SOURCES block are tried in order after `URL`; the first whose file matches the pinned hash wins. Record a versioned or private mirror there, because vendor `latest` links move. On a mismatch the tool prints the version the downloaded XAPK reports against the pinned one; a different version means a new release, so re-audit claims instead of accepting the hash.
- `--local-file PATH` skips the download; `--force` redoes steps; `--recover` runs the CFR recovery for `RECOVER_CLASS`.
- If a target has no usable URL (login-gated), say so and ask the user for the file; do not guess.

## Other artifact kinds
- iOS: IPA is a zip; `Payload/*.app/Info.plist`; the binary is Mach-O (decrypt requirement means static analysis may be blocked; say so).
- Firmware images: record vendor URL and hash; use `binwalk`-style extraction only if the user owns the device.
- Desktop apps: installer hash, then unpack without running (7z, msiexec /a, dpkg -x).
