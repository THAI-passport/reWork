# Sources: {{name}}

Artifacts are git-ignored and never committed. Static analysis only.

| Item | Value |
|---|---|
| Package / identifier | |
| Version (name / code) | |
| Source and URL (no tokens) | |
| File | |
| Size (bytes) | |
| SHA-256 | |
| Retrieved | |

## Machine-readable fields (read by tools/rebuild-analysis.sh)
Pinning rule: pin by version and SHA-256, never by a floating 'latest' link. A new vendor release is a NEW pinned entry (new version, new hash, new SOURCES), never an edit of the old hash. Fill these in after G1 so another machine can rebuild the artifacts and the decompiled tree. Plain KEY=VALUE lines between the markers; the tool parses them and never executes them. No tokens or signed URLs.
<!-- rebuild:begin -->
# NAME_FILE=<artifact file name under targets/<slug>/artifacts>
# VERSION=<version name>
# KIND=apk | xapk | other
# URL=<public download URL, no token>
# URL2=<versioned or mirrored URL of the same file (not a floating 'latest' link); tried if URL gives another hash>
# COPY_LOCATION=<where the owner-controlled exact copy lives: path or location, no secrets>
# SHA256=<sha256 of the downloaded file, lowercase>
# xapk only:
# INNER_APK=<base apk name inside the archive>
# INNER_SHA256=<sha256 of that base apk>
# ABI_APK=<optional native split name>
# ABI_SHA256=<its sha256>
# tool pins and options (optional):
# JADX_VERSION=<for example 1.5.6>
# JAVA_MAJOR=17
# JADX_ARGS=-j 4
# RECOVER_CLASS=<class for --recover>
# RECOVER_DEX=classes.dex
<!-- rebuild:end -->

## Auto-recorded hashes
<!-- rw.py hash appends below -->

## Searches that mattered
| Date | Query | URL | Result |
|---|---|---|---|
