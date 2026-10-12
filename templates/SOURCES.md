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
Fill these in after G1 so another machine can rebuild the artifacts and the decompiled tree. Plain KEY=VALUE lines between the markers; the tool parses them and never executes them. No tokens or signed URLs.
<!-- rebuild:begin -->
# NAME_FILE=<artifact file name under targets/<slug>/artifacts>
# VERSION=<version name>
# KIND=apk | xapk | other
# URL=<public download URL, no token>
# URL2=<optional: versioned or private mirror of the same file, tried if URL gives another hash>
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
