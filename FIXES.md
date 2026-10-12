# Fixes

Things that need fixing in reWork itself (tools, templates, skills), and things already fixed. Add to Open when you find something; move to Fixed with what was wrong and what changed. Same commit as the change.

## Open
- Skills and tools are untested end to end on a real target; run the benchmark in README.md and record gaps here.
- `tools/setup_tools.py` pins jadx and apktool versions and verifies SHA-256 only when `JADX_SHA256`/`APKTOOL_SHA256` are set (it prints the computed hashes); the JDK is the latest 17. Pin real hashes once a machine with github access has downloaded them.
- Windows is untested locally: CI covers `rebuild_analysis.py` and `setup_tools.py`, but the fake-jadx tests skip there and a real run on Windows has not happened. macOS is likewise untested locally (the JDK bundle layout is unit tested).
- The ipa and firmware kinds of `rebuild_analysis.py` verify the hash only.
- Cloud sessions: apkpure, adoptium and github release hosts are blocked unless the environment allows them (README, AGENTS.md).
- iOS, desktop and firmware notes in the skills are thin.

## Fixed
- Hardware recon had no reusable form that a weaker agent could follow: added `templates/tasks/` (README, SW-RECON, HW-RECON, ASSUMPTIONS, STATUS) copied by `rw.py init`, the `re-hardware-recon` skill, `tools/notify_log.py`, `tools/make_test_media.py`, and rules in `re-client-sim` (log pushed status, no-delta option) and `AGENTS.md` (writing for weaker agents). Derived from the reBeamBox task pack.
- Rebuild and setup were bash-only (`sha256sum`, `declare -A`, linux-x64 JDK URL), so they failed on macOS and Windows: rewrote both in Python 3 standard library (`rebuild_analysis.py`, `setup_tools.py`), kept the .sh files as wrappers, added OS/arch detection, the macOS JDK bundle layout, zsh PATH line, apktool.bat, and tests.
- jadx was OOM-killed on small machines and the cap lived only in the log: `rebuild_analysis.py` takes `--max-heap`/`JADX_HEAP` and defaults to 3g under 8 GiB RAM; an OOM kill now says so.
- `?version=latest` URLs break the hash check on a new release: `--url` overrides the download URL.
- No script rebuilt a target's artifacts and decompiled tree on another machine: added `tools/rebuild-analysis.sh` (SOURCES driven, hash-verified, idempotent), a machine-readable block in `templates/SOURCES.md`, and pinned jadx and apktool in setup-tools.
