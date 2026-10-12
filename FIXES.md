# Fixes

Things that need fixing in reWork itself (tools, templates, skills), and things already fixed. Add to Open when you find something; move to Fixed with what was wrong and what changed. Same commit as the change.

## Open
- Skills and tools are untested end to end on a real target; run the benchmark in README.md and record gaps here.
- `tools/setup-tools.sh` pins jadx and apktool versions but verifies no checksums and still fetches the latest JDK 17; add SHA-256 checks.
- `tools/rebuild-analysis.sh` download (network) path has no automated test; only `--local-file` is covered. It was run end to end only for an apk and xapk target; the ipa and firmware kinds verify the hash only.
- iOS, desktop and firmware notes in the skills are thin.

## Fixed
- No script rebuilt a target's artifacts and decompiled tree on another machine: added `tools/rebuild-analysis.sh` (SOURCES driven, hash-verified, idempotent), a machine-readable block in `templates/SOURCES.md`, and pinned jadx and apktool in setup-tools.
