# Tooling log

Problems hit while building reWork's own tools (target problems go in `targets/<slug>/LOG.md`). Entry: date, area, problem, cause, solution. Newest last.

---

## 2026-10-12, tools/rebuild-analysis.sh: foreground jadx run killed
- Problem: running the script in an agent shell ended with "Killed" (exit 137) after about 60 s.
- Cause: memory pressure on a shared box (jadx stalled at 75 percent, then the process was killed); it was not the shell time limit, which was the first guess. A run with `JAVA_OPTS=-Xmx3g` finished in about 45 s.
- Solution: cap the heap with `JAVA_OPTS=-Xmx3g` when memory is tight, and run long decompiles detached (`setsid nohup ... &`) so the shell call does not hold them. The script treats exit 137 as failure and does not mark the tree as built.

## 2026-10-12, tools/rebuild-analysis.sh: silent exit when a tool is broken
- Problem: with a broken jadx on PATH the script exited 1 with no message.
- Cause: a failing command inside `$(... | head -1)` under `set -e` and pipefail ended the script before the version pin check.
- Solution: version lookups end with `|| true`, so the pin check reports exit 4 with a clear message.

## 2026-10-12, tools/rebuild-analysis.sh: copying a file onto itself
- Problem: `--local-file` pointing at the artifacts directory made `cp` fail with "same file".
- Cause: the copy into `targets/<slug>/artifacts` did not check for the same path.
- Solution: skip the copy when `-ef` says both paths are one file.

## 2026-10-12, rebuild and setup were not portable
- Problem: `rebuild-analysis.sh` used `sha256sum` and `declare -A`; `setup-tools.sh` fetched linux/x64 only and edited only ~/.bashrc. None of it ran on macOS (bash 3.2, no sha256sum) or Windows.
- Cause: bash chosen for convenience; GNU userland assumed.
- Solution: reimplemented in Python 3 standard library, shell files became wrappers; the 18 existing tests passed unchanged against the port before new tests were added. Status: Solved for Linux (tested here); macOS and Windows are covered by CI and unit tests only.

## 2026-10-12, cloud session cannot reach the download hosts
- Problem: from a cloud container, `d.apkpure.com` and `api.adoptium.net` are unreachable and github release URLs return 403, so a rebuild stops at the download.
- Cause: the environment network policy allows package managers and a short list of hosts.
- Solution: add the hosts under Allowed domains in the environment settings, or pass `--local-file`. Documented in AGENTS.md. Status: needs the user.

## 2026-10-12, hardware recon steps could not be run as written
- Problem: the first hardware checklist (in the reBeamBox project) contradicted its own safety tooling: an identical-rewrite test is skipped by the delta guard, the minimum interval and daily cap were not budgeted, the free-space number was never printed, and nothing said which steps a cloud agent can actually do.
- Cause: the checklist predated the guard and the first-contact tooling, and mixed background with procedure.
- Solution: generic task pack in `templates/tasks/`, a `re-hardware-recon` skill, a write-budget step, a no-delta option requirement, status-message logging requirement. Status: Solved in templates; untested on a real target.

## 2026-10-12, a hash mismatch after a vendor release gave no clue why
- Problem: SOURCES pins a hash but a vendor "latest" link moves; the rebuild stopped with two hashes and nothing else, and only one URL could be configured.
- Cause: one URL, no version information in the error.
- Solution: `rebuild_analysis.py` prints the version the downloaded XAPK reports against the pinned one and tries URL, URL2, URL3, URL4 in order. Tests added. Status: Solved.

## 2026-10-12, fresh instances rebuilt by reflex and findings were not written back
- Problem: a new agent's default was to download and decompile, which repeats work, and results of a pass were not recorded where the next agent looks.
- Cause: no rule said when a rebuild is justified or what to record afterwards.
- Solution: AGENTS.md "Rebuild only when necessary" and "After every decompile pass" (PROTOCOL, FACTS, LOG, matching skill = reWork's SOP), repeated in the re-static, re-acquire and re-workflow skills; QUICKSTART in the task-pack template; a test that scripts named in docs exist. Status: Solved as process.

## 2026-10-12, generic skills and knowledge were stranded in the watch fork
- Problem: three skills written in reWatch (Jieli family, finding transports in decompiled Android code, HCI capture ingestion) and a budget-wearables note are device-class generic but lived only in the fork.
- Cause: the fork was seeded before reWork collected them.
- Solution: copied `re-jieli`, `re-ble-android-patterns`, `re-capture-ingestion` into reWork, added `knowledge/` with the wearables note (labelled `[W]`), and a next-pass prompt in `docs/`. Status: Solved; the skills still cite one worked example by name and should be reviewed for further genericising.

## 2026-10-12, pinning: floating latest links
- Problem: a SOURCES file could pin a hash while its only URL was a floating "latest" link, and `--accept-new-hash` could be used to move on after a vendor update without a record, so the next machine would pin something else.
- Cause: the rebuild tool only checked hashes; nothing asked for a versioned URL, an owner-controlled copy or a new entry per release.
- Solution: AGENTS.md rule (pin by version and SHA-256, new release is a new pinned entry, never edit the old hash), `COPY_LOCATION` field and template text, warnings for a floating-only URL or a missing copy location, mismatch and accept messages that say so, tests.

## 2026-10-14, skill review: overlaps, missing generic rules, missing tools
- Problem: an external review of `.claude/skills/` found gate-only trigger text, the gate map and tag legend held only in AGENTS.md, generic unicorn rules buried in `re-jieli`, duplicated text between `re-static` and `re-ble-android-patterns`, and promised steps (scrub, flag check) with no tool behind them. Its proposed tag legend redefined `[W]` and `[V]` and added `[C-SDK]`, which would have contradicted AGENTS.md.
- Cause: skills grew per target; generic lessons stayed where they were first learned.
- Solution: see FIXES.md "Skill suite review". The legend stays as in AGENTS.md; SDK code is `[C]` with an "SDK:" note. First flag-check attempt only read fenced blocks and found nothing because the task packs put commands in inline code spans; it now reads both. Status: Solved.

## 2026-10-14, port from reWatch PR #3
- Problem: the PR #3 skill and tool upgrades existed only in reWatch. A first port attempt was built on the repo's default branch (an older Claude branch) instead of `main` and conflicted with main's own earlier partial port.
- Cause: the default branch is not `main`; a shallow clone takes the default.
- Solution: rebuilt on `origin/main` with a three-way merge per file (base: reWatch before PR #3; ours: reWork main; theirs: reWatch after PR #3), keeping reWork's generic wording; target-only content (the watch client, its frame tests, a vendor checksum rule) left out. A proposal also asked for privacy_scan.py, install_hooks.py, re-privacy-scrub, re-step-rationale, CLOUD-SETUP.md and docs/steps.md; none exist in any of the three repos, so none were invented. Status: Solved.

