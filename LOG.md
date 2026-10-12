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
