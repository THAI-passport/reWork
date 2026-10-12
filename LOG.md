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
