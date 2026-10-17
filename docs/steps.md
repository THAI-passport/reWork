# Steps log

Chronological record of every step taken and every decision with its rationale.
Times are Asia/Saigon (UTC+7). Append as work proceeds; do not rewrite history.
Required by AGENTS.md.

Template entry:

```
## YYYY-MM-DD — short title

- **Step:** what was done.
  - **Rationale:** why this step, why this order.
- **Decision:** choice made (if any).
  - **Rationale:** alternatives considered and why this one won.
```

---

## 2026-10-13 — steps log introduced

- **Decision:** Require `docs/steps.md` in every reWork-family repo; append every step and rationale as work proceeds.
  - **Rationale:** Owner instruction. FACTS/PROTOCOL/LOG capture outcomes and problems; the decision trail (why a package, why a branch shape, why a pin) was being lost between agent turns.

## 2026-10-17 (Asia/Saigon) remove-dbug-framework branch: strip the dbug merge

- **Step:** On branch `remove-dbug-framework` (main untouched), removed every path that came from the `cline/ya8xm47p-dbug-merge` import: the 28 `.claude/skills/dbug-*` directories, `tests/test_dbug_framework.py`, the root-level dynamic-analysis tooling (`orchestrator.py`, `desktop_static.py`, `desktop_dynamic.py`, `ios_static.py`, `ios_dynamic.py`, `firmware_static.py`, `web_static.py`, `web_dynamic.py`, `sanitize_device_state.py`, `emulator.md`, `hide_dev.md`), its support directories (`device_cloaking/`, `instrumentation/`, `emulation/`, `memory/`, `network/`, `network_capture/`, `parser_correlator/`, `sample_triage/`), `tools/emulator_launch.py`, the dbug-only `config/` files (`detection_catalog.json`, `lab_config.yaml`, `schemas/`, `tracker_catalog.json`, `seed_canaries.py`, `mock_canaries.json`, `schema_validator.py`), and the merge-documentation files (`PORTING.md`, `revamp.md`, `fork-v1.md`). Trimmed the dbug-only sections and mentions out of `README.md`, `requirements.txt`, `requirement.md`, `tools/rw.py` (doctor's tool table), `docs/SOP.md`, `docs/steps.md`, and `.gitignore`, keeping everything those files also use for reWork's own work (`config/safe_write.py`, `knowledge/`, adb/tshark/radare2/rizin/ghidra/mitmproxy/binwalk, pyyaml/pyelftools/unicorn/capstone).
  - **Rationale:** Owner asked to remove the dbug framework from this branch because its framing (stealth Android malware sandbox, anti-debug/RASP evasion, device cloaking to hide debug state from a sample, a renamed Frida daemon on a non-default port, C2 protocol decoding, infostealer attribution) sits outside reWork's own scope (interoperability reverse engineering of a device the user owns) and was tripping safety classification. `main` keeps the full dbug skill set; this branch is the one with it removed.
- **Decision:** Kept `config/safe_write.py` and `knowledge/` (reWork's own ground-rule-7 write guard and watch-market notes, not part of the dbug merge) and the shared dependencies/doctor entries that reWork's own `re-native-emulation` and `re-capture-ingestion` skills use.
  - **Rationale:** Those are genuine reWork content that happened to sit in the same directories/files as dbug additions; deleting them would break real target work for no safety benefit.

