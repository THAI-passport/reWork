# Software recon tasks: {{name}}

No hardware, no live vendor contact. An AI agent can do all of these. Read `README.md` first. Run from the repository root; target directory is `targets/{{slug}}/`. After each task: write `tasks/results/<task>-<date>.md`, update `STATUS.md`, commit.

## S0. Baseline
1. `python tools/rw.py doctor` (tools present or missing), `python -m unittest discover -s tests`, `python tools/rw.py lint`. All must be clean before you change anything; record failures in the tooling `LOG.md`.
2. Missing JDK/jadx/apktool: `python tools/setup_tools.py --no-venv`.
Pass: doctor lists what exists; tests and lint clean.

## S1. Acquire or rebuild the artifact and decompiled tree
1. If `targets/{{slug}}/decompiled` has files and `BUILD-INFO.txt` matches SOURCES.md, mark done.
2. If SOURCES.md has no machine-readable block yet: do gate G1 (`re-acquire` skill) and fill the block.
3. Otherwise `python tools/rebuild_analysis.py {{slug}} --dry-run`, then without `--dry-run` (add `--max-heap 3g` on small machines).
Decision table: host blocked -> mark `blocked: needs human` (ask the owner to allow the host or supply the file for `--local-file`) and do the tasks that do not need the tree (S0, S7, S8 partly, S9); hash mismatch -> stop, never `--accept-new-hash` without telling the owner; tool version mismatch -> `tools/setup_tools.py` or `--force` and record versions; jadx killed -> lower `--max-heap`.
Never commit anything under `artifacts/`, `work/`, `decompiled/`.

## S2. Audit unconfirmed claims in PROTOCOL.md
1. `grep -nE "\[(I|U)\]" targets/{{slug}}/PROTOCOL.md` -> table of claims, at most 25 per pass, byte-affecting ones first (lengths, checksums, opcodes, timing), then transport selection, then limits.
2. For each claim find the code: grep a literal from the claim in the decompiled tree, read the whole method with wide lines, follow callers. Decompiler stub: `bash tools/recover-failed-methods.sh` or smali via apktool.
3. Outcome per claim: Confirmed (tag `[C]`, add source class.method), Contradicted (fix the text; fix code and tests that depend on it; add a LOG entry), Not settled (leave the tag, name the hardware task that would settle it).
Output: results file with claim, old tag, new tag, source, action.

## S3. Static inventory of the vendor server API
Static only, never call an endpoint. Find base URL constants and endpoints; for device-related ones record method, path, request and response fields from the model classes. Note whether product/model tables are server-side (limits what the client can know). Record only that a hard-coded secret exists and where, never its value, and tell the owner.

## S4. Static inventory of the firmware update path
How the app learns of a new version, the file type it downloads, how it reaches the device, which authentication it uses. Static only; do not download firmware. Mark the result "not to be used for writing". The client must never contain an OTA path.

## S5. Inventory of everything the device can send to the app
Enumerate every receive path (notification handlers, socket reader loops, USB read loops) and list each message type and what the app does with it. State negative results precisely ("no code parses X: searched A, B, C"). Hardware task HW-11 verifies later.

## S6. Scan filter and model detection audit
Record the app's scan filters and name matchers exactly; compare with the client's. Each difference is either deliberate (say why) or a client bug (fix with a test).

## S7. Test media and payload size table
`python tools/make_test_media.py --out testmedia` (needs Pillow; `--no-video` without ffmpeg). For every file and transport run the client's dry run and record the payload size. The table feeds the write budget in HW-0.

## S8. Simulator assumption register
List every behaviour the simulator implements without `[C]` backing (auth details, status contents, ACK strings, delays, free-space numbers), the file and line, and the hardware task that would test it. Turn invented numbers into named constants with a comment pointing at the register. Do not change test meaning.

## S9. First-contact readiness and wrap-up
1. The client's read-only qualification command works against the simulators and writes a report with: advertised name, services, MTU, transport decision, handshake result, status keys, masked addresses. Every send command dry-runs on every transport. The capture reader decodes the synthetic fixtures and reports (not crashes on) the malformed one.
2. The send log prints every device-pushed status message (this is how free space is read in HW-7). If it does not, add that first, with a test.
3. Update `STATUS.md`, `ASSUMPTIONS.md`, `LOG.md`; run tests and lint; commit; push to the given branch.
4. Final message to the owner: what became `[C]`, what was contradicted, what is blocked and on whom, the exact first command for the human (HW-2).
