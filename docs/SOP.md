# SOP: reverse engineering a smartwatch companion app

Generic procedure, tool tricks and lessons. Skills under `.claude/skills/` hold the detailed procedures; this file is the map and the memory. AGENTS.md requires updating it after each decompile or code-reading pass: add what was learned that applies beyond one target, remove what turned out wrong, and keep target-specific facts in `targets/<slug>/`.

Principle: software first, hardware last. Order: public information, the app (static), native libraries (disassemble, emulate), existing captures, and only then, with the owner's approval, read-only contact with the owner's own watch. Physical work is a last resort for a named unknown that software could not settle.

## 1. Procedure by gate
| Gate | Do | Skill |
|---|---|---|
| G0 | slug, goal, assumptions; `python tools/rw.py init`, `doctor`; read `re-watch-targets` first questions | re-workflow, re-watch-targets |
| G1 | find the app, download from a reputable source, validate, hash, pin | re-acquire |
| G2 | decompile, map transports, services, entry points, stored keys | re-static, re-ble-android-patterns, re-jieli if it applies |
| G3 | byte-exact spec with worked vectors; emulate native routines | re-protocol-spec, re-native-emulation |
| G4 | layered client, simulator, dry-run, tests, lint | re-client-sim |
| G5 | handoff and recon task pack | re-workflow, re-hardware-recon |

## 2. Tool setup and probing
- `python tools/setup_tools.py` installs a user-space JDK, jadx and apktool at pinned versions (no admin rights). Probe each tool with a version flag before relying on it. `python tools/rw.py doctor` lists what is missing.
- Run long jobs detached and read the log; a foreground call can be cut by the agent shell's time limit.
- Python tools use only the standard library so they run on Linux, macOS and Windows; shell files are thin wrappers.

## 3. Acquiring and pinning
- Prefer an official source, else a reputable mirror. Listing sites disagree on version and size; use them as hints and trust the file's own manifest.
- `.xapk` and `.apks` are zips: a base APK, split APKs (native libs per ABI, language, density) and `manifest.json`. Extract only the base APK first and the arm64 split when native code matters. `unzip -t` before anything else.
- Pin by exact version and SHA-256, never by a floating "latest" link. Record a versioned or mirrored URL and where the owner keeps the exact copy (`COPY_LOCATION`, no secrets). A new vendor release is a NEW pinned entry; never edit the old hash. `--accept-new-hash` is for inspection only and the user must be told. Details: `re-acquire`, AGENTS.md.
- Rebuild on a new machine with `python tools/rebuild_analysis.py <slug>` (try `--dry-run`). Rebuild only when a named `[I]`/`[U]` claim needs the code; read the target docs first.

## 4. Decompiling
- jadx first (`-j 4`). Exit code 3 only means some methods failed to decompile. Progress output uses carriage returns: `tr '\r' '\n' < log | grep -v progress`.
- On a small or busy machine jadx can stall and be killed (exit 137): cap the heap (`--max-heap 3g` in the rebuild tool, or `JAVA_OPTS=-Xmx3g`).
- Where a method fails, read smali (`apktool d --no-res`), re-run `jadx -m simple --show-bad-code`, or use dex2jar plus CFR (`tools/recover-failed-methods.sh`). Record behaviour, not code.
- Obfuscated names do not matter: follow framework calls, string constants and stored keys; start from the UI action.
- Grep is slow on a 10k-file tree: use ripgrep with fixed strings and narrow paths.

## 5. Packer and protection triage
Signs of a packed or protected app: a tiny `classes.dex` with a stub Application class, native libraries named after protection vendors (for example names containing "jiagu", "shell", "DexHelper", "secexe" [W]), encrypted blobs in assets, `System.load` of an unpack routine, almost no BLE code in the visible tree.
- Triage means identify and record, then stop and tell the user. Do not defeat the protection.
- Alternatives that are in scope: an older or regional build of the same app that is not packed, vendor SDK documentation, third-party write-ups, captures the owner already has, and the standard-GATT layer, which needs no app code.
- Record the finding in the target's LOG.md and FACTS.md as `[C]` (what shows it) and the options.

## 6. Native libraries
Disassemble with capstone and pyelftools; emulate with unicorn; port stage by stage and compare each stage against the emulated routine; keep emulator vectors as tests that skip cleanly when the extras are missing. A negative result ("this library holds no limits") is a result. See `re-native-emulation`, `re-jieli`.

## 7. Captures
Ingest HCI snoop and pcap files with `tools/btcap.py`; map handles to UUIDs, reassemble across MTU chunks, validate checksums, report bad frames instead of dropping them. Scrub before storing; never commit raw captures. See `re-capture-ingestion`.

## 8. Tests and simulators
Build a software device from the spec to test the client, but a simulator written by you proves consistency only. Keep every uncertain value a named constant or flag so first hardware contact needs flag changes. Run `python3 -m unittest discover -s tests` and `python3 tools/rw.py lint` before each commit.

## 9. Lessons carried over from worked examples (reBeamBox e-badge, reWatch watches)
- One app may contain several transports chosen by name, service discovery or a server catalog; build a table before choosing one.
- Which transport a model uses was settled by third-party hardware reports, not by the app: label such claims `[W]` and keep a flag.
- Third-party reports contradicted an earlier code-based assumption; the fix was a documented default plus an option for the other behaviour.
- A wrong field width in a hand-written simulator stalled a transfer in the client's own test; bugs can be symmetric.
- Docs drift: do not write test counts in prose; keep disputed values in one FACTS.md; scan for contradictions after each milestone (that scan found a real client bug).
- Safe-write for storage: counter, delta skipping, minimum interval, daily cap, applied after the payload is known and before the first data frame.
- Check every claim in a task pack against the real flags; invented flags waste the first hardware session.
- Budget smartwatch ecosystem reality: models with similar numbering (e.g. T900 vs C900) often originate from completely different ODM solution houses and silicon architectures (JieLi Pi32 vs Bluetrum RISC-V). Build modular profile selectors rather than assuming monolithic protocol compatibility.
- Critical hazard: budget OTA bootloader services (such as Bluetrum Cus5610 0x18A8 and JieLi 0xAE10) often lack memory boundary checks and overwrite executing code when written to over BLE. Hard-blacklist OTA service UUIDs at the client link layer. (2026-10-14: neither id has a primary source; keep them blocked. Jieli OTA is documented on 0xAE00 itself, so also refuse OTA opcodes, not only services.)
- In-memory simulation speed: do not introduce artificial chunk pacing sleeps in unit test simulators; guard sleep delays with hardware link checks so test suites finish in milliseconds.

## 10. After each pass (checklist)
1. PROTOCOL.md: byte-level findings with tags and the source class and method.
2. FACTS.md: disputed values.
3. LOG.md of the target: every problem with cause and fix, or Unsolved plus what was tried.
4. This SOP or a skill: procedure, flags, dead ends, tricks that help the next target. Promote repeats and delete the repetition.
5. FIXES.md: anything wrong in reWork itself.
6. Commit, then push to the work branch.

## Lessons from the first watch benchmark pass (reWatch, 2026-10-12)
- When the artifact is blocked, still finish G0 and seed PROTOCOL/FACTS from the third-party document as `[W]`, then build the pure codec and simulator ahead with every layout value a named constant. A hand-computed vector in a test is own arithmetic, not evidence; say so in the test.
- Read a third-party frame layout for internal contradictions before coding it (here the ack header 0xFD versus the app header 0xDF, and what the length field counts); each goes into FACTS.md as a dispute.

## Lessons from the skill review (2026-10-14)
- Triage the app framework before grepping Java: Flutter keeps logic in `libapp.so`, React Native in `assets/index.android.bundle` (Hermes or JS). See `re-static`.
- aarch64 unicorn: CPACR_EL1 FP/SIMD on, a TLS page for TPIDR_EL0, PLT hooks return to LR, return to a mapped sentinel. Harness and table in `re-native-emulation`.
- Protobuf payloads: `protoc --decode_raw` on samples before naming fields. See `re-protocol-spec`.
- Always record the ABI split of an XAPK/APKS; natives live only there.
- Scrub capture summaries with `tools/scrub_capture.py` before committing; review the output by eye.
- Check a task pack with `python tools/rw.py taskflags <slug>` before handing it off.
- A skill description should say what a user would ask, not only which gate it belongs to.

