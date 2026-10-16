# reWork

A target-agnostic reverse-engineering workflow for consumer gadgets and their companion apps. Give an agent one line, get back a protocol spec, an open local-only client, a software simulator, tests, and an honest list of what only real hardware can settle.

Distilled from the reBeamBox project (a BLE e-badge). Everything specific to that badge was left behind; the procedure, evidence discipline, tooling and guards were kept.

## One-go start
Fork this repo, open it in Claude Code (or any agent that reads `AGENTS.md`), and prompt:

```
Reverse engineer: <device or app name(s)>.   Goal: <what the client must do>.
```
The agent reads `AGENTS.md`, loads the `re-workflow` skill, and runs gates G0 to G5 without asking for approval between them.

### Benchmark prompt (forked repo)
```
Reverse engineer: <device or app name>.   Goal: scan, connect, read basic status and push one command from a Python CLI.
```
Pass criteria: `targets/<slug>/` has SOURCES.md with hashes, a PROTOCOL.md where every row is tagged, a FACTS.md for disputed values, `client/<slug>/` with `pytest -q` green and `--dry-run`, `python tools/rw.py lint` green, no vendor artifact tracked, HANDOFF.md listing hardware unknowns. Whether both models share one app or protocol is a finding to record, not an assumption.

## What is inside
| Path | Purpose |
|---|---|
| `AGENTS.md` | Contract: prompt format, ground rules, logs, platform and live-contact rules, workflow, evidence tags, gates |
| `FIXES.md` | Open and fixed issues in reWork itself |
| `CLAUDE.md` | Imports AGENTS.md for Claude Code |
| `requirement.md` | All components needed to run reWork/dbug on Windows, macOS, and Linux/Unix, with per-OS install commands |
| `.claude/skills/re-workflow` | Orchestrator, entry point |
| `.claude/skills/re-acquire` | Hardware name to app, download, validate, hash |
| `.claude/skills/re-static` | jadx/apktool survey, surface map, obfuscation, decompiler failures |
| `.claude/skills/re-protocol-spec` | Byte-exact spec, checksums, SDK command layers, captures |
| `.claude/skills/re-native-emulation` | `.so` recovery with capstone and unicorn; aarch64 harness in `scripts/` (needs `setup_tools.py --emulation`) |
| `.claude/skills/re-client-sim` | Layered client, simulator, dry-run, safe-write (reference code in `references/`), fixtures, CI |
| `.claude/skills/re-watch-targets` | Watch specifics: stacks (signatures in `references/vendor-stacks.md`), white-label families, standard GATT services, features, watch face and OTA shapes, read-only safe probes, what to record per family |
| `.claude/skills/re-ble-android-patterns` | Finding transports in decompiled Android code: GATT, MTU, write types, scan filters, name dispatch, catalogs, ACK patterns, Wi-Fi modes |
| `.claude/skills/re-jieli` | Jieli chip family: recognition, RCSP frames, E1/SAFER+ auth, large-file transfer, FatFS, OTA awareness, emulation |
| `.claude/skills/re-capture-ingestion` | HCI snoop and pcap workflow with `tools/btcap.py`, scrubbing with `tools/scrub_capture.py` |
| `.claude/skills/re-hardware-recon` | First contact with a real device, write budget, task packs for weaker agents, gated teardown |
| `knowledge/` | Sanitized notes for the next project (budget wearables landscape) |
| `docs/NEXT-PASS-PROMPT.md` | Prompt for an agent pass over reBeamBox, reWork and reWatch |
| `templates/` | TARGET, SOURCES, FACTS, PROTOCOL, LOG, HANDOFF |
| `tools/rw.py` | `init`, `doctor`, `hash`, `recon`, `lint`, `taskflags` (stdlib only) |
| `tools/emulator_launch.py` | Launch an Android AVD over adb-over-TCP with stealth cloaking; dry-run capable; hands a TCP serial to the dbug pipeline (see `emulator.md`) |
| `tools/btcap.py` | btsnoop/pcap/pcapng to ATT write/notify table by UUID |
| `tools/scrub_capture.py` | Mask addresses, tokens and named literals in a btcap summary, length-preserving |
| `tools/crcfind.py` | Identify a CRC from sample frames |
| `tools/notify_log.py` | Passive BLE notification logger (touch/event discovery) |
| `tools/make_test_media.py` | Synthetic test images, GIF and clips for display devices |
| `templates/tasks/` | Recon task pack copied into every target by `init` |
| `tools/setup_tools.py` | User-space JDK, jadx, apktool, venv (no admin rights); Linux, macOS, Windows. `setup-tools.sh` wraps it |
| `tools/recover-failed-methods.sh` | Second-chance decompile via simple mode and CFR |
| `tools/rebuild_analysis.py` | Rebuild a target's artifacts and jadx tree from SOURCES: hash-verified, idempotent, `--dry-run`, `--max-heap`, `--url`; Linux, macOS, Windows. `rebuild-analysis.sh` wraps it |
| `.claude/skills/dbug-*` | 17 dbug skills: workflow orchestrator, sample triage, device cloaking, canary seeding, network gateway, eBPF capture, Frida instrumentation, native emulation, anti-analysis, C2 protocol, canary correlation, threat intel, privacy audit, AppSec MASVS, opsec safety, infostealer catalog, step rationale |
| `orchestrator.py` | dbug master CLI driving the full dynamic analysis pipeline (G0-G5) across malware, privacy, appsec, and all profiles |
| `config/` | dbug lab configuration, synthetic canaries, and mobile tracker catalog |
| `parser_correlator/` | dbug parsers: PCAP decryptor, canary hunter, C2 decoder, family classifier, IOC extractor, YARA generator, privacy auditor, AppSec auditor |
| `device_cloaking/`, `network_capture/`, `instrumentation/`, `sample_triage/` | dbug stealth pre-flight audit, gateway/eBPF capture, Frida agent scripts, static APK/DEX triage and native emulation |
| `docs/` | dbug SOPs, step log, roadmap, threat model, and task plans |
| `tests/test_dbug_framework.py` | dbug 16-suite end-to-end regression test harness |

## Manual quick start
```
python tools/setup_tools.py        # once; optional --emulation (Windows: run it from PowerShell)
python tools/rw.py doctor
python tools/rw.py init mydev --name "My device" --goal "sync status from CLI"
python tools/rw.py hash targets/mydev/artifacts/app.xapk --slug mydev
python tools/rw.py recon targets/mydev/decompiled --slug mydev
python tools/rw.py lint
python -m unittest discover -s tests
```

## Scope and limits
Static analysis, interoperability, local clients. It does not install or run target apps, does not ship vendor code, and does not defeat protection mechanisms. Results from simulators are consistency checks, never hardware truth.
