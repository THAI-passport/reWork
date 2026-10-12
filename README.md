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
Reverse engineer: the T900 and C900 watch app.   Goal: scan, connect, read basic status and push a watch face or notification from a Python CLI.
```
Pass criteria: `targets/<slug>/` has SOURCES.md with hashes, a PROTOCOL.md where every row is tagged, a FACTS.md for disputed values, `client/<slug>/` with `pytest -q` green and `--dry-run`, `python tools/rw.py lint` green, no vendor artifact tracked, HANDOFF.md listing hardware unknowns. Whether both models share one app or protocol is a finding to record, not an assumption.

## What is inside
| Path | Purpose |
|---|---|
| `AGENTS.md` | Contract: prompt format, ground rules, evidence tags, gates |
| `CLAUDE.md` | Imports AGENTS.md for Claude Code |
| `.claude/skills/re-workflow` | Orchestrator, entry point |
| `.claude/skills/re-acquire` | Hardware name to app, download, validate, hash |
| `.claude/skills/re-static` | jadx/apktool survey, surface map, obfuscation, decompiler failures |
| `.claude/skills/re-protocol-spec` | Byte-exact spec, checksums, SDK command layers, captures |
| `.claude/skills/re-native-emulation` | `.so` recovery with capstone and unicorn |
| `.claude/skills/re-client-sim` | Layered client, simulator, dry-run, safe-write, fixtures, CI |
| `templates/` | TARGET, SOURCES, FACTS, PROTOCOL, LOG, HANDOFF |
| `tools/rw.py` | `init`, `doctor`, `hash`, `recon`, `lint` (stdlib only) |
| `tools/btcap.py` | btsnoop/pcap/pcapng to ATT write/notify table by UUID |
| `tools/crcfind.py` | Identify a CRC from sample frames |
| `tools/setup-tools.sh` | User-space JDK, jadx, apktool, venv (no sudo) |
| `tools/recover-failed-methods.sh` | Second-chance decompile via simple mode and CFR |

## Manual quick start
```
bash tools/setup-tools.sh           # once, optional --emulation
python tools/rw.py doctor
python tools/rw.py init t900 --name "T900 watch" --goal "sync status from CLI"
python tools/rw.py hash targets/t900/artifacts/app.xapk --slug t900
python tools/rw.py recon targets/t900/decompiled --slug t900
python tools/rw.py lint
python -m unittest discover -s tests
```

## Scope and limits
Static analysis, interoperability, local clients. It does not install or run target apps, does not ship vendor code, and does not defeat protection mechanisms. Results from simulators are consistency checks, never hardware truth.
