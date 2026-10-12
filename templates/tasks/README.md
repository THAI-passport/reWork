# Recon task pack: {{name}}

Written for an AI agent or a person who has not seen this project. Follow it literally. Where it is silent, make an assumption using the policy below, write it down, and keep going.

Start with `QUICKSTART.md`: a one-page table of which tasks apply to you.

Goal of the target: {{goal}}
Evidence tags: `[C]` confirmed in the artifact, `[V]` verified by emulation or test vector, `[H]` confirmed on real hardware, `[W]` third-party claim, `[I]` inferred, `[U]` unknown.

## Files
| File | Purpose |
|---|---|
| `QUICKSTART.md` | One page: which tasks apply to your situation, ten rules |
| `SW-RECON.md` | Software tasks S0 to S9: no hardware, an AI can do them alone |
| `HW-RECON.md` | Hardware tasks HW-0 and up: need a physical device and a machine with the right radio/port |
| `ASSUMPTIONS.md` | Pre-made assumptions and the log of new ones |
| `STATUS.md` | Task board; update when a task changes state |
| `results/` | One result file per finished task: `<task>-<YYYY-MM-DD>.md` |

## Who can do what
| Task type | Who | Why |
|---|---|---|
| S tasks | AI agent alone | Pure software |
| HW tasks marked HUMAN+AI | A person runs the commands on a machine with the device attached; the AI prepares the run sheet, reads pasted output, updates docs | Cloud sandboxes have no Bluetooth/USB/serial access and cannot touch a device |
| HW tasks marked HUMAN | Only a person, only with the owner's written approval | Battery, heat, soldering, firmware dumps |
An AI with no human available completes every S task, prepares the HW-0 run sheet, and stops. Never invent hardware results or claim to have run a hardware task without pasted output.

## Hard rules
1. Static analysis of vendor software by default. A live session (real device, vendor app capture, vendor server) needs the owner's approval for that session; write the approval in the result file.
2. Never commit vendor artifacts, decompiled trees, firmware dumps, tokens, signed URLs, personal data, full device addresses, serial numbers or Wi-Fi passwords. Captures stay outside the repo unless scrubbed.
3. Every write to a real device goes through a safe-write guard (counter, identical-payload skip, minimum interval, daily cap). Do not disable it unless a step says so. Each HW task lists its write cost; stay within the daily budget.
4. Reads only for firmware and storage. No flashing, erasing, OTA or download-mode tools.
5. Do not retry a failing hardware step in a loop: one retry after a power cycle, then record and move on.
6. No emoji; no hard-coded test counts in docs; do not push to `main`; do not open a pull request unasked.
7. If a step needs a person and nobody is available, set the task to `blocked: needs human` and continue with the next task.

## Assumption policy
Prefer `ASSUMPTIONS.md`. If not covered, choose the option that is reversible, writes least to the device, and is easiest to falsify; add a log row (id, assumption, why, how to falsify, impact). Never stop for a question that a search, a grep or a default can settle. Stop and ask only for: physical access, permission for a live session, a destructive step, a legal question, a credential, or a command that would exceed the write budget. An unrecorded assumption is a defect.

## Result file template
```
# <task id>: <title>
date / time zone:      executor:
device and firmware / app version:
branch and commit:
commands run (exact, in order):
raw outputs (paths or pasted, redacted):
measured values:
result: PASS | FAIL | PARTIAL | BLOCKED
evidence tag per finding: [C] [V] [H] [W] [I] [U]
assumptions made (ids):
docs or code changed:
new problems (also appended to LOG.md):
next task suggested:
```

## Where things get recorded
| What | Where |
|---|---|
| Task result | `tasks/results/<task>-<date>.md` and a row in `STATUS.md` |
| A problem you hit | `LOG.md` (date, gate, problem, cause, solution or open) |
| Something in reWork itself that needs fixing | repo-root `FIXES.md` |
| Disputed values | `FACTS.md` only |
| Confirmed or corrected byte-level claim | `PROTOCOL.md`, with the tag changed and the source named |

## Generic trip-ups
| Symptom | Likely cause | Fix |
|---|---|---|
| Device not found by scan | It advertises only in a pairing/discoverable mode, or the vendor app holds the single connection | Put it in pairing mode, close the vendor app, toggle phone Bluetooth |
| No adapter / bare errno | No Bluetooth hardware or daemon (every cloud sandbox) | Run on a machine with an adapter |
| macOS shows UUIDs not MAC addresses | CoreBluetooth hides addresses | Use the printed UUID |
| Windows connect fails after OS pairing | Device uses application-level binding | Remove it from OS paired devices |
| Second identical send is "skipped" | Delta guard: same payload hash | Intended; use the no-delta option for rewrite tests |
| Send refused | Minimum interval or daily cap | Wait; never raise the cap without approval |
| Tests skip | Optional package or native library absent | Expected; do not commit the library |
| Decompiler killed | Out of memory | `--max-heap 3g` |
| Mirror/host unreachable | Cloud network policy | `--local-file` or ask the owner to allow the host |
