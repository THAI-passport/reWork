---
name: re-workflow
description: Orchestrates a full reverse-engineering run of a device or companion app (BLE, Wi-Fi, USB, serial, cloud-free local protocols) from a one-line prompt to a tested open client, gates G0 to G5. Use first whenever the prompt says "reverse engineer", names a gadget, watch or companion app, asks for an open client or protocol spec, resumes an existing targets/<slug>/, asks which skill or gate comes next, or hands surface-map work to subagents. Holds the gate-to-skill map and the evidence-tag legend.
---

# re-workflow

Entry point. Input is `Reverse engineer: <device/app>. Goal: <client behaviour>.` Output is `targets/<slug>/` docs plus `client/<slug>/` code and tests, pushed.

## Evidence tags (canonical legend: AGENTS.md; do not redefine)
`[C]` confirmed in the artifact (cite file and class.method) · `[V]` verified by an emulator or test vector against real code · `[H]` confirmed on real hardware (capture or report) · `[W]` third-party claim, unverified · `[I]` inferred · `[U]` unknown. Code from a bundled third-party or chip SDK is still `[C]`, but write "SDK: <package>" next to it: it proves the SDK can do something, not that the target uses it. Disputed values live only in FACTS.md.

## Gate map
| Gate | Load | Output |
|---|---|---|
| G0 Brief | `re-watch-targets` for a watch or band (+ `re-jieli` if JL signs) | `targets/<slug>/` via `rw.py init`, TARGET.md assumptions |
| G1 Acquire | `re-acquire` | artifacts pinned and hashed in SOURCES.md |
| G2 Surface map | `re-static`, then `re-ble-android-patterns` | surface map in PROTOCOL.md, disputes in FACTS.md, native list |
| G3 Spec | `re-protocol-spec`; `re-native-emulation` if native auth/crypto/CRC; `re-capture-ingestion` if captures exist | byte-exact PROTOCOL.md with worked examples and vectors |
| G4 Client | `re-client-sim` | `client/<slug>/`, simulator, safe-write guard, tests |
| G5 Handoff | `re-hardware-recon` (+ `re-capture-ingestion`) | `targets/<slug>/tasks/` specialised, HANDOFF.md |

## Steps
1. **G0 Brief.** Pick a short slug (lowercase, dashes). Run `python tools/rw.py init <slug> --name "<name>" --goal "<goal>"`. Run `python tools/rw.py doctor` and note missing tools in LOG.md. Write defaults you chose in TARGET.md Assumptions: static only, Android first, Python client, local-only.
2. **Identify the target software.** If only hardware names were given (model numbers, a brand), follow `re-acquire` section "From hardware name to app".
3. **Rebuild only when needed.** If the artifacts are not on this machine, read the target docs first and rebuild only for a named `[I]`/`[U]` claim (AGENTS.md): `bash tools/rebuild-analysis.sh <slug> --dry-run`, then without `--dry-run` (`re-acquire`, "Make it rebuildable"). Never continue past a hash mismatch.
4. **Run G1 to G4** with the skills in the gate map. Software first: plan no hardware step until software is exhausted and the user approves (AGENTS.md "Software first, hardware last").
5. **After each gate or pass:** update the gate table in TARGET.md; findings to PROTOCOL.md, disputes to FACTS.md, problems to LOG.md, reusable procedure to the matching skill and `docs/SOP.md`; commit, push.
6. **G5 Handoff.** Specialise `targets/<slug>/tasks/` with `re-hardware-recon`, check it with `python tools/rw.py taskflags <slug>`, then fill HANDOFF.md from the template: what exists, evidence summary (counts of C/V/H/W/I/U), unknowns that need hardware, the first-session checklist (read-only probe first, capture everything, one write at a time), and the safe-write policy.

## Handing work to weaker agents
Write for the weakest executor: no unstated context, every step a command with an expected result, every unknown an assumption in `tasks/ASSUMPTIONS.md` with a test that would falsify it, every risk a stop condition. State who can do each task (AI alone, human plus AI, human only). The pack is part of the deliverable, not an afterthought.

## Decisions already made (do not re-litigate)
- Transport comes from service discovery or constants, not from device name.
- Multiple models in one family: build one profile table (data), select by flag.
- Several apps for several models (for example two models, two apps): run G1 to G3 per app, then diff the protocols in one table in PROTOCOL.md; share code where bytes are identical.
- Product identity (which model uses which transport) is often server-side. Say so, make it a flag, and record it under Unknowns.
- Do not stop at "tests pass". Tests against your own simulator prove consistency only.

## Parallelism
Independent surface-map tasks (per transport, per app, per native library) can be handed to subagents. Give each the slug, the question, and the tag legend above. Merge their findings into PROTOCOL.md yourself.

## Failure handling
If a gate cannot be completed (no network, artifact unobtainable, native code too large), write the blocker and the cheapest next action in TARGET.md, mark the gate `blocked`, and continue with any gate that does not depend on it.

## Steps log
Append every step and decision with rationale to `docs/steps.md` (Asia/Saigon time) as work proceeds. Required by AGENTS.md.

