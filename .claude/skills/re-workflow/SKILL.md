---
name: re-workflow
description: Orchestrates a full reverse-engineering run of a device or companion app (BLE, Wi-Fi, USB, serial, cloud-free local protocols) from a one-line prompt to a tested open client. Use first whenever the prompt says "reverse engineer", names a gadget or app, or asks for an open client, protocol spec, or companion-app analysis.
---

# re-workflow

Entry point. Input is `Reverse engineer: <device/app>. Goal: <client behaviour>.` Output is `targets/<slug>/` docs plus `client/<slug>/` code and tests, pushed.

## Steps
1. **G0 Brief.** Pick a short slug (lowercase, dashes). Run `python tools/rw.py init <slug> --name "<name>" --goal "<goal>"`. Run `python tools/rw.py doctor` and note missing tools in LOG.md. Write defaults you chose in TARGET.md Assumptions: static only, Android first, Python client, local-only.
2. **Identify the target software.** If only hardware names were given (model numbers, a brand), follow `re-acquire` section "From hardware name to app".
   If the artifacts are not on this machine (new container, other agent), rebuild them first: `bash tools/rebuild-analysis.sh <slug> --dry-run`, then without `--dry-run` (see `re-acquire`, section "Make it rebuildable"). Never continue past a hash mismatch.
2a. **Rebuild policy.** On a new instance do not rebuild by reflex: read the target docs first, rebuild only for a named `[I]`/`[U]` claim (see AGENTS.md). After any pass, record findings, disputed values, problems and reusable procedure before stopping.
3. Run gates G1 to G4 with the skills named in AGENTS.md. After each gate: update the gate table in TARGET.md, append problems to LOG.md, commit, push.
4. **G5 Handoff.** Specialise the recon task pack in `targets/<slug>/tasks/` with the `re-hardware-recon` skill (it is copied from `templates/tasks/` by `init`), then fill HANDOFF.md from the template: what exists, evidence summary (counts of C/V/H/W/I/U), unknowns that need hardware, the first-session checklist (read-only probe first, capture everything, one write at a time), and the safe-write policy.

## Handing work to weaker agents
Write for the weakest executor: no unstated context, every step a command with an expected result, every unknown an assumption in `tasks/ASSUMPTIONS.md` with a test that would falsify it, every risk a stop condition. State who can do each task (AI alone, human plus AI, human only). The pack is part of the deliverable, not an afterthought.

## Decisions already made (do not re-litigate)
- Transport comes from service discovery or constants, not from device name.
- Multiple models in one family: build one profile table (data), select by flag.
- Several apps for several models (for example two models, two apps): run G1 to G3 per app, then diff the protocols in one table in PROTOCOL.md; share code where bytes are identical.
- Product identity (which model uses which transport) is often server-side. Say so, make it a flag, and record it under Unknowns.
- Do not stop at "tests pass". Tests against your own simulator prove consistency only.

## Parallelism
Independent surface-map tasks (per transport, per app, per native library) can be handed to subagents. Give each the slug, the question, and the evidence-tag rule. Merge their findings into PROTOCOL.md yourself.

## Failure handling
If a gate cannot be completed (no network, artifact unobtainable, native code too large), write the blocker and the cheapest next action in TARGET.md, mark the gate `blocked`, and continue with any gate that does not depend on it.
