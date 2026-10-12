---
name: re-hardware-recon
description: Plan and run (or hand off) first contact with a real device after the protocol spec exists - run sheet, approvals, write budget, read-only qualification, container/size/limit tests, free-space and persistence tests, passive event logging, physical survey, and the gated destructive track. Also how to write step-by-step recon tasks that a weaker agent can follow without asking questions.
---

# re-hardware-recon (gate G5 and any later hardware session)

Output: `targets/<slug>/tasks/` (created by `python tools/rw.py init`, from `templates/tasks/`), result files under `tasks/results/`, and updates of FACTS.md and PROTOCOL.md with `[H]` tags.

## Principles
1. A cloud sandbox has no Bluetooth, USB or serial access. Hardware tasks need a person with a machine and the device. The agent prepares, the person executes, the agent interprets pasted output. Never claim hardware results you did not receive.
2. Read-only first: scan, connect, read GATT/descriptors, listen for pushed status. Writes come one at a time after that, each with a stated purpose and a pre-computed cost.
3. Everything that writes goes through a safe-write guard (counter, identical-payload skip, minimum interval, daily cap). Plan the day's write budget before the first write: sum the per-task write counts, stay under half the cap.
4. Rewrite tests collide with the guard: an identical resend is skipped by design, so such tests need the no-delta option and the interval respected. Say so in the step, or the tester will conclude the device ignored them.
5. The simulator proves consistency, not truth. After every hardware finding update the simulator and the spec together.
6. Stop conditions beat persistence: one retry after a power cycle, then record and move on. Any freeze, reboot, odd reply or low free space stops the escalating test.
7. Firmware and storage are read-only to us. No OTA, no download modes, no flashing, ever.

## Building the task pack for a target
`python tools/rw.py init <slug>` already copies the generic pack. Specialise it at G5 (and again whenever G3 changes the spec):
1. Replace the generic commands in `HW-RECON.md` with the target's real client commands and flags (check each flag exists: run the command with `--help` or `--dry-run`).
2. Fill `ASSUMPTIONS.md` with the target's defaults, each with "how it is proven wrong" and "effect if wrong".
3. For every unknown in PROTOCOL.md section "Unknowns" add or map a task that settles it; remove tasks that do not apply and mark them `skipped: not applicable` in STATUS.md.
4. For each task write: executor, writes used, preconditions, exact commands, expected output, an interpretation table (observation -> meaning -> action), stop condition, and the files to update. A table beats prose.
5. Put a "trip-ups" table in README.md from the target's LOG.md: symptom, cause, fix.
6. Verify what you can without hardware: run every command in dry-run or simulate mode; the pack must not contain a flag that does not exist.

## Standard tasks (generic order)
Run sheet and approvals -> reference capture with the vendor app (approval) -> scan + read-only qualification -> second-radio survey -> dry runs -> container/format acceptance -> size/shape/orientation -> free space + rewrite behaviour -> power-cycle persistence -> throughput -> length/size limits -> passive event logging (`tools/notify_log.py`) -> non-destructive physical survey -> USB/serial observation -> destructive teardown (approval).

## Interpreting free space (generic)
D1 = F0 - F1 about payload and D2 about 0: one slot overwritten. D1 and D2 both about payload: append or log allocation, rewrites consume space. D1 about 0: lazy or RAM accounting, repeat after power cycle. Page-sized steps: page granular accounting. Values that differ between two identical reads: take the median and say so.

## Destructive track gate
Only the owner can approve (written, per unit). Plastic tools, battery disconnected first, no heat above about 60 C, measure the flash rail before attaching any programmer (a 3.3 V programmer destroys 1.8 V parts), check whether a dump point exists at all (flash may sit inside the SoC package), read twice and require identical hashes, store dumps outside git, commit only notes. Dump analysis (binwalk, strings, file-system, display init) is safe AI work on a supplied file.

## Handoff quality bar
A weaker agent can follow the pack without asking a question: every step has a command, an expected result and a decision; every unknown has an assumption and a test; every risk has a stop condition.
