# Quickstart: {{name}} (read this first, then only your own task)

The pack is long on purpose so you do not have to read it all. Pick your situation, do the listed tasks in order, open only those sections.

| Your situation | Do this, in order | Stop when |
|---|---|---|
| AI agent, no device, no human | S0, S7, S8, S9 (S1 to S6 only if the decompiled tree exists or can be rebuilt) | HW-0 run sheet written, STATUS.md current |
| AI agent, decompiled tree exists | S0, S2, S5, S6, S8, S9 | Every claim touched has a recorded outcome |
| AI agent, no tree, and the answer is already in PROTOCOL.md, FACTS.md, LOG.md or a skill | Do not rebuild; answer from the docs and cite the section | - |
| AI agent, no tree, an `[I]`/`[U]` claim needs the code | S0, S1 (`--dry-run` first), S2 | `[C]` or a precise "not settled" per claim |
| Person with the device and a laptop | HW-0, HW-2, HW-4, HW-5, HW-6, HW-7, HW-8, then HW-9 to HW-11 | Write budget used or a stop condition hit |
| Device exposes a second radio | add HW-3 | - |
| Owner approved opening one unit | HW-12 to HW-14 in order | A step answers the question |

## Ten rules
1. Do not rebuild or decompile to explore; read PROTOCOL.md, FACTS.md, LOG.md and the skills first.
2. Never write to the device outside a listed task; read-only first; respect the interval and the write budget.
3. Never claim a hardware result you were not given as pasted output.
4. One retry after a power cycle, then record and move on.
5. Tag every finding `[C] [V] [H] [W] [I] [U]`.
6. Use ASSUMPTIONS.md; log new assumptions; do not ask what a default can settle.
7. After a decompile pass record findings in PROTOCOL.md, disputed values in FACTS.md, problems in LOG.md, reusable procedure in the matching skill, and append the step/rationale to `docs/steps.md`, in the same commit.
8. Never commit vendor files, dumps, captures with addresses, or test counts in docs.
9. Run `python tools/rw.py lint` and the tests before committing.
10. If a step is wrong or missing, fix this pack and add an Open item to the root FIXES.md.
