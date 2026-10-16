# Porting external tools and skills into reWork

This file is the plan for bringing another repository's tools and skills into this reWork repo. ReWork itself is the target-agnostic shell: gates G0-G5, six skills in `.claude/skills/`, stdlib-only CLI tools in `tools/`, gate templates in `templates/`, and unittest-based checks in `tests/`. Anything ported in must fit that layout and keep `python tools/rw.py lint` and `python3 -m unittest discover -s tests` green.

## What reWork already has

| Area | Location | Convention |
|---|---|---|
| CLI tools | `tools/*.py`, `tools/*.sh` | Python 3.10+, stdlib only for anything `rw.py` calls; third-party imports only behind optional-extra flags (`setup-tools.sh --emulation`) |
| Skills | `.claude/skills/<slug>/SKILL.md` | YAML frontmatter `name:` / `description:`; plain ASCII, no emoji; evidence-tag discipline |
| Gate templates | `templates/TARGET.md`, `SOURCES.md`, `FACTS.md`, `PROTOCOL.md`, `LOG.md`, `HANDOFF.md` | Jinja-style `{{slug}}` / `{{name}}` / `{{goal}}` / `{{date}}` substitution via `rw.py init` |
| Tests | `tests/test_*.py` | `unittest`, no pytest required; import tools directly from `tools/` |
| Repo rules | `AGENTS.md`, `README.md`, `FIXES.md`, `.gitignore` | No vendor artifacts (apk/xapk/dex/jar/.so/ipa/bin), no secrets, no emoji; lint enforces all three |

## Where ported content goes

- Repo-level command-line tool -> `tools/<name>.py` (add a subcommand to `tools/rw.py` if it belongs in the `rw.py` dispatch; otherwise a standalone script with the same header doc style)
- Shell helper/installer -> `tools/<name>.sh` (user-space, idempotent, no sudo; update `README.md` and `tools/setup-tools.sh` when it adds a dependency)
- Reverse-engineering procedure/skill -> `.claude/skills/<slug>/SKILL.md` with `name:` and `description:` frontmatter; cross-link from `AGENTS.md` gate table if it maps to a gate
- New gate template -> `templates/` (only if the external repo introduces a new gate; keep `{{`-substitution compatible)
- Test for a ported tool -> `tests/test_<name>.py` (unittest; use `importorskip` for optional packages, temp dirs for filesystem writes)
- Synthetic fixtures -> `tests/fixtures/` (commit with a SYNTHETIC manifest; never real captures from hardware)

## What must NOT be ported

- Vendor artifacts: APK, XAPK, APKs, AAB, IPA, dex, jar, `.so`, firmware, decompiled trees — `.gitignore` already blocks these; `rw.py lint` fails on them
- Tokens, signed URLs, personal data (addresses, phone numbers, account ids, serials, MACs) — scrub before saving
- Emoji in docs or code — `rw.py lint` fails on them

## Porting procedure

1. Create a feature branch from `cline/ya8xm47p` (never `main`, never direct to default branch).
2. Inventory the external repo: list every tool, script, skill/procedure doc, template, test, and fixture. Do not copy git history — copy files only.
3. Map each item to a reWork location in the table above. Reconcile layout differences (for example, if the external repo puts clients under `client/<slug>` while reWork gate G4 produces `client/<slug>/`, keep the reWork layout).
4. Scrub: remove tokens, signed URLs, vendor binaries, emoji, and secrets. Record provenance (source URL + SHA-256) in notes, not in code.
5. Register: add new `rw.py` subcommands in `tools/rw.py` `main()` dispatch; add skill names to the AGENTS.md gate table only when they own a gate; add dependencies to `setup-tools.sh` + `README.md`.
6. Test: add tests under `tests/`; run `python3 -m unittest discover -s tests` and `python tools/rw.py lint`; fix until both are green.
7. Document: update `AGENTS.md`, `README.md`, `FIXES.md` (Open -> Fixed when you close something), and the target `TARGET.md` gate table if this is for a specific target.
8. Commit and push on the feature branch; offer a pull request when the gate set is done (do not open one unasked).

## Readiness check before accepting the external repo

- [ ] Repo URL/path known (GitHub or local path)
- [ ] Inventory done: tools / skills / templates / tests listed
- [ ] Each item mapped to a reWork location
- [ ] Scrub review passed: no vendor artifacts, tokens, or emoji to carry over
- [ ] Lint green: `python tools/rw.py lint` -> 0 problems
- [ ] Tests green: `python3 -m unittest discover -s tests` -> OK
- [ ] `README.md` / `setup-tools.sh` updated for any new dependency
- [ ] Committed on `cline/ya8xm47p` (or a feature branch off it) and pushed

## Completed port: dbug (THAI-passport/dbug)

The dbug Android dynamic analysis / AppSec / privacy auditing framework has been ported into reWork on branch `cline/ya8xm47p-dbug-merge`:

| dbug content | reWork location |
|---|---|
| 17 skills (`.claude/skills/dbug-*`) | `.claude/skills/dbug-*` |
| `orchestrator.py`, `parser_correlator/`, `sample_triage/`, `device_cloaking/`, `network_capture/`, `instrumentation/` | repo root (preserves dbug's relative-path structure) |
| `config/` (lab_config.yaml, mock_canaries.json, tracker_catalog.json, seed_canaries.py) | `config/` |
| `docs/` (SOP, steps) | `docs/` + `fork-v1.md`, `hide_dev.md` (repo root) |
| `tests/test_framework_e2e.py` | `tests/test_dbug_framework.py` (16-suite) and `tests/test_framework_e2e.py` (22-suite expanded) |

Not ported (intentionally): `targets/*` sample-specific analysis workspaces (contain per-sample IOCs and reports; target-scoped, not framework), `samples/` (vendor artifacts, never committed).

Adjustments made for reWork compatibility:
- Fixed Python 3.11 f-string quote conflict in `orchestrator.py` (nested same-quote f-string on the YARA rule path line).
- Added dbug-generated artifact patterns to `.gitignore` (`sessions/`, `captures/`, `*.pcap`, `*.pcapng`, `sslkey.log`, `*.log`, `.env`, `targets/current_sample/`, `targets/simulated_*/`).
- Verified: `python tools/rw.py lint` -> 0 problems; `python3 -m unittest discover -s tests` -> 48 tests OK (10 reWork + 16 dbug + 22 expanded dbug).
