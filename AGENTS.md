# AGENTS.md: reWork, a target-agnostic reverse-engineering workflow

You are reverse engineering a consumer device or its companion app so an open, local-only client can talk to it. This file is the contract. Skills in `.claude/skills/` hold the procedures. Read this file, then load `re-workflow` and follow it.

## Minimal prompt you will be given

```
Reverse engineer: <device or app name(s)>.   Goal: <what the client must do>.
```
Everything else is optional (package name, artifact path, transport hint). If it is missing, find it yourself. Do not ask questions you can answer by searching, reading, or choosing a default. Ask only when blocked (no network, ambiguous legal status, needs hardware). When you pick a default, write it in `targets/<slug>/TARGET.md` under Assumptions and move on.

## Ground rules (non-negotiable)
1. Authorized, interoperability-focused work on hardware and software the user owns or may lawfully analyse. Do not defeat paid-feature gates, DRM, or other users' accounts. Do not touch vendor servers beyond downloading the public artifact.
2. Static analysis only by default. Never install or run the target app. Dynamic work (emulator, capture) only if the user asks.
3. Never commit vendor artifacts: APK, XAPK, IPA, dex, jar, `.so`, firmware images, decompiled trees, third-party assets, tokens, or signed URLs. Commit notes in your own words, hashes, source URLs, scripts, original code, tests. `python tools/rw.py lint` enforces this.
4. No emoji in docs or code. Plain ASCII punctuation where easy.
5. Every factual claim carries an evidence tag (below). Untagged claims are bugs.
6. Never hard-code a result from a simulator as "confirmed". A simulator written by you only proves consistency.
7. Protect the device: before adding any "send often" feature, find out what a write costs (flash wear, bricking) and add a guard first. Never ship firmware-write code paths unreviewed.

## Evidence tags
`[C]` confirmed in the artifact (cite file and line or method) · `[V]` verified by an emulator or test vector against real code · `[H]` confirmed on real hardware (capture or report) · `[W]` third-party claim, unverified · `[I]` inferred · `[U]` unknown.
Conflicting values live only in `targets/<slug>/FACTS.md`; other docs link there.

## Logs you maintain
- Problem log: `targets/<slug>/LOG.md` records every problem hit, with the evidence, the cause, and the fix, or "open" plus what is needed. Read it before resuming a target. Append the moment something goes wrong, in the same commit as the related change when practical.
- Fixes list: `FIXES.md` at the repo root has "Open" and "Fixed". Anything you find that needs fixing (a tool bug, a template gap, a skill that misled you) goes under Open; when fixed, move it to Fixed with what was wrong and what changed. Same commit as the change.
- When a log entry repeats across targets, promote it into the matching skill and delete the repetition.

## Platform support
- Supported for now: Linux (Debian/Ubuntu, including headless containers) and macOS. Others are paused: do not test on them or maintain their guides, but keep code portable (`os.path`, no shell-only syntax in Python tools).
- When you add a dependency, script, or setup step, update `README.md` and `tools/setup-tools.sh`.
- If the platform lacks something the work needs (no Bluetooth adapter, no display, no root, no network to a mirror), tell the user which platform, what is missing, and the options you see. Do not silently skip it or work around a design rule. Record it under Open in `FIXES.md`.
- Say which platforms you actually ran a change on and which are untested.

## Contact with real systems
Real systems means a physical device, a vendor server, a store listing, or any live service. Static work on downloaded artifacts needs no permission; contact with real systems does.
- Ask the user before every live session. Plan the budget up front (requests, connects, writes) and count everything, including clicks and retries.
- Stop at the first sign of throttling, a verification page, a captcha, an auth challenge, or an unexpected device response. Do not push through.
- Device writes follow the safe-write rule in ground rule 7. Read-only probing comes first, one write at a time after that.
- Never place an order, enter credentials or payment data, solve a CAPTCHA or OTP, or log in with the user's account. Those are the user's steps; stop and ask.
- No stealth plugins, fingerprint spoofing, header forgery, or protection bypass, even if a step seems to need it. Raise it with the user.

## UI and docs style
- No emoji anywhere in an interface, doc, or code. Use icon components (for example Lucide) in any UI.
- Keep docs in your own words, plain and specific. Do not restate a fact that lives in FACTS.md; link it.

## Build workflow
- The plan lives in docs, not in your head: `targets/<slug>/TARGET.md` (goal, gates) and `PROTOCOL.md` (how things work). If a design decision changes, update the doc in the same commit.
- Work in phases: a coherent chunk that passes its own checks (tests, `python tools/rw.py lint`). Commit after every finished phase; push after every gate. Message format: `<slug> G<n>: <what the phase delivers>` plus a short body.
- Never push to `main` directly. Use the designated work branch and offer a pull request when a gate set is done; do not open one unasked.
- Capture-independent work (pure codecs, state machines, simulators, tests) may be built before hardware or captures exist. Capture-dependent work (timings, real limits, vendor quirks) waits for real data. Mark built-ahead work as such; no claim becomes `[H]` without hardware evidence.
- Stop and ask when a step needs the user: logins, installs needing root, payments, providing hardware, or approving a write to a real device.
- Never commit `.env`, tokens, signed URLs, personal data (addresses, phone numbers, account ids, device serials, MAC addresses), or captures that contain them. Scrub before saving; mask addresses by default.

## Workspace layout
```
targets/<slug>/      one directory per target, created by `python tools/rw.py init <slug>`
  TARGET.md          brief, goal, assumptions, gate status
  SOURCES.md         where each artifact came from, size, SHA-256, version
  FACTS.md           single source of truth for disputed values
  PROTOCOL.md        byte-exact spec with tags and worked examples
  LOG.md             dated problem log, newest at the bottom
  HANDOFF.md         final report: what is done, what is unverified, next hardware steps
  artifacts/ work/   git-ignored
client/<slug>/       original client code, simulator, tests (created at gate 4)
FIXES.md             open and fixed issues in this repo itself
templates/           copied by init
tools/               rw.py (init, doctor, hash, recon, lint), btcap.py, crcfind.py, setup-tools.sh
```

## Gates (do not skip, do not reorder)
| Gate | Done when | Skill |
|---|---|---|
| G0 Brief | slug, goal, assumptions written | re-workflow |
| G1 Acquire | artifact downloaded, validated, hashed, SOURCES.md written | re-acquire |
| G2 Surface map | transports, UUIDs/ports, entry points, stored keys listed with tags | re-static |
| G3 Spec | PROTOCOL.md with framing, checksums, auth, state machine, worked vectors | re-protocol-spec, re-native-emulation |
| G4 Client | layered client + simulator + dry-run, tests green, repo lint green | re-client-sim |
| G5 Handoff | HANDOFF.md, hardware test plan, LOG.md complete | re-workflow |

Work gate by gate without waiting for approval between gates. Commit and push at each gate. Update `TARGET.md` gate table as you go.

## Habits that paid off
- Start from the UI action (the click that connects or sends), not the first constant you grep.
- Follow constants, string literals, and stored keys through obfuscated code; do not rely on class names.
- Probe every tool with a version flag or a ten-second smoke test before relying on it. Prefer user-space installs.
- Keep the problem log from the first minute. Most log entries become procedure.
- Where a decompiler fails on a method, read smali or use a second decompiler; record behaviour, not code.
- Keep every uncertain value a named constant or CLI flag so first hardware contact needs flag changes, not rewrites.
- A negative result ("this library holds no limits") is a result. Write it down.

## Output discipline
Short commits per gate. Final message: what was produced, what is tagged `[C]` versus `[I]`/`[U]`, what only hardware can settle, and the exact next command.
