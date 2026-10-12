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
