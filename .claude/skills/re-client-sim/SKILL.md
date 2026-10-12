---
name: re-client-sim
description: Build the open client for a reverse-engineered device in layers (pure byte builders, media/conversion, async session over an abstract link, CLI), plus a software device simulator, dry-run mode, safe-write guards, fixtures, tests, repo-rules lint and CI. Use after the protocol spec exists.
---

# re-client-sim (gate G4)

Location: `client/<slug>/` with its own `pyproject.toml` (core deps minimal, `[test]`, optional `[emulation]`). Python 3.10+. Bluetooth via `bleak`, sockets via stdlib, USB via `pyusb` only if needed.

## Layers (build in this order)
1. **Pure codecs**: frame builders and parsers, checksums, containers. No I/O. Unit tests round-trip against an independent parser written in the test.
2. **Media/conversion** (if the device shows or plays media): Pillow for images, ffmpeg via subprocess for video, behind a clear "ffmpeg missing" error; tests skip without it.
3. **Link abstraction**: `Link` protocol with `write`, `notify callback`, `mtu`, `services`. Only one class touches real hardware. A `RecordingLink` logs every write and simulated notification for dry runs.
4. **Session**: async state machine from PROTOCOL.md (discover, enable notify, bind/auth, query, transfer). Transport chosen by discovery, not by name.
5. **Simulator**: implement the device side from the spec, including auth and device-pulled transfers. Run the real session code against it. This finds client state-machine bugs. It shares your misreadings, so label results accordingly.
6. **CLI**: `scan`, `probe` (read-only: advertisement, MTU, GATT dump, transport decision, first reply, writes nothing), action commands with `--dry-run <file>`. Every uncertain value is a flag.
7. **Profiles**: per-model data object; CLI flag selects data only.

## Safe-write guard (before any repeated-send feature)
Per-device state file keyed by a hash of the address: write counter, last payload hash (skip identical), minimum interval, hard daily cap, warnings; count only after success; dry runs never count.

## Fixtures, lint, CI
- Generate small synthetic captures with the same builders, commit with a manifest that says SYNTHETIC and a `--check` mode so drift fails CI. Include one deliberately malformed capture; the tools must report it, not crash.
- Test that the client package contains no vendor URLs, analytics hosts, or network modules beyond the declared transport (`test_no_vendor_calls`).
- `python tools/rw.py lint` in CI. Workflow file: matrix of Python versions, install `.[test]`, run lint then `pytest -q`. Do not write test counts in prose.
- Dependency discipline: every test needing an optional package or native artifact uses `importorskip` with a reason.

## First-contact tooling
`probe --qualify` writes a report shaped like the hardware test template (masked addresses, git-ignored). Provide a hardware checklist: order of operations, what to capture, what a failure looks like, stop conditions.

## Done when
`pytest -q` is green with no hardware, dry-run output is inspectable, and HANDOFF.md lists which assumptions only hardware can verify.
