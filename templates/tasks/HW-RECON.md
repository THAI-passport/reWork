# Hardware recon tasks: {{name}}

Needs a physical device. Read `README.md` first. Executor key: `HUMAN+AI` = a person runs commands on a machine with the right adapter, the AI prepares the run sheet and interprets pasted output; `HUMAN` = only a person, only with written owner approval. Replace `ADDR`, `CLIENT` and file names with the target's actual values (see `client/{{slug}}/`). Keep `ADDR` in a shell variable; never write real addresses into committed files. After each write wait out the minimum interval and photograph or record the device.

## HW-0. Run sheet, approvals, write budget
1. Collect: device model, whether the vendor app may be used for a capture (approval for HW-1), whether opening the device is allowed (HW-14, default no), machine and OS. If nobody answers use `ASSUMPTIONS.md` and skip HW-1 and HW-14.
2. Prepare: `python tools/make_test_media.py --out testmedia`, client installed, its tests green, device charged above 50 percent, vendor app closed.
3. Fix the write budget from the payload sizes of S7: list each task's write count; total below half the daily cap to leave retry margin.
4. Write `tasks/results/run-sheet-<date>.md`: commands in order with `ADDR` variable, tick column, paste area.

## HW-1. Reference capture with the vendor app (approval required)
Why: the vendor app is ground truth for transport, framing and pacing. Enable the phone's Bluetooth HCI snoop log (Android) or use PCAPdroid for Wi-Fi traffic; do one still and one animation through the vendor app only; pull the log; keep it OUTSIDE the repo; decode with `python tools/btcap.py file` and compare with PROTOCOL.md. Every difference is a finding; confirmed items become `[H]`.

## HW-2. Scan and read-only qualification
Writes: 0. Put the device in its pairing/discoverable mode. Scan for everything, then with the model filter; run the client's read-only qualification (scan, connect, MTU, GATT, transport decision, listen for status, report with masked addresses). Record name, services, MTU, status fields. Interpretation: the discovered service set decides the transport (assumption A2); an unknown set means stop writing and run HW-3 and HW-1. No status push is not a failure: read it after the first write.

## HW-3. Second-radio survey
Writes: 0. Look for Wi-Fi SSIDs or other radios the device exposes; if found, join only if open or documented, record gateway and open ports once. If none, mark any dependent task `skipped: not applicable`.

## HW-4. Dry runs
Writes: 0. Dry-run every send you plan to make; keep the frame logs and payload files for comparison with captures; note payload sizes.

## HW-5. Container/format acceptance tests
Writes: 2 per alternative encoding. Send the same labelled test image through each candidate container or format (use the target's PROTOCOL.md alternatives), photographing the result. Table: A shows/B blank -> keep A; both show -> keep default; A blank/B shows -> flip the model profile default and add a test; neither -> go to HW-6 and compare with the HW-1 capture.

## HW-6. Size, shape, orientation
Writes: 3. Send the labelled-corner gradient at each candidate size and without any mask. Record corner labels visible, mirroring, rotation, centring, wrapped edge pixels. Settle disputed sizes in FACTS.md with `[H]`.

## HW-7. Free space and rewrite behaviour
Writes: 3. Needs the status/free-space value (qualification report or the send log's status line).
1. Read free space F0 twice. 2. Send the large noise image (payload P), read F1. 3. Wait out the interval, send the identical payload with the no-delta option, read F2. 4. Send a different image, read F3.
Interpretation (D1=F0-F1, D2=F1-F2, D3=F2-F3): D1 about P with D2 about 0 -> overwrite of a single slot; D1 and D2 both about P -> append/log allocation (rewrites consume space and wear; keep the cap); D1 about 0 -> lazy or RAM accounting, repeat after a power cycle; values in page-sized steps -> page-granular accounting. Update the guard's documentation with measured behaviour (`[H]`). Stop if free space falls below a few MB; recovery is a vendor-app delete.

## HW-8. Power-cycle persistence
Writes: 0. After HW-7 power the device fully off with the documented method (do not open it), wait 10 s, power on. Picture returns -> non-volatile; blank/default -> volatile or reset.

## HW-9. Throughput
Writes: 5. Send the animation five times (no-delta after the first), `time` each, compute payload/seconds, record MTU, ack mode, retries, failures. No pass/fail on speed; fail only on dropped transfers or disconnects. Compare with predicted bounds in the streaming plan.

## HW-10. Length and size limits
Writes: up to 6. Send clips of increasing length (for example 2, 3, 4, 5, 8, 10 s); stop at the first freeze, reboot, disconnect or refusal. Record completion, playback behaviour, payload size, free space before and after. The longest clean clip sets the profile cap.

## HW-11. Passive notification/event logging
Writes: 0. `python tools/notify_log.py ADDR --seconds 90 --json events.jsonl` while performing every physical interaction (touch gestures, each button, shake, charging plug/unplug) in a noted order. Result is either "no events" (a valid answer) or raw hex with the correlated action. Events found -> PROTOCOL.md `[H]` and a FIXES.md item for a parser.

## HW-12. Non-destructive physical survey
HUMAN, no opening. Regulatory database entry (grantee, bands, internal photos), label photo with serials blurred, external seams/screws/ports, optional DMM check of USB CC resistors with the device off and unplugged.

## HW-13. USB/serial enumeration (observe only)
HUMAN. Plug in, record the descriptor strings, VID:PID and what the screen shows (`lsusb`, `system_profiler SPUSBDataType`, `Get-PnpDevice`). Do not mount, format, write, or enter any download mode.

## HW-14. Destructive teardown and read-only dump (approval required)
HUMAN only; written approval for a unit the owner is willing to lose. Plastic tools, battery disconnected first, heat below about 60 C. Identify chips from macro photos; measure the flash rail BEFORE connecting any programmer (1.8 V parts are common; a 3.3 V programmer destroys them); flash may be inside the SoC package, so first check whether a dump point exists. Read twice and require identical SHA-256. Dumps go to `dumps/` (git-ignored), never to git; commit only notes (layout, offsets, hashes). Never write, erase or flash. Analysis of a dump the human supplies (`binwalk`, `strings`, file-system and display-init search) is AI work.

## After hardware tasks
Update only what the evidence changes, with tag `[H]` and the result file as source: transport and sizes -> FACTS.md and PROTOCOL.md; container/format defaults -> the client profile, with a test; limits -> profile and FACTS.md; flash behaviour -> the guard's documentation (thresholds only with owner approval); a wrong byte -> PROTOCOL.md, builder, test vector and simulator together; anything surprising -> LOG.md. Then `STATUS.md`, commit, push, and report: what is now `[H]`, what contradicted the code, what is still unknown, the next test.
