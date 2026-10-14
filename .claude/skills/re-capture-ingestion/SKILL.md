---
name: re-capture-ingestion
description: Turn a Bluetooth HCI snoop log or pcap/pcapng file into protocol evidence - how the owner captures it from a phone, ingesting with tools/btcap.py, mapping handles to UUIDs, reassembling MTU chunks, scrubbing addresses, tokens and personal text with tools/scrub_capture.py, and promoting findings into PROTOCOL.md and FACTS.md as [H]. Use whenever the user supplies or asks for a capture, or asks to scrub MAC addresses, tokens or notification text from a capture before committing a fixture.
---

# re-capture-ingestion

A capture of the vendor app talking to a real device is hardware evidence `[H]` for what the app did and what the device answered. It does not prove behaviour the capture did not exercise.

## How the owner captures (they do this, not you)
- Android: enable Developer options, "Enable Bluetooth HCI snoop log" (choose the full mode, not a filtered one, which can strip payloads [U on some versions]); toggle Bluetooth off and on so service discovery is captured; run exactly one scripted action; stop. Retrieve with a bug report (`adb bugreport`, the snoop log is inside the zip) or a vendor-specific path; the location varies by device and version [U], so check the phone's developer settings text.
- iOS: Apple's Bluetooth logging profile with PacketLogger or a sysdiagnose [W]; steps vary by version.
- Wi-Fi modes: a packet capture on the device's access point (tcpdump or Wireshark on the computer joined to it).
- Keep a timestamped action list next to the file: "12:01:10 open app, 12:01:25 tap connect, 12:02:00 send dial".
- Never ask for credentials, and tell the owner the capture contains addresses and possibly personal data.

## Ingest
```
python tools/btcap.py capture.btsnoop [--hex-limit 48] [--json out.json]
```
Reads btsnoop (datalinks 1001 and 1002), pcap and pcapng (linktype 187 or 201), reassembles ACL fragments, maps value handles to UUIDs from discovery responses in the capture, prints writes (W), notifications (N) and reads (R). It does not decode payloads; use the target's PROTOCOL.md for that.
1. Run it, read the UUID table first: which services and characteristics carried traffic.
2. Handles with no discovery print as `h=0x....`: the capture started after discovery. Ask for a new one (Bluetooth off and on first) or map handles by hand from known writes.
3. Split by action using the owner's timestamps. For each action list the writes and the replies in order.
4. Reassemble application frames across writes (MTU chunking) before decoding; chunk boundaries are not frame boundaries.
5. Validate checksums yourself. Report bad checksums and sequence gaps instead of dropping the frames: they are findings (or a sign you picked the wrong framing).
6. Compare with the spec in PROTOCOL.md: every byte that differs from the spec is a correction. Change the tag to `[H]` only for what the capture shows; keep the rest `[I]` or `[U]`.

## Write a decoder only after the spec exists
A target-specific replay tool belongs under `client/<slug>/` or `tools/` of that target, built on btcap's reader. Do not put target decoders in generic tools.

## Scrub and store
- Raw captures contain device addresses, account tokens and sometimes photos or notification text. Do not commit them, and do not commit btcap output unscrubbed.
- Scrub every summary or fixture before committing:
  `python tools/btcap.py capture.btsnoop --json raw.json` then `python tools/scrub_capture.py raw.json -o scrubbed.json --mask <serial> --mask <name>`.
  Addresses become stable pseudonyms (02:00:00:00:00:01, ...), token-like values become `x` runs, and each `--mask` literal is masked in text and in ASCII/UTF-16LE payload hex with lengths kept. Masked payloads no longer match their CRC; the tool says how many. Read the output before committing: notification text and names you did not list are still there.
- Record in the target's LOG.md: which capture, which action, what it settled, what it did not.

## Pitfalls (from the worked example)
- A parser that required a valid checksum to classify a frame silently dropped corrupted ones; classify by structure, then report the checksum result.
- A malformed or truncated file must produce an error, not an empty success.
- Fixtures you generate yourself prove the parser, not the device; label them synthetic.
