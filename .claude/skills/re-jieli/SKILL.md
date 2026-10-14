---
name: re-jieli
description: Jieli (JL) Bluetooth SoC family (BR28 / AC701N, AC69xx and relatives) as seen from a companion app - recognition, RCSP frame layout, the E1 over SAFER+ authentication handshake, large-file transfer, FatFS and gallery notes, OTA awareness (read-only), and Jieli-specific notes for emulating libjl_auth. Use whenever an app or device shows Jieli signs - libjl_* natives, com.jieli.* packages, GATT service 0xAE00, FE DC BA ... EF frames in a capture, or SAFER+ authentication.
---

# re-jieli

All concrete values below come from one worked example (a Jieli-based BLE display device; see knowledge/ for example projects). Tags: [C] confirmed there in app code, [V] verified by emulation there, [W] third-party report, [U] unknown. They are a starting hypothesis for a new device: check each against the app you are analysing before relying on it.

## Recognise it in an app
- Native libraries named `libjl_*` (examples: `libjl_auth.so`, `libjl_crc.so`, `libjl_fatfs.so`) in the arm64 split. List them with `unzip -l` on the ABI split. [C]
- Java packages under `com/jieli/` (`jl_rcsp`, `jl_bt_ota`, `jl_audio` and similar). Names survive obfuscation because the SDK is shipped as a library. [C]
- Services: a 16-bit service 0xAE00 with 0xAE01 (write without response) and 0xAE02 (notify) for the RCSP link, and often a second vendor control service whose base UUID starts with a 128-bit vendor prefix (the example used `C2E6FD00-...`) for the app's own commands. [C]
- Wire frames beginning `FE DC BA` and ending `EF`. [C]
- Advertising: a vendor tag byte in manufacturer data plus a shape or product byte; do not assume it carries the model. [C for the example]
- Chip evidence is usually [W]: FCC internal photos, a USB mass-storage identifier containing "UDISK", teardown posts.

## RCSP frame [C in example]
`FE DC BA | flag(1) | opcode(1) | length(2, big endian) | body | EF`. Body of a command is `sn(1)` then parameters; body of a response is `status(1) | sn(1) | parameters`. `sn` is a per-link counter that wraps at 256. Opcode 0x01 (data) inserts one inner opcode after `sn`. Flag bit 7 marks direction (command from the app) and bit 6 whether a response is wanted; confirm both from the frame builder in your app. Each frame is split into ATT writes of at most MTU minus 3 bytes by a sender thread. Example frame from the worked target: `FE DC BA C0 21 00 02 01 00 EF` (flag C0, opcode 0x21, length 2, sn 1, one parameter byte).

## Authentication (E1 over SAFER+) [C, V]
- Runs on every new connection before any RCSP frame, on raw GATT writes to 0xAE01 and raw notifications from 0xAE02 (not RCSP framed). Timeout about 5 s.
- Messages: `00 | R[16]` challenge, `01 | E1(R)[16]` answer, `02 70 61 73 73` ("\x02pass") accept.
- Exchange in the example app: reset-auth-flag RCSP frame, then the app sends its challenge and checks the device's `01` answer; only then it answers the device's own challenge; the device sends `02 pass` when it accepts the app. A client must implement both directions.
- Algorithm: the Bluetooth Core legacy authentication E1 on SAFER+ with the standard tables, a fixed 6-byte address, a constant default 16-byte key embedded in the library, and all 16 output bytes returned. The app never sets another link key in the example [C]; check `setLinkKey`-style calls in yours.
- Whether a device enforces auth, and whether it uses the default key, cannot be settled without hardware or a capture [U].

## Large-file transfer [C in example]
Device-pulled: CRC-16/XMODEM of the whole file, `NotifyPrepareEnv` (opcode 0x21), optional device extend parameter (0x27), `StartLargeFileTransfer` (0x1B: size, CRC, temp path with NUL), then the device sends read requests (0x1D: size and offset) and the app answers with data frames; the device may ask for the final name (0x20) and ends with Stop (0x1C, reason 0 = success). Honour the device's requested offsets, ignore repeats, watch for silence (use a no-progress watchdog, 20 s in the example). File-name encodings differ per command (ASCII temp name, UTF-16LE in one reply): read the builders, do not guess.

## FatFS and gallery notes
`libjl_fatfs` is a FAT implementation; a 16 MiB NOR flash with a FAT16 gallery is reported for one product [W]. Native libraries often hold no limits at all; that negative result is worth recording [C]. The SDK defines storage-management commands (browse, delete by name, format, read file). Treat delete and format as destructive: record their ids, never send them [U for payloads].

## OTA: read-only awareness
`jl_bt_ota` implements firmware upgrade over the same transport: the official OTA SDK docs put it on 0xAE00 itself, with the device pulling blocks (opcode 0xE5, seek and length) [W]. A service-UUID blocklist therefore does not stop Jieli OTA; the client must refuse the OTA opcodes. Study the flow to know what a watch accepts, and to know what to avoid. Never send OTA data to a real device; a bad image bricks it. Record only which service, characteristics and commands are involved.

## Emulating libjl_auth [V]
Use `re-native-emulation` and its harness for the generic unicorn setup (CPACR_EL1, TPIDR_EL0, PLT hooks returning to LR). Jieli specifics:
1. Find the E1 entry from the JNI natives of the auth class; the SAFER+ tables and the default key sit in `.rodata`/`.data`.
2. The address input is a fixed 6 bytes; check how the app pads or orders it before calling.
3. Port stage by stage (SAFER+ key schedule, rounds, E1 wrapper) and compare each stage with the emulated library, not only the final output. Keep emulator vectors as tests (50 random key, address and input triples were used) and skip cleanly when unicorn is missing.
4. Emulation proves your port equals the library, not that a device accepts it.

## Pitfalls
- jadx may merge branches in the bind and info decoders; where a layout looks odd read smali.
- A hand-written simulator can carry the same mistake as the client (a wrong length-field width stalled a transfer); build the simulator from the spec, then from captures.
- The device-side challenge arrives unprompted; a client that waits for a request deadlocks.
- RCSP and the vendor control service are different layers; the control service had its own checksum and frame header in the example.
- Record the SDK version if the app prints it; behaviour changed across versions [U].
