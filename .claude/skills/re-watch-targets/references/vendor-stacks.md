# Vendor stack signatures (reference for re-watch-targets)

Recognition hints only. Sources were gathered by an external review (2026-10-14) and not re-read by us; links are given so the next pass can check them. Every row is `[W]` (public documentation or common knowledge, not verified against your target) unless marked `[U]`. Confirm in the app you are analysing and re-tag in the target's FACTS.md and PROTOCOL.md. Package names are what to grep for; exact class names vary by SDK version.

## Signatures
| Stack | App-side signs | GATT signs | OTA / file layer | Notes |
|---|---|---|---|---|
| Jieli (JL) | `libjl_*` natives, `com.jieli.*` | 0xAE00 (0xAE01 write, 0xAE02 notify) | `jl_bt_ota`. The official OTA SDK docs put OTA on the same 0xAE00 link (device pulls blocks, opcode 0xE5 with seek and length) [W: doc.zh-jieli.com jl_ota_sdk_qa]. 0xAE10/0xAE20 have no known source | blocking a service id does not stop Jieli OTA; block the OTA opcodes. See `re-jieli` |
| Nordic nRF5 (legacy SDK) | `no.nordicsemi.android.dfu` | Secure DFU 0xFE59; legacy DFU 00001530-1212-EFDE-1523-785FEABCD123; Nordic UART 6E400001-B5A9-F393-E0A9-E50E24DCCA9E | DFU init packet + firmware image in a zip | buttonless DFU is a write that reboots into the bootloader: never send |
| Nordic nRF Connect SDK / Zephyr | `io.runtime.mcumgr`, `no.nordicsemi.android.mcumgr` | SMP service 8D53DC1D-1DB7-4CD3-868B-8A527460AA84 | mcumgr image upload, CBOR payloads | SMP also has read-only groups (image list, OS echo); the image and fs groups write |
| Realtek | `com.realsil.sdk.*`, `com.realtek.*` | Realtek base `xxxxxxxx-3c17-d293-8e48-14fe2e4da212`: OTA service 0xD0FF (chars 0xFFD1-0xFFD4, 0xFFF1), DFU data service 0x6287, vendor data 0xE0FF (often write 0xFFE9, notify 0xFFE1) | Realtek DFU library | [W: Realtek wristband demo `dfu/DfuService.java` in github.com/Ox10cx/WristbandDemo]; varies per SDK |
| Telink | `com.telink.*` | OTA service 00010203-0405-0607-0809-0a0b0c0d1912, OTA char 00010203-0405-0607-0809-0a0b0c0d2b12 (read, write without response) | Telink OTA, sequential indexed packets with CRC; images reported to carry ASCII `KNLT` at offset 8 | [W: Telink `UuidInformation.java` in a public mesh SDK copy; atc1441 TelinkFlasher; pvvx/ATC_MiThermometer issue 302] |
| Huami / Zepp (Amazfit, Mi Band) | `com.huami.*`, `com.xiaomi.*` | 0xFEE0 and 0xFEE1 | firmware and watch faces over a vendor chunked transfer | AES auth with a per-device key from the vendor account at pairing; never obtain it from the user's account |
| Bluetrum (AB5xxx, BT8958) | `com.bluetrum.fota` | 0x18A8 ("Cus5610") appears only in the imported landscape doc, no primary source: keep it blocklisted anyway | `com.bluetrum.fota`; RISC-V cores; `bluetrum_nimble` BLE stack in the public BSP | [W: tomLadder/thermoprint REVERSE_ENGINEERING.md] |
| Actions (ATS), Bestechnic (BES) | package names [U] | no public fixed UUIDs; OEMs define their own tables [W] | [U] | unknown until recognised in the APK |
| Goodix, Dialog/Renesas, Ambiq | SDK package names in the app | [U] | [U] | treat as unknown until read |

## White-label app families [W]
| App | Package | Stacks reported | How the protocol is chosen | Public notes |
|---|---|---|---|---|
| FitCloudPro (TopStep) | `com.topstep.fitcloudpro` | Realtek, Bluetrum dual-mode | capability bitmask in the bind/login handshake | gadgetbridge.org gadgets/wearables/fitcloud |
| Da Fit (Moyoung) | `com.crrepa.band.dafit` | Goodix, Nordic, Realtek, Jieli | Device Information Manufacturer Name 0x2A29: `MOYOUNG` = V1 fixed packets, `MOYOUNG-V2` = MTU-chunked `FE EA` frames on 0xFEEA | gadgetbridge.org internals/specifics/moyoung-protocol |
| VeryFit (IDO) | `com.watch.life`, `com.sport.fitplus1` | Realtek, Nordic | service 0x0AF0 (write 0x0AF6, notify 0x0AF7); `02 <cmd>` commands, V3 bulk frames with `DA AD DA AD` preamble and CRC16 | sprocketfox.io xssfox 2025-02-09 "ido"; d3nd3/toobur-veryfit-research |
| GloryFit / GloryFitPro | `com.yc.gloryfit`, `com.yc.gloryfitpro` | Realtek, Bluetrum, Jieli | two apps, two different wire protocols; features gated by device info | gadgetbridge.org gadgets/wearables/gloryfit and gloryfitpro |
| CO-FIT | `com.codingiot.co.fit` | budget Jieli/Bluetrum/Realtek [W] | [U]: no public write-up | Play listing only |
Gadgetbridge source is the best second opinion for these: read its implementation as `[W]`, and confirm in the app you analyse.

## Protobuf-heavy ecosystems
Huami/Zepp (newer generations), Xiaomi, Huawei and Garmin are widely reported to wrap commands in Protocol Buffers or nested TLV instead of fixed offsets [W]. Look for `com.google.protobuf`, generated `*Proto` classes, or nanopb symbols in natives; then follow `re-protocol-spec` section "Protobuf and TLV".

## Read-only safe probes per stack
- Nordic SMP: OS echo and image state list are reads; image upload, erase, reset and fs write are not.
- Any stack: anything named ota, dfu, upgrade, firmware, erase, format, reset is outside the budget. Record the ids; never send.
