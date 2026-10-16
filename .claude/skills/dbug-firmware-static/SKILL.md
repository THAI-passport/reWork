---
name: dbug-firmware-static
description: Static analysis of firmware images. binwalk-style extraction, filesystem parsing (squashfs/jffs2), UART/JTAG pinout documentation, firmware signature verification, and bootloader analysis. Gate G2 surface map for firmware targets.
---

# dbug-firmware-static (Gate G2: Firmware)

Firmware images are vendor-provided binary blobs (flash dumps, OTA updates, BIOS/UEFI, bootloader). Static analysis proceeds without installing or running on hardware (AGENTS.md ground rule 2). No flashing without explicit user approval (ground rule 7).

## 1. Firmware image types
- Flash dumps (raw binary, often with header)
- OTA update packages (signed/encrypted payloads)
- BIOS/UEFI ROM images
- Bootloader images (U-Boot, etc.)

## 2. Static analysis steps
1. **Format identification:** magic bytes, file size, known headers (U-Boot `U-Boot`, squashfs `hsqs`, jffs2 magic `0x1985`).
2. **binwalk-style extraction:** scan for embedded filesystems, compressed streams, certificates, private keys, embedded ELF/PE binaries, scripts.
3. **Filesystem parsing:** squashfs (unsquashfs), jffs2 (jffs2dump), initramfs (cpio), FAT/ext2/ext3 partitions.
4. **UART/JTAG pinout documentation:** identify TX/RX/GND pins from PCB photos or schematics (user-provided only). Document baud rates (commonly 115200).
5. **Bootloader analysis:** U-Boot environment variables, boot commands, console access, secure boot status.
6. **Signature verification:** check for digital signatures, secure boot flags, encryption headers.
7. **String extraction:** URLs, IP addresses, credentials, API keys, hardcoded secrets, build metadata.
8. **Binary entropy:** identify encrypted/compressed regions (high entropy = `[U]` pending decryption).

## 3. Output
Write into PROTOCOL.md a surface map: firmware type, format, filesystems found, extracted binaries/scripts, UART pinout (if documented), bootloader info, signature status, high-entropy regions. Every row tagged `[C]` (confirmed in image) or `[U]` (unknown).

## 4. Evidence tags
- `[C]` confirmed in firmware image
- `[U]` unknown (encrypted/compressed, requires hardware to verify)
- Never `[H]` without hardware access (user must provide device and UART capture).

## 5. Dependencies
- `binwalk` (optional; `setup-tools.sh`)
- `unsquashfs`, `jffs2dump`, `cpio` (optional system tools)
- Stdlib-only fallback: pure Python magic-byte scanning and string extraction