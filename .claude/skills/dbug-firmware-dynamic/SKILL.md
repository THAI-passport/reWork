---
name: dbug-firmware-dynamic
description: Dynamic analysis of firmware via emulation. QEMU-user/qemu-system emulation, unicorn-based firmware blob emulation, serial/UART capture, flash wear analysis. Gate G4/G5 for firmware targets. Emulation-only by default; no flashing without explicit user approval (ground rule 7).
---

# dbug-firmware-dynamic (Gate G4/G5: Firmware)

Firmware dynamic analysis uses emulation rather than physical hardware by default. Flashing firmware to a device carries brick/flash-wear risk and requires explicit user approval (AGENTS.md ground rule 7).

## 1. Emulation approaches
1. **QEMU-user:** emulate individual ELF binaries extracted from firmware (userspace, no kernel).
2. **QEMU-system:** full-system emulation of the target SoC/board (kernel, peripherals, flash).
3. **Unicorn:** CPU-level emulation of specific firmware functions (string decryption, boot routines).
4. **Serial/UART capture:** connect to device UART pins (TX/RX/GND) at documented baud rate; capture boot logs and runtime output.

## 2. Dynamic analysis steps
1. **Extract bootloader/kernel** from firmware image.
2. **QEMU-user:** run extracted userspace binaries under emulation, observe syscalls and network behavior.
3. **QEMU-system:** boot full firmware image in emulated machine, observe boot process, services, network.
4. **Unicorn:** emulate specific functions (e.g., string decryption, credential checking) to recover plaintext without running full firmware.
5. **UART capture:** connect to device, capture boot console output, look for debug shells, password prompts, firmware version strings.
6. **Flash wear analysis:** estimate erase/write cycles before recommending any flash operation (ground rule 7).

## 3. Safety
- **Never flash firmware without explicit user approval.**
- Emulation is read-only and safe.
- UART capture is read-only and safe.
- Document flash wear cost before any write operation.

## 4. Output
- `firmware_emulation_report.md` — boot behavior, services, network, decrypted strings, debug shells found
- `uart_capture.log` — raw UART output (sanitized of any credentials)
- Sync to `targets/<slug>/` per AGENTS.md contract

## 5. Evidence tags
- `[V]` verified against emulation/simulation
- `[I]` inferred from static analysis
- `[H]` only with real hardware UART/capture (user must provide)
- Never claim a firmware is "secure" or "insecure" based on emulation alone.

## 6. Dependencies
- `qemu-user`, `qemu-system` (optional; `setup-tools.sh`)
- `unicorn` Python module (optional; `setup-tools.sh --emulation`)
- User-provided firmware image only (never committed)