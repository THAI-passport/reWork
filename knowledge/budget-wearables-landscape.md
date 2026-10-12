# Budget wearables landscape (knowledge note, imported)

> Imported 2026-10-12 from an external write-up; an example of what to learn before reverse engineering a cheap white-label wearable. Every claim is `[W]` (third-party, unverified) unless a target's own PROTOCOL.md confirms it. This is knowledge, not a target of this repo: work on it happens in a fork (for example reWatch). Known flaws of the source: a stray JSX `<Callout>` tag, a garbled flash-size range for the Jieli parts, and an anecdotal claim that the health sensors are cosmetic.

# Ultra-Budget Smartwatch Reconnaissance: C900, T900, and Clones

Audience: Reverse engineers, embedded software developers, and clean-room client architects.
Target Devices: C900 Ultra / Pro Max, T800 / T900 Ultra / Ultra 2, Hoco Y23, and generic Apple Watch Ultra replicas (100–250 THB price tier).

---

## 1. Market Ecosystem & White-Label ODM Reality

The sub-250 THB ($3–$7 USD) smartwatch market operates on high-volume, low-margin white-label designs developed by Shenzhen Original Design Manufacturers (ODMs) and solution houses.

```
+---------------------------------------------------------------+
|                      Shenzhen ODM Solution                    |
|      (Firmware, PCB Layout, Reference Android App Template)   |
+---------------------------------------------------------------+
                               |
         +---------------------+---------------------+
         |                                           |
+---------------------------------+         +---------------------------------+
|         JieLi Ecosystem         |         |        Bluetrum Ecosystem       |
|    (JL7012, AC6954, AC6958)     |         |             (AB5xxx)            |
+---------------------------------+         +---------------------------------+
         |                                           |
         v                                           v
  HiWatch Pro / Da Fit                       HryFine / FitPro
         |                                           |
+---------------------------------+         +---------------------------------+
|   T800 / T900 Ultra Series      |         |   C800 / C900 / BOOD Series     |
+---------------------------------+         +---------------------------------+
```

### Commercial Entities vs. Branding
* Brands like **Hoco**, **Kospet**, or unbranded generic boxes ("Ultra Watch") do not write software. They purchase assembled motherboards or complete boxed units from solution houses (such as Shenzhen Jusheng, Yscoco, or Micro-intelligence).
* Companion applications exist primarily to generate passive ad revenue and gather user analytics. The underlying BLE synchronization protocols are straightforward and can be completely replaced with offline, clean-room software.

---

## 2. Silicon Families & Microcontroller Architectures

Unlike smartphones or high-end smartwatches that use ARM Cortex-A or multi-core Cortex-M33 processors, budget replicas run on cost-optimized Chinese microcontroller architectures.

### 2.1 JieLi Technology (Zhuhai Jieli)
* **Prevalent Parts:** **JL7012 series (JL7012A6, JL7012F6)**, **AC6954**, **AC6958**.
* **CPU Core:** Proprietary **Pi32 core** (32-bit RISC architecture, custom instruction set, 16/32-bit variable instruction length).
* **Clock & Memory:** Typically 120 MHz–160 MHz; 128 KB internal SRAM; 16 MB–64 MB (2 MB–8 MB) external SPI/QSPI NOR Flash.
* **Radios:** Dual-mode Bluetooth 5.3 (integrated BLE controller + Bluetooth Classic BR/EDR audio baseband for wrist calling).
* **Protocol Footprint:** Uses JieLi RCSP framing (`FE DC BA ... EF`) or vendor-custom command tables. Bootloader updates are managed via proprietary single-wire UART pins (`PRG`, `UTX`, or USB `D+`/`D-`).

### 2.2 Bluetrum Technology (Shenzhen Bluetrum)
* **Prevalent Parts:** **AB53xx / AB56xx series**.
* **CPU Core:** 32-bit **RISC-V core** (commonly RV32IMAC).
* **Radio & Storage:** Dual-mode Bluetooth; embedded or SIP SPI flash memory.
* **Protocol Footprint:** Frequently implements the Nordic UART Service (NUS `6E400001...`) as an application transport layer and utilizes `Cus5610` (`0x18A8`) for over-the-air firmware upgrades.

### 2.3 Secondary Contenders (Yichip & HunterSun)
* **Yichip YC1133 / YC1136:** Proprietary 32-bit architecture used in lowest-cost C-series production batches.
* **HunterSun HS6621 / HS6621AG:** ARM Cortex-M3 / M4F core with dedicated BLE baseband, commonly paired with the **Wearfit Pro** app ecosystem.

---

## 3. Companion Software Landscape & Wire Protocols

### 3.1 HiWatch Pro (`com.jusheng.hiwatchpro`)
* **Primary Target:** T800 Ultra, T900 Ultra, T900 Ultra 2.
* **App Architecture:** Bundles JieLi Bluetooth SDKs.
* **Permissions & Telemetry:** Invasive background polling, aggressive ad mediation networks, contacts/phone access forced for call audio.
* **Protocol Characteristics:**
  - Employs JieLi command wrappers over proprietary 16-bit or 128-bit vendor GATT services.
  - Commands use explicit opcode headers for time synchronization, alarm configuration, remote camera triggers, and dial management.

### 3.2 HryFine (`com.yscoco.watch`)
* **Primary Target:** C900 Ultra, C800, BOOD W7/X10, ZK5610.
* **App Architecture:** Built around Nordic UART Service (NUS) emulation.
* **Documented Wire Protocol:**
  - **Service UUID:** `6E400001-B5A3-F393-E0A9-E50E24DCCA9F`
  - **Write Characteristic:** `6E400002-B5A3-F393-E0A9-E50E24DCCA9F`
  - **Notification Characteristic:** `6E400003-B5A3-F393-E0A9-E50E24DCCA9F`
  - **App to Watch Frame Structure:**
    $$\mathtt{0xDF} \,|\, \text{Len}_{\text{hi}} \,|\, \text{Len}_{\text{lo}} \,|\, \text{Checksum} \,|\, \text{Cmd} \,|\, \mathtt{0x01} \,|\, \text{Sub} \,|\, \text{PayLen}_{\text{hi}} \,|\, \text{PayLen}_{\text{lo}} \,|\, \text{Payload}$$
    - Total length: $((\text{Len}_{\text{hi}} \ll 8) \mid \text{Len}_{\text{lo}}) + 4$ bytes.
    - Checksum: Modulo-256 sum of all bytes in the frame with `byte[3]` set to `0x00`.
  - **Watch Acknowledgement Frame:**
    $$\mathtt{0xFD} \,|\, \mathtt{0x00} \,|\, \mathtt{0x05} \,|\, \text{Checksum} \,|\, \text{Cmd} \,|\, \text{Key} \,|\, \text{AckLen}_{\text{hi}} \,|\, \text{AckLen}_{\text{lo}} \,|\, \mathtt{0x01}$$
  - **Primary Command Set:**
    - Time Sync: `CMD 0x02, SUB 0x0A`
    - Device Metadata: `CMD 0xF3, SUB 0x00`
    - Battery Query: Standard SIG Battery Service (`0x180F` / `0x2A19`).

### 3.3 Da Fit (`com.crrepa.band.dafit`)
* **Primary Target:** Hoco Y23, MO YOUNG / Crrepa OEM devices.
* **App Architecture:** Cleanest protocol of the budget options; well-structured opcode tables, predictable binary chunking, and fewer invasive SDK layers.

---

## 4. Hardware Teardown Findings: T-Series vs. C-Series

```
+-----------------------------------+-----------------------------------+
|          T900 Ultra Series        |         C900 Ultra Series         |
+-----------------------------------+-----------------------------------+
| Zinc die-cast pot metal           | Dense aluminum/zinc alloy         |
| Cosmetic dummy rear screws        | Real threaded corner screws       |
| Molded non-functional strap locks | Functional spring-loaded locks    |
| Soft PMMA acrylic lens            | Tempered mineral glass            |
| Battery glued directly to LCD     | Internal plastic carrier tray     |
| Silicon: Consistently JieLi       | Silicon: Variable (JieLi/Bluetrum)|
+-----------------------------------+-----------------------------------+
```

### 4.1 The Biometric Sensor Illusion
Teardowns across both T-series and C-series devices reveal that health tracking hardware is purely cosmetic:
* **Physical Assembly:** The rear optical window contains a pair of standard surface-mount green LEDs (0805 package) and a cheap phototransistor (or unpopulated pads).
* **Firmware Emulation:** Pulse, SpO2, and blood pressure readings are generated by firmware software timers. Placing either device on an inanimate object (such as a mug or desk surface) will produce valid heart rate readings centered around 72–85 bpm.
* **Engineering Impact:** Reverse-engineering health telemetry from these watches has zero medical or practical utility. Focus efforts strictly on time sync, display/dial updates, and notifications.

### 4.2 Display Subsystem
* Panels are typically 2.02-inch to 2.09-inch TFT or IPS LCDs with native resolutions of $240 \times 286$ or $320 \times 385$ pixels.
* Interfaced via 4-wire SPI or 8-bit parallel 8080 MCU display interfaces with integrated capacitive touch controllers (CST816 series).

---

## 5. Watch Face (Dial) Binary Structure

Unlike digital badges (which consume raw JPEGs or simple AVI/container streams), smartwatches require pre-compiled binary dial packages (`.bin` files).

### Typical Dial Package Layout
```
+-------------------------------------------------------+
| Header: Magic bytes, target LCD ID, dial version      |
+-------------------------------------------------------+
| Thumbnail: Small RGB565 / JPEG preview (e.g. 128x128)  |
+-------------------------------------------------------+
| Coordinate Table: X/Y offsets for clock, date, widgets|
+-------------------------------------------------------+
| Font Glyph Bitmaps: Numeric digits (0-9), am/pm icons |
+-------------------------------------------------------+
| Background Image: Full-screen raw RGB565 / compressed  |
+-------------------------------------------------------+
```

* **Color Format:** High-speed display controllers use raw **RGB565** (16 bits per pixel, little-endian) rather than decompression-heavy JPEGs to minimize MCU RAM overhead during screen refreshes.
* **Encoding Constraint:** To push a custom watch face, an open-source client must compile an image into an RGB565 byte stream and serialize the metadata block into the structure expected by the specific firmware revision.

---

## 6. Critical Hazards & Bricking Traps (Lessons from the Field)

Recent reverse-engineering efforts documented in the community (e.g., r/hardwarehacking teardowns of HryFine/Bluetrum watches) illustrate critical risks when interfacing with budget bootloaders:

### 6.1 The OTA Bootloader Deathtrap (`0x18A8` / Cus5610)
* **What Happened:** Researchers attempting to flash custom firmware over BLE connected to the watch's OTA bootloader service (`0x18A8`).
* **Root Cause of Bricking:** 
  1. **Instruction Set Mismatch:** The researchers assumed a Telink (TC32) CPU based on GATT UUID patterns, but the physical silicon was a Bluetrum (RISC-V) core. Writing Telink machine code into flash caused the MCU to halt permanently upon reboot.
  2. **Overwriting Active Bootloader Memory:** OTA commands were written to offset `0x00000` and `0x01000`. The bootloader had no write-protection boundaries and overwrote its own executing code mid-transfer, dropping Bluetooth connectivity permanently.
* **Core Rule for Client Development:**
  > DANGER:
  Never issue commands to OTA update services (Service 0x18A8, Cus5610, or JieLi OTA handlers). Restrict client interactions strictly to runtime application characteristics (time sync, settings, watch face upload).

### 6.2 Flash Programming Realities
* If a watch is bricked over BLE, it cannot be restored over the air.
* Physical recovery requires desoldering or cracking the chassis to locate the SoC's single-wire serial bootloader test pads (`PRG` / `UTX` on JieLi; `UART_TX`/`RX` on Bluetrum) and flashing a known good factory dump using vendor programmers.

---

## 7. Recommended Action Plan for Reverse Engineering

1. **Target Selection:**
   - **T900 Ultra (HiWatch Pro):** Recommended if targeting **JieLi architecture** to leverage the existing `reBeamBox` RCSP knowledge base.
   - **C900 Ultra (HryFine):** Recommended if targeting an **already-mapped protocol** (utilizing the documented `0xDF`/`0xFD` NUS frame specification).
2. **Scoping:**
   - Constrain the client scope to **Pairing**, **Time Synchronization**, and **Custom Watch Face Binary Packing**.
   - Strip out all health telemetry, sleep monitoring, and background tracking routines.
3. **Architecture:**
   - Implement the watch client directly inside the existing `reBeamBox` transport architecture by adding a dedicated session handler (`rebeambox/hryfine.py` or `rebeambox/hiwatch.py`) over the established `BleakLink` interface.