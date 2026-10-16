---
name: dbug-infostealer-catalog
description: Reference knowledge base and behavioral profiles for top evasive Android infostealers, banking trojans, and RATs (Ermac, Hook, CraxsRAT, SpyNote, Godfather, Medusa, Octo, Vultur, Cerberus, Anatsa). Covers known anti-analysis checks, accessibility abuse patterns, C2 protocols, overlay mechanisms, and signature indicators. Use during sample triage or attribution to cross-reference observed behavior with known malware families.
---

# dbug-infostealer-catalog: Threat Profiles & Signatures

Reference guide for classifying evasive Android infostealers and banking trojans encountered during dynamic sandbox sessions.

---

## 1. Malware Family Behavioral Matrix

| Family | Primary Objective | Evasion & Anti-Debug Tactics | C2 Transport & Protocols | Key Indicators |
|---|---|---|---|---|
| **Ermac / Hook** | Banking credentials, 2FA, crypto seed phrases | WebSocket TLS; checks `ro.debuggable` & `adb_enabled`; detects emulator via QEMU drivers; disables Play Protect via Accessibility | WebSocket (`wss://`) on custom ports; JSON-RPC tasking; encrypted with RC4/AES | Targets 400+ financial apps; accessibility clickjacking; VNC screen capture |
| **CraxsRAT** | Full remote device control, audio/screen spying | Heavy string encryption; monitors `/proc/self/status` `TracerPid`; checks Frida default ports (`27042`) | Raw TCP socket connection; custom binary length-prefixed packet protocol | Auto-clicks permissions; keylogger; pattern lock bypass; Telegram bot fallback |
| **SpyNote** | Surveillance, SMS interception, credential theft | Detects battery charging state; polls accelerometer for physical motion; checks developer options | Direct TCP sockets with Base64/XOR encoding | Exploits Accessibility service; injects fake system update notifications |
| **Godfather** | Banking overlay phishing, SMS OTP theft | Queries `Settings.Global.ADB_ENABLED`; inspects installed apps via `getRunningAppProcesses` | HTTPS POST requests with JSON payload encrypted via custom AES CBC | Injects fake login screens over banking and crypto exchange apps; intercepts Google Authenticator codes |
| **Medusa (TangleBot)** | Banking theft, SMS propagation, keylogging | Multi-stage payload decryption via native `.so` (`JNI_OnLoad`); heavy code obfuscation | WebSockets over HTTPS; secondary fallback C2 domains | Uses accessibility to grant itself SMS/Contact permissions; initiates unauthorized money transfers |
| **Octo (Coper variant)** | Remote access, banking fraud, on-device streaming | Disables screen wake lock; draws black screen overlay to conceal actions; checks proxy settings | HTTPS beacons with gzip/AES compression; fast-flux C2 infrastructure | Built-in VNC module; black screen overlay (`SYSTEM_ALERT_WINDOW`) while stealing data in background |
| **Anatsa (TeaBot)** | European banking fraud, automatic transfer system (ATS) | Dropped via clean Play Store utility stubs; checks for rooting binaries (`su`, Magisk) | Encrypted HTTPS traffic to VPS endpoints | Automated wire transfer execution via accessibility service gestures |

---

## 2. Common Anti-Analysis Heuristics by Family

### The "Dormancy until Motion" Heuristic
- **Observed in:** SpyNote, Ermac, Medusa.
- **Mechanism:** Listens for `Sensor.TYPE_ACCELEROMETER` or `Sensor.TYPE_STEP_COUNTER`. If step count is 0 or device does not tilt for several minutes, malware assumes an emulated sandbox and halts execution.
- **Countermeasure:** Physical lab device is handled or placed on an automated shaker/motor, or sensor events are spoofed via Frida.

### The "Play Protect Disabler" Loop
- **Observed in:** Hook, CraxsRAT, Octo.
- **Mechanism:** Immediately upon obtaining Accessibility permissions, the malware launches Google Play Store settings and clicks "Disable Play Protect" via `AccessibilityNodeInfo.performAction(ACTION_CLICK)`.
- **Countermeasure:** Observed as confirmation of malicious intent `[D]`; let execution proceed while capturing traffic.
