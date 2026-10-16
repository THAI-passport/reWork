---
name: dbug-sample-triage
description: Safe acquisition, cryptographic hashing, unpacking, and static triage of suspicious Android malware APKs, XAPKs, and DEX files (Gate G0). Identifies permissions, accessibility service abuse, overlay intents, native libraries, packers/protectors (Jiagu, SecNeo, Bangcle), C2 string literals, Telegram bot tokens, and anti-analysis triggers before dynamic execution. Use when the user asks to ingest, verify, unpack, decompile, or statically audit a malware sample.
---

# dbug-sample-triage (Gate G0)

Safely inspect, unpack, and profile an Android malware sample without executing it on the host or alerting its C2.

---

## 1. Safe Ingestion & Verification
1. **Quarantine Directory:** Keep all untrusted binaries in `samples/<sha256>/` or a dedicated air-gapped staging directory.
2. **Compute Hashes:**
   ```bash
   sha256sum sample.apk
   md5sum sample.apk
   ```
3. **Verify Archive Integrity:**
   ```bash
   unzip -t sample.apk
   ```
4. **Signature & Certificate Audit:**
   ```bash
   apksigner verify --verbose --print-certs sample.apk
   ```
   - Note subject, issuer, validity period, and whether debug/default Android keystore was used (e.g., `CN=Android Debug`).

---

## 2. Static Decompilation & Extraction
```bash
# Extract raw files & smali
apktool d -s -f --no-res -o work/smali sample.apk

# Decompile Java sources with jadx in background
jadx -j 4 -d work/decompiled sample.apk > work/jadx.log 2>&1
```

### XAPK & APKS Split Handling
If the sample is an `.xapk` or `.apks`:
- Unzip the container.
- Identify the base APK (`base.apk` or `<package>.apk`).
- Identify the ARM64 native split (`config.arm64_v8a.apk` or `split_config.arm64_v8a.apk`). Extract `.so` files from the split—do not assume an absence of native code if `base.apk` lacks `lib/`.

---

## 3. High-Priority Triage Indicators

### A. Dangerous Permissions & Services
Inspect `AndroidManifest.xml` for classic infostealer / RAT abuse:
- `android.permission.BIND_ACCESSIBILITY_SERVICE` (keylogging, automated click-jacking, 2FA harvesting)
- `android.permission.SYSTEM_ALERT_WINDOW` (phishing overlays on banking apps)
- `android.permission.RECEIVE_BOOT_COMPLETED` (persistence across reboots)
- `android.permission.READ_SMS` / `RECEIVE_SMS` (OTP interception)
- `android.permission.RECORD_AUDIO` / `CAMERA` (surveillance/RAT)
- `android.permission.REQUEST_INSTALL_PACKAGES` (dropper payload delivery)
- `android.permission.QUERY_ALL_PACKAGES` (installed banking app reconnaissance)

### B. Packer & Protector Identification
Inspect directory tree and native libraries before searching Java code:
| Indicator | Packer / Protector | Notes |
|---|---|---|
| `libjiagu.so` | Qihoo 360 Jiagu | Heavy anti-debug, memory encryption |
| `libsecmain.so`, `libSecShell.so` | Bangcle / SecNeo | Dex encryption, native loader |
| `libstub.so`, `libexec.so` | Tencent Legu | Encrypted classes.dex in assets |
| `libDexHelper.so` | Medusa / custom | Custom payload decryption in `JNI_OnLoad` |
| `assets/dexguard/` | DexGuard | String encryption, class reflection |

*If packed:* Note that static Java code is a stub. Priority shifts to runtime memory dumps (`dbug-frida-instrumentation`) or native unpacking (`dbug-native-emulation`).

### C. Framework Classification
| Signature | Framework | Primary Logic Location |
|---|---|---|
| `lib/<abi>/libflutter.so` + `libapp.so` | Flutter | Dart AOT in `libapp.so`; strings in binary |
| `assets/index.android.bundle` | React Native | Hermes or JS bundle; grep for endpoints |
| `assets/www/` | Cordova / Capacitor | Web HTML/JS assets |
| `lib/<abi>/lib*.so` | Native Core | C/C++/Rust logic; triage via Ghidra/radare2 |
| Plain `classes.dex` | Java / Kotlin | Standard Android Dalvik bytecode |

---

## 4. Extraction of C2 & Evasion Cues

### Grep Recipes for Decompiled Source:
```bash
# 1. C2 URLs, IP addresses, and WebSockets
grep -Ero "https?://[a-zA-Z0-9\.\_\:\-]+[a-zA-Z0-9]" work/decompiled/
grep -Ero "wss?://[a-zA-Z0-9\.\_\:\-]+" work/decompiled/
grep -Ero "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]{2,5})?" work/decompiled/

# 2. Telegram Bot tokens and Discord Webhooks
grep -Ero "bot[0-9]{9,11}:[a-zA-Z0-9_-]{35}" work/decompiled/
grep -Ero "discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+" work/decompiled/

# 3. Anti-analysis & Detection checks
grep -Enr "adb_enabled|development_settings_enabled" work/decompiled/
grep -Enr "isDebuggerConnected|waitingForDebugger" work/decompiled/
grep -Enr "ro\.debuggable|ro\.secure|sys\.usb\.state" work/decompiled/
grep -Enr "TracerPid|frida|xposed" work/decompiled/
grep -Enr "tun0|ppp0|http\.proxyHost" work/decompiled/
```

---

## 5. Output Deliverables
Produce `targets/<sample_hash>/STATIC_AUDIT.md`:
1. Metadata: package name, hashes (MD5, SHA-256), version code/name, min/target SDK.
2. Architecture: pure Java, packed, or native-heavy.
3. Identified detection vectors: which anti-debug/anti-root checks were found statically.
4. Hardcoded seed strings: domain candidates, encryption keys, DGA seeds.
