---
name: re-static
description: Static analysis of an Android (and by analogy iOS or desktop) companion app: decompile with jadx/apktool, triage the app framework (Java/Kotlin, Flutter libapp.so, React Native/Hermes bundle, native core), separate vendor code from bundled SDKs, trace the send pipeline from the UI, follow stored keys, recover methods the decompiler failed on, and write the G2 surface map with evidence tags. Use when the user asks to decompile or inspect an APK/XAPK/IPA, read jadx or smali output, or map how an app talks to a device.
---

# re-static (gate G2)

Setup: `python tools/setup_tools.py` (user-space JDK, jadx, apktool; no admin rights; Linux, macOS, Windows). Then `python tools/rw.py doctor`.

## Decompile
```
unzip -oq targets/<slug>/artifacts/<file>.xapk <package>.apk -d targets/<slug>/work
nohup bash -c 'jadx -j 4 -d targets/<slug>/decompiled targets/<slug>/work/<package>.apk > targets/<slug>/work/jadx.log 2>&1; echo "exit=$?" > targets/<slug>/work/jadx.done' >/dev/null 2>&1 &
apktool d -s -f --no-res -o targets/<slug>/work/smali targets/<slug>/work/<package>.apk
```
jadx exit 3 only means some methods failed. Read the log with `tr '\r' '\n'`. Code may be R8-obfuscated (single-letter packages); vendor packages and string constants usually survive.

## Decompile only when needed, and always record
Before decompiling, grep the target's PROTOCOL.md, FACTS.md and LOG.md for the answer, and check whether `targets/<slug>/decompiled` already exists (BUILD-INFO.txt). Decompile only for a specific `[I]`/`[U]` claim, a new version, or a contradiction, and write down which. After the pass, in the same commit: findings -> PROTOCOL.md (tag, class.method), disputed values -> FACTS.md, problems and solutions -> LOG.md, reusable procedure -> this skill.

## Framework triage (before grepping Java)
`unzip -l <apk or ABI split>` and decide what holds the logic; a thin Java shell greps empty.
| Sign | Framework | Where the logic is |
|---|---|---|
| `lib/<abi>/libflutter.so` + `libapp.so` | Flutter | Dart AOT in `libapp.so`; Java has only `MethodChannel` bridges (`io.flutter.plugin.common.MethodChannel`). Find the BLE plugin (`flutter_blue_plus`, `flutter_reactive_ble` or a vendor plugin) on the Java side, then strings in `libapp.so`; `blutter` recovers Dart symbols (Dart 2.17 to about 3.9 [W]) but needs network and a C++ compiler to build the matching Dart SDK; offline, fall back to strings in `libapp.so` and the MethodChannel boundary |
| `assets/index.android.bundle` | React Native | Check the first bytes: Hermes bytecode has magic `c6 1f bc 03 c1 03 19 1f`; otherwise plain or minified JS. HBC version is the uint32 at offset 8; use `hermes-dec` (P1sec, HBC up to about 96-98); `hbctool` stops at HBC 76-89 [W]. Else string tables for UUIDs and opcodes. BLE goes through a native module (`react-native-ble-plx` and similar) |
| `assets/www/`, Capacitor/Cordova | web | JS in plain files |
| big vendor `.so` + thin Java | native core | `re-native-emulation` |
| none of these | Java/Kotlin | continue below |
Record the framework in TARGET.md. Tools named here are optional; note in LOG.md if one was missing.

## Fast survey
`python tools/rw.py recon targets/<slug>/decompiled --slug <slug>` greps a recipe pack (GATT API, UUID literals, sockets, URLs, IPs and ports, crypto, native libs, stored-key APIs, byte-array literals) and writes `targets/<slug>/work/recon.md`, separating app code from bundled libraries. Treat it as a map, not as findings.

## Method (order matters)
1. Manifest: permissions (BLUETOOTH_*, NEARBY_WIFI_*, CHANGE_WIFI_STATE, USB, foreground services) and exported components and deep links.
2. Separate vendor code from SDKs. Bundled SDKs (a chip vendor's BLE/OTA SDK, Nordic, Telink, Jieli, Realtek) are documented behaviour to read, not novel findings; tag them `[C]` with "SDK: <package>" and cite the app's own call site; with no caller in app code write "unreferenced by app" so G3/G4 do not treat dead SDK code as target behaviour. Stack signatures: `re-watch-targets/references/vendor-stacks.md`.
3. Find the UI action that connects or sends. From it, find how the app chooses a transport. Do not start from the first UUID hit.
4. Transport details (UUIDs, write types, MTU, scan filters, ACKs, Wi-Fi): run the searches in `re-ble-android-patterns`. In short: all `UUID.fromString(` literals minus library noise; identify the vendor class holding service constants and everything that references it. Standard 0x2902 is the CCCD.
5. GATT callback: MTU request, service/characteristic lookup order, descriptor writes, write type (`setWriteType`: 1 no-response, 2 default).
6. Single write path: find where bytes leave the app (`writeCharacteristic`, `getOutputStream`, `HttpURLConnection`, USB bulk). Walk backwards to every caller for the full command list. Walk forward through `onCharacteristicChanged` / the reader loop for reply layout.
7. Pacing: `postDelayed`, retry counters, timeouts, batch sizes, chunk sizes. Record constants with their method.
8. Persistent state: trace every stored key (MMKV, SharedPreferences, DataStore) from writer to readers; this exposes device-type switches.
9. Server-driven behaviour: URLs, JSON field names (`@SerializedName`), model/product tables. If the product list is server-side, record that as a limitation.
10. Scan filters: `ScanFilter`, name/manufacturer-id matchers, advertised-name constants.

## Obfuscation and decompiler failures
- Navigate by constants, strings, stored keys, and framework call sites, not by names.
- `jadx -m simple --show-bad-code` removes region-maker failures. Type-inference failures remain: read smali, or convert the dex with dex2jar and decompile that class with CFR. `bash tools/recover-failed-methods.sh <apk> <classesN.dex> <class>` automates it.
- Wrap whole-tree greps in `timeout`; narrow to likely packages after the first hit.
- Truncated lines hide facts: read full lines (wide columns) before recording a value.

## Output of G2
Write into PROTOCOL.md a surface map: transports (with service UUIDs/ports/SSID patterns), characteristics and their roles, scan filters, command inventory (opcode, direction, source method), pacing constants, stored switches, unknowns. Every row tagged. Native libraries found go to the list for `re-native-emulation`.

## Other platforms
iOS: first `otool -l <binary> | grep -A4 LC_ENCRYPTION_INFO`; `cryptid 1` means FairPlay-encrypted code: stop and ask the owner for a decrypted IPA, still read `Info.plist`, usage strings and bundled assets. On a decrypted binary grep selectors `scanForPeripheralsWithServices:`, `discoverCharacteristics:forService:`, `writeValue:forCharacteristic:type:`, `setNotifyValue:forCharacteristic:`, `UUIDWithString:`; class-dump or Ghidra; same method. Desktop: strings and import tables first. Web/Electron: unpack asar and read JS, endpoints are plain.
