---
name: re-static
description: Static analysis of an Android (and by analogy iOS or desktop) companion app to map how it talks to a device. Decompile with jadx/apktool, find BLE/Wi-Fi/serial/socket surfaces, trace the send pipeline from the UI, deal with obfuscation and decompiler failures, and write the surface map with evidence tags.
---

# re-static (gate G2)

Setup: `bash tools/setup-tools.sh` (user-space JDK, jadx, apktool; no sudo). Then `python tools/rw.py doctor`.

## Decompile
```
unzip -oq targets/<slug>/artifacts/<file>.xapk <package>.apk -d targets/<slug>/work
nohup bash -c 'jadx -j 4 -d targets/<slug>/decompiled targets/<slug>/work/<package>.apk > targets/<slug>/work/jadx.log 2>&1; echo "exit=$?" > targets/<slug>/work/jadx.done' >/dev/null 2>&1 &
apktool d -s -f --no-res -o targets/<slug>/work/smali targets/<slug>/work/<package>.apk
```
jadx exit 3 only means some methods failed. Read the log with `tr '\r' '\n'`. Code may be R8-obfuscated (single-letter packages); vendor packages and string constants usually survive.

## Fast survey
`python tools/rw.py recon targets/<slug>/decompiled --slug <slug>` greps a recipe pack (GATT API, UUID literals, sockets, URLs, IPs and ports, crypto, native libs, stored-key APIs, byte-array literals) and writes `targets/<slug>/work/recon.md`, separating app code from bundled libraries. Treat it as a map, not as findings.

## Method (order matters)
1. Manifest: permissions (BLUETOOTH_*, NEARBY_WIFI_*, CHANGE_WIFI_STATE, USB, foreground services) and exported components and deep links.
2. Separate vendor code from SDKs. Bundled SDKs (a chip vendor's BLE/OTA SDK, Nordic, Telink, Jieli, Realtek) are documented behaviour to read, not novel findings; note them by package.
3. Find the UI action that connects or sends. From it, find how the app chooses a transport. Do not start from the first UUID hit.
4. UUIDs: all `UUID.fromString(` literals minus library noise; identify the vendor class holding service constants and everything that references it. Standard 0x2902 is the CCCD.
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
iOS: class-dump / Ghidra on the decrypted Mach-O, `Info.plist` for Bluetooth usage strings; same method. Desktop: strings and import tables first. Web/Electron: unpack asar and read JS, endpoints are plain.
