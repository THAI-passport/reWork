---
name: re-ble-android-patterns
description: Search patterns for the transport code of a decompiled Android companion app - GATT service and characteristic UUIDs, MTU, write types, scan filters, manufacturer data, name-based dispatch, server product catalogs, notification assemblers, flow control and ACKs, Wi-Fi access point and socket modes, and wrappers (RxAndroidBle, Nordic BLE library, coroutines). Use when the user asks to find GATT UUIDs, write types, MTU, scan filters or ACK logic in jadx output, or during gate G2 for any BLE or Wi-Fi device.
---

# re-ble-android-patterns

Run the searches on the jadx tree (`targets/<slug>/decompiled`) after `re-static` has decompiled it and ruled out Flutter/React Native. Obfuscated class names do not matter; framework calls and string constants do. Tag results [C] with class and method. Worked values from reBeamBox are examples only.

## Start from the action, then grep
Start at the UI action (connect, send, upload media), follow it to the sender, then use the searches below to confirm and to find siblings.

| Question | Search (ripgrep, fixed strings first) |
|---|---|
| Which GATT services and characteristics? | `UUID.fromString`, `-0000-1000-8000-00805f9b34fb`, 4-hex-digit constants near `BluetoothGattCharacteristic`, `getService(`, `getCharacteristic(` |
| Notifications enabled? | `setCharacteristicNotification`, `00002902-0000-1000-8000-00805f9b34fb`, `ENABLE_NOTIFICATION_VALUE`, `onCharacteristicChanged` |
| Write type | `setWriteType`, `WRITE_TYPE_NO_RESPONSE`, `WRITE_TYPE_DEFAULT`, `writeCharacteristic(` |
| MTU | `requestMtu(`, `onMtuChanged`, constants 512, 517, 247, 23, 3 (header) |
| Connection | `connectGatt(`, `BluetoothGattCallback`, `discoverServices`, `createBond`, `refresh` (reflection cache clear) |
| Scanning | `ScanFilter`, `ScanSettings`, `startScan`, `getScanRecord`, `getManufacturerSpecificData`, `getServiceUuids`, `getDeviceName` |
| Name dispatch | string compares near the scan callback: `startsWith`, `contains`, `equalsIgnoreCase`, `toUpperCase`; also name lists in resources and `strings.xml` |
| Server catalogs | Retrofit or OkHttp interfaces, endpoints containing `device`, `product`, `badge`, `watch`, `firmware`, `dial`, `face`; JSON field names such as `deviceName`, `signalName`, `deviceType` |
| Wi-Fi | `WifiNetworkSpecifier`, `WifiManager`, `ConnectivityManager.bindProcessToNetwork`, `new Socket(`, `InetSocketAddress`, `192.168.`, `HttpURLConnection`, `Content-Range` |
| Classic BT (SPP/RFCOMM) | `00001101-0000-1000-8000-00805f9b34fb`, `createRfcommSocketToServiceRecord`, `createInsecureRfcommSocketToServiceRecord`, `BluetoothSocket`, `getBondedDevices` (dual-mode watches may move bulk data here) |
| Native links | `System.loadLibrary`, `native ` method declarations, `JNI_OnLoad` registrations |
| RxAndroidBle | `RxBleClient`, `RxBleConnection`, `establishConnection`, `setupNotification`, `writeCharacteristic`, `requestMtu` |
| Nordic Android-BLE-Library | `extends BleManager`, `writeCharacteristic(`, `setNotificationCallback`, `enableNotifications`, `requestMtu(`, `isRequiredServiceSupported` |
| Kotlin coroutines/Flow | `callbackFlow`, `MutableSharedFlow`, `Channel<` near a `BluetoothGattCallback`; the write queue is often a `Channel` consumer |

## Reading the results
- **Advertising data.** AD type 0xFF is manufacturer data: the first two bytes are the company id (little endian). Apps often read a tag byte and a shape or product byte from it; record offsets and meanings as separate rows. The local name is AD 0x08 or 0x09 and can differ between scan response and the GAP name.
- **Name-based dispatch.** If the app picks a code path by device name, list every name and every path; a name can be hidden from the scan list by a substring rule. The same hardware may advertise different names in different modes (pairing screen versus charging) [W-style finding: verify].
- **Server product catalogs.** Which model uses which transport is often decided by a server record, not by code. Say so, make it a client flag, and record it as [U] until a capture or a reply settles it.
- **Write types and pacing.** Write without response needs pacing or an application ACK; write with response is naturally flow controlled. Look for a sender thread with `Thread.sleep` or a handler delay: that is the pacing value. Record chunk size as MTU minus 3 (ATT header) unless the code subtracts more.
- **Notifications.** Find the assembler: replies can be split over notifications; look for a length field and a checksum, and for JSON accumulated until braces balance.
- **Flow control and ACK.** Common patterns: batch of N packets then wait for an ACK; per-packet sequence numbers with a "fail at index" reply that restarts from a given packet; a device-pulled model where the device requests offsets. Write the state machine as a table (state, event, action) before coding.
- **Checksums.** Read the method; names are obfuscated but the loop is recognisable (table lookup, shifts, 0x1021, 0xEDB88320). `tools/crcfind.py` identifies a CRC from sample frames.
- **Wi-Fi modes.** Joining a device access point (SSID prefix, password rules, `bindProcessToNetwork`), a fixed gateway address and port, control words versus length-prefixed frames, HTTP upload with ranges. Watch faces and media often go: BLE command opens a SoftAP on the watch, the app binds to it, then HTTP upload (`MultipartBody`, `@Multipart`, `@POST`) or a TCP socket to a fixed gateway (`192.168.4.1`, `192.168.10.1`, `192.168.43.1` are common [W]). Record how the phone joins, which models use it, the frame limits and any rate cap in the code.
- **Several transports in one app.** Build a table: transport, selector (name, service, catalog field), models, evidence. Do not assume one transport per app.

## Out of scope here
Decompiling, decompiler failures, framework triage and stored keys (MMKV, SharedPreferences): `re-static`.
