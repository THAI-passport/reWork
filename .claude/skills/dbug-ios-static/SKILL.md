---
name: dbug-ios-static
description: Static analysis of iOS companion apps and binaries. Mach-O parsing, Info.plist/entitlements extraction, crypto export checks, Objective-C method survey, and class-dump-style reconnaissance. Gate G2 surface map for iOS targets.
---

# dbug-ios-static (Gate G2: iOS)

iOS apps are distributed as IPA files (zipped `Payload/*.app` bundles containing a Mach-O binary, `Info.plist`, embedded.mobileprovision, and resources). Static analysis proceeds without installing or running the app (AGENTS.md ground rule 2).

## 1. IPA structure
```
Payload/<app>.app/
  <app>                # Mach-O binary (ARM64 / arm64e)
  Info.plist           # bundle ID, version, UIRequiredDeviceCapabilities, transport modes
  embedded.mobileprovision  # provisioning profile (app ID, entitlements, team)
  _CodeSignature/      # CodeResources (integrity)
  Frameworks/          # bundled dynamic frameworks
  PlugIns/             # app extensions
```

## 2. Static analysis steps
1. Unzip IPA (do not install or run). Identify `Payload/*.app/<app>` Mach-O binary.
2. Parse `Info.plist`: `CFBundleIdentifier`, `CFBundleShortVersionString`, `CFBundleVersion`, `UIBackgroundModes`, `NSBluetoothPeripheral`, `NSLocalNetworkUsageDescription`, `NSAppTransportSecurity` (ATS exceptions = cleartext / custom TLS).
3. Parse `embedded.mobileprovision`: app ID prefix, team ID, entitlements (aps-environment, com.apple.developer.networking.networkextension, etc.).
4. Mach-O survey: load commands (`LC_SEGMENT_64`, `LC_SYMTAB`, `LC_DYLD_INFO_ONLY`, `LC_ENCRYPTION_INFO_64`), exported symbols, imported libraries, encrypted segments (FairPlay / App Store encryption = `[U]` until decrypted).
5. Objective-C method survey: `objc_class` names, `+[class method]` selectors, `NSURLConnection`/`NSURLSession` usage, `CFNetwork` calls, `Security.framework` (SecTrustEval, certificate pinning), `CoreBluetooth`/`CoreNFC` usage.
6. String literal survey: hardcoded endpoints, API keys, UUIDs, BLE service/characteristic UUIDs, staging vs production flags.
7. Entitlements check: `com.apple.developer.applesigning`, `get-task-allow` (debuggable), `com.apple.debug` (diagnostics).

## 3. Output
Write into PROTOCOL.md a surface map: bundle ID, version, transport modes (BLE UUIDs, ports, SSID), encrypted segments, entitlements, known pinning endpoints. Every row tagged `[C]` (confirmed in IPA) or `[U]` (unknown pending hardware).

## 4. Dependencies
- `pyelftools` or `lief` for Mach-O parsing (optional; `setup-tools.sh --emulation`)
- `plistlib` (stdlib) for Info.plist / mobileprovision (XML plist)

## 5. Evidence tags
- `[C]` confirmed in IPA binary / plist
- `[U]` unknown (encrypted binary, server-side config)
- Never `[H]` without jailbroken hardware capture.