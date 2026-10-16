---
name: dbug-ios-dynamic
description: Dynamic analysis of iOS companion apps on jailbroken hardware. Frida-based spawning/attach, Objective-C runtime inspection, keychain/data-protection audit, SSL pinning bypass via Frida. Gate G4/G5 for iOS targets. Requires jailbroken device; dynamic claims tagged [I] until hardware-verified.
---

# dbug-ios-dynamic (Gate G4/G5: iOS)

iOS dynamic analysis requires a jailbroken device with Frida server running. All dynamic work is user-requested (AGENTS.md ground rule 2) and only on hardware the user owns.

## 1. Preconditions
- Jailbroken iOS device (checkra1n, palera1n, dopamine, etc.)
- OpenSSH + frida-server installed on device
- `ios-deploy` or `ideviceinstaller` for app installation (user-provided IPA only)
- Frida on host: `frida`, `frida-tools` (already in requirements.txt)

## 2. Dynamic analysis steps
1. Install user-provided IPA to device (never from vendor servers beyond public artifact download).
2. Start frida-server on device (non-default port to evade detection).
3. Attach Frida to target process (spawn or attach to running).
4. Objective-C runtime inspection: list classes matching target bundle, hook `-[NSURLSession dataTaskWithRequest:]` to capture endpoints, hook `-[SecTrust evaluateWithObject:]` to bypass pinning.
5. Keychain audit: hook `SecItemCopyMatching` to observe what secrets the app queries.
6. Data-protection audit: observe file protection classes (`NSFileProtectionComplete`, `NSFileProtectionCompleteUnlessOpen`, etc.).
7. Network interception: Frida-based out-of-band TLS key extraction (no user CA install, no VPN profile).

## 3. Frida scripts (agent/controller separation, per objection pattern)
- `ios_objc_runtime.js` — enumerate classes, dump methods
- `ios_network_hook.js` — hook NSURLSession/CFNetwork, log endpoints + payloads
- `ios_pinning_bypass.js` — hook SecTrustEval, return kSecTrustResultUnspecified
- `ios_keychain_audit.js` — hook SecItemCopyMatching, log queried attributes

## 4. Output
- `instrumentation_events.jsonl` — JSON telemetry from Frida hooks
- `ios_dynamic_report.md` — endpoints, pinned hosts bypassed, keychain items accessed, data-protection classes
- Sync to `targets/<slug>/` per AGENTS.md contract

## 5. Evidence tags
- `[I]` inferred from static + dynamic (no hardware yet)
- `[V]` verified against real code in emulator/simulator
- `[H]` only with jailbroken hardware capture (user must provide)
- Never claim undetectable; iOS ptrace/amfi checks may detect Frida.

## 6. Dependencies
- `frida`, `frida-tools` (host)
- `frida-server` (device, architecture-matched: arm64/arm64e)
- User-provided IPA only (never committed)