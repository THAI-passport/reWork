---
name: dbug-web-dynamic
description: Dynamic analysis of web/Electron applications. Frida-based Electron renderer/main process hooking, WebSocket/XHR/fetch interception, local storage/IndexedDB audit. Gate G4/G5 for web/Electron targets. Requires appropriate host; dynamic claims tagged [I] until hardware-verified.
---

# dbug-web-dynamic (Gate G4/G5: Web/Electron)

Web/Electron dynamic analysis uses Frida to instrument Electron main/renderer processes or hooks browser DevTools Protocol. All dynamic work is user-requested (AGENTS.md ground rule 2) and only on hardware the user owns.

## 1. Preconditions
- Host: Linux, macOS, or Windows with Frida installed
- Electron app with Frida gadget or injectable main process
- Or browser with DevTools Protocol enabled (`--remote-debugging-port`)
- Target app (user-provided only)

## 2. Dynamic analysis steps
1. **Process attachment:** spawn or attach to Electron main/renderer process via Frida.
2. **Network interception:** hook `fetch`, `XMLHttpRequest.send`, `WebSocket.send`, `axios` to capture requests/responses.
3. **Storage audit:** hook `localStorage.setItem/getItem`, `IndexedDB` operations, `cookie` access to observe stored data.
4. **DevTools Protocol:** connect to `--remote-debugging-port`, inspect network, console, storage, page DOM.
5. **Native module inspection:** hook `.node` addon exports if Electron uses native bindings.
6. **Auto-update check:** observe Squirrel/Electron auto-updater requests to detect update mechanism and signature verification.

## 3. Frida scripts (agent/controller separation, per objection pattern)
- `web_network_hook.js` — hook fetch/XHR/WebSocket, log endpoints and payloads
- `web_storage_audit.js` — hook localStorage/IndexedDB, log stored keys/values
- `web_devtools_probe.js` — connect to DevTools Protocol port, enumerate targets

## 4. Output
- `instrumentation_events.jsonl` — JSON telemetry from Frida hooks
- `web_dynamic_report.md` — endpoints, storage keys, DevTools findings, auto-update behavior
- Sync to `targets/<slug>/` per AGENTS.md contract

## 5. Evidence tags
- `[I]` inferred from static + dynamic (no hardware yet)
- `[V]` verified against real code in emulator/simulator
- `[H]` only with real host capture (user must provide)
- Electron `nodeIntegration: true` is a `[H]` risk if confirmed on a running app.

## 6. Dependencies
- `frida`, `frida-tools` (host, already in requirements.txt)
- Target app (user-provided only, never committed)