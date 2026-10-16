---
name: dbug-desktop-dynamic
description: Dynamic analysis of desktop processes (Linux/macOS/Windows). Frida-based process instrumentation, API hooking (WinAPI/libc), DLL/dylib injection, local socket/pipe tracing, memory scanning. Gate G4/G5 for desktop targets. Requires appropriate host; dynamic claims tagged [I] until hardware-verified.
---

# dbug-desktop-dynamic (Gate G4/G5: Desktop)

Desktop dynamic analysis uses Frida to instrument processes on Linux, macOS, or Windows hosts. All dynamic work is user-requested (AGENTS.md ground rule 2) and only on hardware the user owns.

## 1. Preconditions
- Host: Linux, macOS, or Windows with Frida installed
- frida-server running on host (or Frida gadget loaded into target)
- Target binary or running process (user-provided only)
- Administrator/root may be needed for certain API hooks

## 2. Dynamic analysis steps
1. **Process attachment:** spawn or attach to target process via Frida.
2. **API hooking:** hook WinAPI (CreateFile, RegSetValue, WinHttp, InternetOpen), libc (fopen, connect, send, recv), or framework APIs (.NET, Cocoa).
3. **DLL/dylib injection:** load custom Frida gadget or agent script into target process.
4. **Local socket/pipe tracing:** hook connect(), bind(), accept() on Unix domain sockets and named pipes (Windows).
5. **Memory scanning:** scan heap, stack, and .rodata for keys, tokens, strings matching patterns.
6. **Registry/file monitoring** (Windows): hook RegSetValueEx, CreateFile to observe persistence and config changes.
7. **GUI interaction** (optional): hook window procedure, menu events for UI-driven analysis.

## 3. Frida scripts (agent/controller separation, per objection pattern)
- `desktop_api_hook.js` — hook OS APIs, log calls + arguments
- `desktop_socket_trace.js` — trace socket/pipe connections and data
- `desktop_memory_scan.js` — scan memory regions for patterns
- `desktop_registry_monitor.js` — Windows registry write monitoring

## 4. Output
- `instrumentation_events.jsonl` — JSON telemetry from Frida hooks
- `desktop_dynamic_report.md` — API calls, network connections, memory findings, registry changes
- Sync to `targets/<slug>/` per AGENTS.md contract

## 5. Evidence tags
- `[I]` inferred from static + dynamic (no hardware yet)
- `[V]` verified against real code in emulator/simulator
- `[H]` only with real desktop host capture (user must provide)
- Desktop EDR/antivirus may detect Frida; never claim undetectable.

## 6. Dependencies
- `frida`, `frida-tools` (host, already in requirements.txt)
- Target binary/process (user-provided only, never committed)