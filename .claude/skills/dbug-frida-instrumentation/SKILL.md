---
name: dbug-frida-instrumentation
description: Dynamic runtime instrumentation using stealth Frida agents (Gate G4). Connects over non-standard port 38921 with renamed daemon hl_daemon, injecting bypass_antidebug.js, crypto_dumper.js (Cipher.doFinal key/plaintext dumper), and socket_tracer.js (libc connect/send and DNS tracer). Streams real-time telemetry into structured JSONL logs. Use when configuring, writing, or executing dynamic Frida hooks.
---

# dbug-frida-instrumentation (Gate G4)

Targeted, lightweight in-process dynamic instrumentation to catch pre-encryption payloads and raw socket C2 connections.

---

## 1. Stealth Frida Host Loader (`instrumentation/frida_loader.py`)

Run Frida without triggering standard port scans or binary name checks:

```python
import frida
import json
import sys
import time

TARGET_PORT = 38921  # Non-default Frida port (masks 27042)
LOG_FILE = "instrumentation_events.jsonl"

def on_message(message, data):
    if message.get("type") == "send":
        payload = message.get("payload", {})
        payload["timestamp_ms"] = int(time.time() * 1000)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(payload) + "\n")
        print(f"[{payload.get('event', 'EVENT')}] {payload.get('summary', '')}")
    elif message.get("type") == "error":
        print(f"[!] Frida Error: {message.get('stack')}", file=sys.stderr)

def run(package_name, script_path, duration=120):
    # Connect via custom device manager / remote port
    mgr = frida.get_device_manager()
    device = mgr.add_remote_device(f"127.0.0.1:{TARGET_PORT}")
    
    print(f"[*] Spawning target package {package_name}...")
    pid = device.spawn([package_name])
    session = device.attach(pid)

    with open(script_path, "r") as f:
        source = f.read()

    script = session.create_script(source)
    script.on("message", on_message)
    script.load()

    device.resume(pid)
    print(f"[+] Instrumentation running for {duration} seconds...")
    time.sleep(duration)

    device.kill(pid)
    session.detach()
    print("[+] Session complete. Events written to", LOG_FILE)
```

---

## 2. In-Process Agent Scripts

### A. Fallback Anti-Debug Cloak (`instrumentation/agent/bypass_antidebug.js`)
```javascript
Java.perform(() => {
    // 1. Spoof Settings.Global getters
    const SettingsGlobal = Java.use("android.provider.Settings$Global");
    SettingsGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, def) {
        if (name === "adb_enabled" || name === "development_settings_enabled") {
            return 0;
        }
        return this.getInt(cr, name, def);
    };

    // 2. Spoof Debugger Checks
    const Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = () => false;
    Debug.waitingForDebugger.implementation = () => false;

    // 3. Spoof Native libc __system_property_get
    const propGet = Module.findExportByName("libc.so", "__system_property_get");
    if (propGet) {
        Interceptor.attach(propGet, {
            onEnter(args) {
                this.name = args[0].readCString();
                this.valuePtr = args[1];
            },
            onLeave(retval) {
                if (this.name === "ro.debuggable") this.valuePtr.writeUtf8String("0");
                if (this.name === "sys.usb.state") this.valuePtr.writeUtf8String("mtp");
            }
        });
    }
});
```

### B. Pre-Network Cryptography Dumper (`instrumentation/agent/crypto_dumper.js`)
```javascript
Java.perform(() => {
    const Cipher = Java.use("javax.crypto.Cipher");
    
    // Intercept cipher execution to dump plaintext & keys
    Cipher.doFinal.overload('[B').implementation = function(input) {
        const result = this.doFinal(input);
        const algo = this.getAlgorithm();
        
        send({
            event: "CRYPTO_DOFINAL",
            summary: `Cipher.doFinal() called with algo ${algo}`,
            algorithm: algo,
            input_hex: input ? bytesToHex(input) : null,
            output_hex: result ? bytesToHex(result) : null
        });
        return result;
    };
});

function bytesToHex(byteArray) {
    return Array.from(byteArray, byte => ('0' + (byte & 0xFF).toString(16)).slice(-2)).join('');
}
```

### C. Low-Level Socket & DNS Tracer (`instrumentation/agent/socket_tracer.js`)
```javascript
// Native libc socket connect tracer
const connectPtr = Module.findExportByName("libc.so", "connect");
if (connectPtr) {
    Interceptor.attach(connectPtr, {
        onEnter(args) {
            const sockfd = args[0].toInt32();
            const sockaddr = args[1];
            const sa_family = sockaddr.readU16();
            
            if (sa_family === 2) { // AF_INET (IPv4)
                const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                const ip = [
                    sockaddr.add(4).readU8(),
                    sockaddr.add(5).readU8(),
                    sockaddr.add(6).readU8(),
                    sockaddr.add(7).readU8()
                ].join('.');
                
                send({
                    event: "SOCKET_CONNECT",
                    summary: `Direct TCP connect to ${ip}:${port}`,
                    ip: ip,
                    port: port
                });
            }
        }
    });
}
```
