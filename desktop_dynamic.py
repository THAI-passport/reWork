#!/usr/bin/env python3
"""desktop_dynamic.py: Desktop dynamic analysis tool (Gate G4/G5).

Frida-based process instrumentation, API hooking (WinAPI/libc), DLL/dylib
injection, local socket/pipe tracing, memory scanning for desktop targets
(Linux/macOS/Windows). Runs in dry-run simulation mode without hardware.

Usage:
    python desktop_dynamic.py --process <pid|name> --duration 120 --dry-run
    python desktop_dynamic.py --binary <path> --duration 60
    python desktop_dynamic.py --process <pid> --script desktop_api_hook.js
"""
import argparse
import json
import os
import sys
import time

try:
    import frida
    HAS_FRIDA = True
except ImportError:
    HAS_FRIDA = False

DEFAULT_DURATION = 120
class DesktopDynamicAnalyzer:
    def __init__(self, target, duration=DEFAULT_DURATION,
                 log_path="desktop_instrumentation_events.jsonl",
                 script_path=None, dry_run=False, is_pid=True):
        self.target = target
        self.duration = duration
        self.log_path = log_path
        self.script_path = script_path
        self.dry_run = dry_run
        self.is_pid = is_pid
        self.device = None
        self.session = None
        self.pid = None
        self.log_file = None

    def _attach(self):
        try:
            if self.is_pid:
                self.session = frida.get_local_device().attach(int(self.target))
                self.pid = int(self.target)
            else:
                self.pid = frida.get_local_device().spawn([self.target])
                self.session = frida.get_local_device().attach(self.pid)
        except Exception as e:
            print("[!] Failed to attach to %s: %s" % (self.target, e), file=sys.stderr)
            return False
        print("[+] Attached to %s (pid=%s)" % (self.target, self.pid))
        return True

    def _load_script(self):
        if self.script_path and os.path.isfile(self.script_path):
            with open(self.script_path, "r", encoding="utf-8") as f:
                return f.read()
        return """
        send({event: 'ATTACHED', target: '%s', pid: %d});
        """ % (self.target, self.pid or 0)

    def _on_message(self, message, data):
        now_ms = int(time.time() * 1000)
        if message.get("type") == "send":
            payload = message.get("payload", {})
            payload["timestamp_ms"] = now_ms
            if self.log_file:
                self.log_file.write(json.dumps(payload) + "\n")
                self.log_file.flush()
            event = payload.get("event", "EVENT")
            print("  [%s] %s" % (event, json.dumps(payload)[:120]))
        elif message.get("type") == "error":
            print("[!] Frida error: %s" % message.get("description"), file=sys.stderr)
    def run_dry_run(self):
        print("[+] [DRY-RUN] Attaching to desktop target '%s'..." % self.target)
        print("[*] [DRY-RUN] Simulating desktop dynamic analysis telemetry...")
        dir_path = os.path.dirname(os.path.abspath(self.log_path))
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        now_ms = int(time.time() * 1000)
        sample_events = [
            {"event": "API_CALL", "module": "kernel32.dll", "function": "CreateFileW",
             "args": {"lpFileName": "C:\\\\Users\\\\...\\\\config.dat"}, "timestamp_ms": now_ms + 100},
            {"event": "SOCKET_CONNECT", "family": "AF_INET", "ip": "198.51.100.42",
             "port": 4433, "timestamp_ms": now_ms + 250},
            {"event": "MEMORY_SCAN", "region": "0x7ffee4b00000", "size": 65536,
             "pattern": "sk_live_", "timestamp_ms": now_ms + 500},
            {"event": "REGISTRY_WRITE", "key": "HKCU\\\\Software\\\\...\\\\Run",
             "value": "updater", "timestamp_ms": now_ms + 750},
        ]
        with open(self.log_path, "w", encoding="utf-8") as f:
            for ev in sample_events:
                f.write(json.dumps(ev) + "\n")
                print("  [%s] Simulated telemetry event logged." % ev["event"])
        print("[+] [DRY-RUN] Telemetry logged to %s" % self.log_path)
        return True

    def run(self):
        if self.dry_run or not HAS_FRIDA:
            if not HAS_FRIDA and not self.dry_run:
                print("[-] Notice: 'frida' Python module not installed. Falling back to simulation mode.", file=sys.stderr)
            return self.run_dry_run()

        if not self._attach():
            return False

        source = self._load_script()
        print("[*] Injected desktop instrumentation agent (%d bytes)..." % len(source))

        dir_path = os.path.dirname(os.path.abspath(self.log_path))
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        self.log_file = open(self.log_path, "a", encoding="utf-8")

        script = self.session.create_script(source)
        script.on("message", self._on_message)
        script.load()

        try:
            print("[+] Monitoring for %d seconds..." % self.duration)
            time.sleep(self.duration)
        except KeyboardInterrupt:
            print("\n[!] Execution interrupted by user.")
        finally:
            self.cleanup()
        print("[+] Session complete. Telemetry persisted to %s" % self.log_path)
        return True

    def cleanup(self):
        if self.log_file and not self.log_file.closed:
            self.log_file.close()
        if self.session:
            try:
                self.session.detach()
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description="Desktop dynamic analysis (Gate G4/G5)")
    parser.add_argument("--process", help="Target process PID or name")
    parser.add_argument("--binary", help="Target binary path to spawn")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION, help="Observation window in seconds")
    parser.add_argument("--log", default="desktop_instrumentation_events.jsonl", help="Telemetry output log")
    parser.add_argument("--script", default=None, help="Path to custom Frida JS agent")
    parser.add_argument("--dry-run", action="store_true", help="Simulate without hardware")
    args = parser.parse_args()

    if args.binary:
        target = args.binary
        is_pid = False
    elif args.process:
        target = args.process
        is_pid = target.isdigit()
    else:
        parser.error("specify --process or --binary")

    analyzer = DesktopDynamicAnalyzer(
        target=target, duration=args.duration, log_path=args.log,
        script_path=args.script, dry_run=args.dry_run, is_pid=is_pid)
    ok = analyzer.run()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()