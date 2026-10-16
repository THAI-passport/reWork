#!/usr/bin/env python3
"""frida_loader.py: Stealth Dynamic Instrumentation Loader for dbug (Gate G4).

Spawns the target APK via a non-standard Frida port (38921), compiles and injects
consolidated stealth hooks (bypass_antidebug, crypto_dumper, socket_tracer), and
streams structured JSON telemetry to a timestamped session log.
"""

import argparse
import json
import os
import re
import signal
import sys
import time

# Optional frida import
try:
    import frida
    HAS_FRIDA = True
except ImportError:
    HAS_FRIDA = False

# Optional PyYAML support with regex fallback
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def parse_lab_config(config_path):
    """Parses lab_config.yaml using PyYAML or regex fallback."""
    if not os.path.exists(config_path):
        return {}

    if HAS_YAML:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"[-] Warning: Failed to parse YAML via PyYAML: {e}", file=sys.stderr)

    config = {"lab_environment": {"device": {}, "target_sample": {}, "telemetry": {"frida": {}}}}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
        pkg_m = re.search(r'package_name:\s*["\']?([^"\'\s#]*)', content)
        if pkg_m and pkg_m.group(1):
            config["lab_environment"]["target_sample"]["package_name"] = pkg_m.group(1)
        port_m = re.search(r'port:\s*(\d+)', content)
        if port_m:
            config["lab_environment"]["telemetry"]["frida"]["port"] = int(port_m.group(1))
    except Exception as e:
        print(f"[-] Warning: Fallback config parser error: {e}", file=sys.stderr)

    return config


class FridaLoader:
    def __init__(self, package_name, port=38921, host="127.0.0.1",
                 log_path="instrumentation_events.jsonl", dry_run=False):
        self.package_name = package_name
        self.port = port
        self.host = host
        self.log_path = log_path
        self.dry_run = dry_run
        self.session = None
        self.device = None
        self.pid = None
        self.log_file = None

    def compile_agent_sources(self, script_paths):
        """Concatenates multiple agent JavaScript files into a single bundle."""
        bundle = []
        for path in script_paths:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    bundle.append(f"// --- Begin: {path} ---\n" + f.read() + f"\n// --- End: {path} ---")
            else:
                print(f"[-] Warning: Agent script not found: {path}", file=sys.stderr)
        return "\n\n".join(bundle)

    def on_message(self, message, data):
        """Callback processing messages from in-process Frida agents."""
        now_ms = int(time.time() * 1000)
        if message.get("type") == "send":
            payload = message.get("payload", {})
            payload["timestamp_ms"] = now_ms

            if self.log_file:
                self.log_file.write(json.dumps(payload) + "\n")
                self.log_file.flush()

            event = payload.get("event", "EVENT")
            if event == "CRYPTO_DOFINAL":
                algo = payload.get("algorithm", "UNKNOWN")
                in_len = payload.get("input_length", 0)
                print(f"  [CRYPTO] Cipher.doFinal({algo}) | In: {in_len}B | KeyHex: {payload.get('key_hex', 'N/A')[:16]}...")
            elif event == "SOCKET_CONNECT":
                dst = payload.get("destination_ip", "0.0.0.0")
                port = payload.get("destination_port", 0)
                print(f"  [SOCKET] connect() -> {dst}:{port}")
            elif event == "DNS_LOOKUP":
                print(f"  [DNS] InetAddress.getByName({payload.get('hostname')})")
            else:
                print(f"  [{event}] {json.dumps(payload)[:100]}")

        elif message.get("type") == "error":
            print(f"[!] Frida In-Process Error: {message.get('description')}", file=sys.stderr)

    def run_dry_run(self, duration=5):
        """Simulates instrumented execution and generates mock telemetry."""
        print(f"[+] [DRY-RUN] Connecting to Frida daemon at {self.host}:{self.port}...")
        print(f"[+] [DRY-RUN] Spawning target package '{self.package_name}'...")
        print(f"[+] [DRY-RUN] Injected stealth agents: bypass_antidebug, crypto_dumper, socket_tracer")
        print(f"[*] [DRY-RUN] Simulating {duration} seconds of malware telemetry...")

        # Generate sample events
        os.makedirs(os.path.dirname(os.path.abspath(self.log_path)), exist_ok=True)
        now_ms = int(time.time() * 1000)
        sample_events = [
            {
                "event": "DNS_LOOKUP",
                "hostname": "c2-api.malicious-gate.example",
                "timestamp_ms": now_ms + 100
            },
            {
                "event": "SOCKET_CONNECT",
                "family": "AF_INET",
                "destination_ip": "198.51.100.24",
                "destination_port": 8443,
                "timestamp_ms": now_ms + 250
            },
            {
                "event": "CRYPTO_INIT",
                "algorithm": "AES/CBC/PKCS5Padding",
                "opmode": "ENCRYPT_MODE",
                "key_algorithm": "AES",
                "key_hex": "4a8f9c01823901b2c3d4e5f6071829304a8f9c01823901b2c3d4e5f607182930",
                "iv_hex": "00112233445566778899aabbccddeeff",
                "timestamp_ms": now_ms + 500
            },
            {
                "event": "CRYPTO_DOFINAL",
                "algorithm": "AES/CBC/PKCS5Padding",
                "input_length": 98,
                "input_hex": "596f7572206f6e652d74696d6520617574686f72697a6174696f6e20636f64652069732039383432313720666f72207472616e73616374696f6e2054582d43414e4152592d3838333932312e",
                "input_utf8": "Your one-time authorization code is 984217 for transaction TX-CANARY-883921.",
                "output_length": 112,
                "output_hex": "a1b2c3d4e5f6071829304a8f9c018239a1b2c3d4e5f6071829304a8f9c018239",
                "timestamp_ms": now_ms + 750
            }
        ]

        with open(self.log_path, "w", encoding="utf-8") as f:
            for ev in sample_events:
                f.write(json.dumps(ev) + "\n")
                print(f"  [{ev['event']}] Simulated telemetry event logged.")

        print(f"[+] [DRY-RUN] Telemetry logged to {self.log_path}")
        return True

    def run(self, script_paths, duration=120):
        """Spawns target app, injects hooks, and streams telemetry."""
        if self.dry_run or not HAS_FRIDA:
            if not HAS_FRIDA and not self.dry_run:
                print("[-] Notice: 'frida' Python module not installed. Falling back to simulation mode.", file=sys.stderr)
            return self.run_dry_run(duration=min(duration, 5))

        print(f"[*] Connecting to Frida daemon at {self.host}:{self.port}...")
        try:
            mgr = frida.get_device_manager()
            self.device = mgr.add_remote_device(f"{self.host}:{self.port}")
        except Exception as e:
            print(f"[!] Failed to connect to Frida remote device: {e}", file=sys.stderr)
            return False

        print(f"[*] Spawning target package '{self.package_name}'...")
        try:
            self.pid = self.device.spawn([self.package_name])
            self.session = self.device.attach(self.pid)
        except Exception as e:
            print(f"[!] Failed to spawn package '{self.package_name}': {e}", file=sys.stderr)
            return False

        source = self.compile_agent_sources(script_paths)
        print(f"[*] Injected consolidated agent ({len(source)} bytes)...")

        os.makedirs(os.path.dirname(os.path.abspath(self.log_path)), exist_ok=True)
        self.log_file = open(self.log_path, "a", encoding="utf-8")

        script = self.session.create_script(source)
        script.on("message", self.on_message)
        script.load()

        # Resume process execution
        self.device.resume(self.pid)
        print(f"[+] Target process {self.pid} resumed. Monitoring for {duration} seconds...")

        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            print("\n[!] Execution interrupted by user.")
        finally:
            self.cleanup()

        print(f"[+] Session complete. Telemetry persisted to {self.log_path}")
        return True

    def cleanup(self):
        """Cleans up session, terminates target process, and flushes log file."""
        if self.log_file and not self.log_file.closed:
            self.log_file.close()

        if self.session:
            try:
                self.session.detach()
            except Exception:
                pass

        if self.device and self.pid:
            try:
                self.device.kill(self.pid)
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(
        description="dbug Stealth Frida Runtime Instrumentation Loader (Gate G4)"
    )
    parser.add_argument("--apk", default=None, help="Target APK path (extracts package name)")
    parser.add_argument("--package", default=None, help="Target Android package name")
    parser.add_argument("--config", default="config/lab_config.yaml", help="Path to lab_config.yaml")
    parser.add_argument("--port", type=int, default=None, help="Frida remote TCP port (default: 38921)")
    parser.add_argument("--duration", type=int, default=120, help="Observation window in seconds")
    parser.add_argument("--output", default="./sessions/current_capture/instrumentation_events.jsonl", help="Telemetry output log")
    parser.add_argument("--dry-run", action="store_true", help="Simulate execution without physical hardware")
    args = parser.parse_args()

    cfg = parse_lab_config(args.config)
    sample_cfg = cfg.get("lab_environment", {}).get("target_sample", {})
    frida_cfg = cfg.get("lab_environment", {}).get("telemetry", {}).get("frida", {})

    package_name = args.package or sample_cfg.get("package_name") or "com.example.malware"
    port = args.port or frida_cfg.get("port", 38921)
    duration = args.duration

    script_paths = [
        "instrumentation/agent/bypass_antidebug.js",
        "instrumentation/agent/crypto_dumper.js",
        "instrumentation/agent/socket_tracer.js"
    ]

    loader = FridaLoader(
        package_name=package_name,
        port=port,
        log_path=args.output,
        dry_run=args.dry_run
    )

    def sig_handler(sig, frame):
        print("\n[!] Signal received. Shutting down instrumentation...")
        loader.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    loader.run(script_paths, duration=duration)


if __name__ == "__main__":
    main()
