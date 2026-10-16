---
name: dbug-ebpf-capture
description: Zero-footprint kernel-level TLS plaintext interception and master secret extraction using eBPF uprobes with eCapture (Gate G3). Attaches to Conscrypt's libssl.so at the Linux kernel layer, generating sslkey.log and decrypted pcapng streams without modifying malware memory or breaking TLS certificate chains. Use when configuring, launching, or troubleshooting eBPF TLS decryption.
---

# dbug-ebpf-capture (Gate G3)

Intercept decrypted TLS traffic and TLS master keys directly from the Linux kernel using eBPF uprobes.

---

## 1. Why eBPF Beats Traditional MitM Proxies

| Feature | MitM Proxy (Burp / mitmproxy) | eBPF Uprobe (`ecapture`) |
|---|---|---|
| **Android Proxy Property** | Sets `http.proxyHost` (Easily detected) | None (`getprop http.proxyHost` is empty) |
| **CA Certificate** | Requires installing untrusted user CA | Preserves 100% stock system trust store |
| **SSL Pinning** | Fails unless patched/unpinned in memory | Bypasses pinning naturally (hooks `SSL_read`/`SSL_write`) |
| **Process Tampering** | Requires in-process memory hooks / injection | Zero memory modifications inside malware address space |

---

## 2. On-Device Prerequisites
- Physical device running Linux kernel 5.4+ with eBPF and uprobes enabled (`CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_UPROBES=y`).
- Static ARM64 binary of `ecapture` located at `/data/local/tmp/ecapture`.
- Conscrypt library target path: `/apex/com.android.conscrypt/lib64/libssl.so` (or 32-bit equivalent `/apex/com.android.conscrypt/lib/libssl.so`).

---

## 3. eCapture Automation Runner (`network_capture/ecapture_runner.py`)

Host Python script controlling the background eBPF capture process on Android:

```python
import subprocess
import time
import os

ECAPTURE_PATH = "/data/local/tmp/ecapture"
REMOTE_KEYLOG = "/data/local/tmp/sslkey.log"
REMOTE_PCAPNG = "/data/local/tmp/tls_decrypted.pcapng"
LIBSSL_PATH = "/apex/com.android.conscrypt/lib64/libssl.so"

class ECaptureRunner:
    def __init__(self, device_serial=None):
        self.device_cmd = ["adb"] if not device_serial else ["adb", "-s", device_serial]

    def start(self, iface="wlan0"):
        print("[*] Launching eBPF TLS capture via eCapture on device...")
        # Clear old capture artifacts
        subprocess.run(self.device_cmd + ["shell", "su", "-c", f"rm -f {REMOTE_KEYLOG} {REMOTE_PCAPNG}"])
        
        # Build command: captures decrypted pcapng + emits NSS sslkey.log
        cmd = [
            "shell", "su", "-c",
            f"nohup {ECAPTURE_PATH} tls -m pcap -i {iface} "
            f"--pcapfile={REMOTE_PCAPNG} --sslkeylog={REMOTE_KEYLOG} "
            f"--libssl={LIBSSL_PATH} > /data/local/tmp/ecapture.log 2>&1 &"
        ]
        subprocess.run(self.device_cmd + cmd)
        time.sleep(2)
        print("[+] eCapture attached to libssl.so uprobes.")

    def stop(self, local_output_dir):
        print("[*] Stopping eCapture and retrieving TLS captures...")
        subprocess.run(self.device_cmd + ["shell", "su", "-c", "pkill -2 ecapture || pkill -15 ecapture"])
        time.sleep(2)

        os.makedirs(local_output_dir, exist_ok=True)
        # Pull keylog and pcapng
        subprocess.run(self.device_cmd + ["pull", REMOTE_KEYLOG, os.path.join(local_output_dir, "sslkey.log")])
        subprocess.run(self.device_cmd + ["pull", REMOTE_PCAPNG, os.path.join(local_output_dir, "tls_decrypted.pcapng")])
        print(f"[+] TLS master keys and decrypted PCAP saved to {local_output_dir}")
```

---

## 4. Verification of eBPF TLS Streams
Once pulled to the host:
```bash
# Verify sslkey.log contains CLIENT_RANDOM entries
head -n 5 sessions/current_capture/sslkey.log

# Inspect decrypted pcapng
tshark -r sessions/current_capture/tls_decrypted.pcapng -Y "http || http2"
```
If keylog entries are present, all TLS streams can be decrypted in `pcap_decryptor.py`.
