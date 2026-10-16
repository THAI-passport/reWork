---
name: dbug-network-gateway
description: Configuration and management of the isolated Linux Wi-Fi Access Point gateway (Gate G3). Sets up hostapd, dnsmasq, iptables NAT masquerade, DNS query logging, and transparent full-payload tcpdump capture on interface ap0 without installing device certificates or proxy settings. Use when configuring out-of-band network interception or managing gateway packet captures.
---

# dbug-network-gateway (Gate G3)

Zero-footprint network capture: Capture 100% of L3/L4 packets, DNS queries, and raw TCP/UDP flows outside the Android device.

---

## 1. Gateway Architecture

```
Physical Android Phone (wlan0)
  │ (Wi-Fi 802.11 connection to SSID "Lab-Isolated-AP")
  ▼
Dedicated Wi-Fi Adapter (ap0) on Linux Gateway Host
  ├── hostapd: Manages 802.11 Access Point
  ├── dnsmasq: DHCP server (192.168.44.0/24) + DNS logging
  ├── tcpdump: Out-of-band full packet capture (raw_traffic.pcap)
  └── iptables: NAT masquerade to upstream Ethernet (eth0)
```

No system proxy. No custom CA certificates. No VPN apps or `tun0` interfaces on the device.

---

## 2. Gateway Automation Script (`network_capture/gateway_setup.sh`)

```bash
#!/usr/bin/env bash
# Linux Wi-Fi AP + NAT + tcpdump capture setup
set -euo pipefail

AP_IFACE="ap0"
UPSTREAM_IFACE="eth0"
SUBNET="192.168.44"
GATEWAY_IP="${SUBNET}.1"
PCAP_DIR="./sessions/current_capture"
ACTION="${1:-start}"

mkdir -p "${PCAP_DIR}"

if [ "${ACTION}" = "stop" ]; then
    echo "[*] Stopping gateway and packet capture..."
    pkill -f "tcpdump -i ${AP_IFACE}" || true
    systemctl stop hostapd dnsmasq || true
    iptables -t nat -D POSTROUTING -o "${UPSTREAM_IFACE}" -j MASQUERADE 2>/dev/null || true
    echo 0 > /proc/sys/net/ipv4/ip_forward
    echo "[+] Gateway stopped cleanly."
    exit 0
fi

echo "[*] Initializing isolated gateway on ${AP_IFACE}..."
# 1. Enable IPv4 packet forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# 2. Configure AP interface IP
ip addr flush dev "${AP_IFACE}" || true
ip addr add "${GATEWAY_IP}/24" dev "${AP_IFACE}"
ip link set "${AP_IFACE}" up

# 3. Configure iptables NAT
iptables -t nat -A POSTROUTING -o "${UPSTREAM_IFACE}" -j MASQUERADE
iptables -A FORWARD -i "${AP_IFACE}" -o "${UPSTREAM_IFACE}" -j ACCEPT
iptables -A FORWARD -i "${UPSTREAM_IFACE}" -o "${AP_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT

# 4. Start hostapd & dnsmasq
systemctl restart hostapd
systemctl restart dnsmasq

# 5. Launch full-payload tcpdump in background
echo "[*] Starting raw L3/L4 packet capture on ${AP_IFACE}..."
nohup tcpdump -i "${AP_IFACE}" -s 0 -n -w "${PCAP_DIR}/raw_traffic.pcap" > "${PCAP_DIR}/tcpdump.log" 2>&1 &

echo "[+] Gateway active: AP=${AP_IFACE}, IP=${GATEWAY_IP}, PCAP=${PCAP_DIR}/raw_traffic.pcap"
```

---

## 3. DNS Query Auditing
`dnsmasq` logs all domain queries independently:
```bash
# Watch real-time DNS requests from the Android device
tail -f /var/log/dnsmasq.log | grep -E "query\[A|AAAA\]"
```
This isolates C2 Domain Generation Algorithms (DGA), fast-flux domains, and resolved IP mappings even if the malware uses raw IP addresses for subsequent payload delivery.

---

## 4. Teardown & Capture Verification
When stopping the session:
1. Send `SIGINT` / `SIGTERM` to `tcpdump`.
2. Verify PCAP integrity:
   ```bash
   capinfos sessions/current_capture/raw_traffic.pcap
   ```
3. Check for truncated frames or zero packet counts.
