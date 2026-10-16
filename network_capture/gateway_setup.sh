#!/usr/bin/env bash
# gateway_setup.sh: Configures an isolated Linux Wi-Fi Access Point (ap0),
# enables transparent iptables NAT routing, and manages background tcpdump capture.
#
# Usage:
#   sudo ./gateway_setup.sh start [--ap ap0] [--upstream eth0] [--output-dir ./sessions/current]
#   sudo ./gateway_setup.sh stop [--ap ap0] [--upstream eth0]
#   ./gateway_setup.sh status [--ap ap0]
#   ./gateway_setup.sh --dry-run start

set -euo pipefail

ACTION="start"
DRY_RUN=false
AP_IFACE="ap0"
UPSTREAM_IFACE="eth0"
SUBNET="192.168.44"
GATEWAY_IP="${SUBNET}.1"
OUTPUT_DIR="./sessions/current_capture"

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        start|stop|status)
            ACTION="$1"
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --ap)
            AP_IFACE="$2"
            shift 2
            ;;
        --upstream)
            UPSTREAM_IFACE="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [start|stop|status] [--dry-run] [--ap ap0] [--upstream eth0] [--output-dir path]"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

run_cmd() {
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY-RUN] $*"
    else
        "$@"
    fi
}

PID_FILE="${OUTPUT_DIR}/tcpdump.pid"
PCAP_FILE="${OUTPUT_DIR}/raw_traffic.pcap"
LOG_FILE="${OUTPUT_DIR}/tcpdump.log"

case "$ACTION" in
    status)
        echo "============================================================"
        echo "ISOLATED WI-FI GATEWAY STATUS (${AP_IFACE})"
        echo "============================================================"
        if [ "$DRY_RUN" = true ]; then
            echo "[+] [DRY-RUN] Gateway status simulated: ACTIVE"
            exit 0
        fi

        # Check interface
        if ip link show "${AP_IFACE}" >/dev/null 2>&1; then
            echo "  [+] AP Interface: ${AP_IFACE} is UP"
        else
            echo "  [-] AP Interface: ${AP_IFACE} NOT found or down"
        fi

        # Check IP Forwarding
        if [ -f /proc/sys/net/ipv4/ip_forward ]; then
            FWD=$(cat /proc/sys/net/ipv4/ip_forward)
            echo "  [*] IPv4 Forwarding: ${FWD}"
        fi

        # Check tcpdump process
        if [ -f "${PID_FILE}" ] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
            echo "  [+] tcpdump: RUNNING (PID $(cat "${PID_FILE}"))"
            echo "      Output PCAP: ${PCAP_FILE}"
        else
            echo "  [-] tcpdump: NOT RUNNING"
        fi
        echo "============================================================"
        exit 0
        ;;

    stop)
        echo "[*] Stopping isolated Wi-Fi gateway and capture on ${AP_IFACE}..."

        # 1. Stop background tcpdump
        if [ -f "${PID_FILE}" ]; then
            TCP_PID=$(cat "${PID_FILE}" 2>/dev/null || true)
            if [ -n "${TCP_PID}" ]; then
                echo "  [*] Stopping tcpdump (PID ${TCP_PID})..."
                run_cmd kill -15 "${TCP_PID}" 2>/dev/null || true
                sleep 1
                run_cmd rm -f "${PID_FILE}"
            fi
        else
            run_cmd pkill -f "tcpdump.*${AP_IFACE}" 2>/dev/null || true
        fi

        # 2. Stop hostapd and dnsmasq services if managed
        if command -v systemctl >/dev/null 2>&1; then
            run_cmd systemctl stop hostapd 2>/dev/null || true
            run_cmd systemctl stop dnsmasq 2>/dev/null || true
        fi

        # 3. Teardown iptables NAT rules
        if command -v iptables >/dev/null 2>&1; then
            echo "  [*] Flushing NAT and forwarding rules..."
            run_cmd iptables -t nat -D POSTROUTING -o "${UPSTREAM_IFACE}" -j MASQUERADE 2>/dev/null || true
            run_cmd iptables -D FORWARD -i "${AP_IFACE}" -o "${UPSTREAM_IFACE}" -j ACCEPT 2>/dev/null || true
            run_cmd iptables -D FORWARD -i "${UPSTREAM_IFACE}" -o "${AP_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
        fi

        # 4. Disable packet forwarding
        if [ -f /proc/sys/net/ipv4/ip_forward ] && [ "$DRY_RUN" = false ]; then
            echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
        elif [ "$DRY_RUN" = true ]; then
            echo "[DRY-RUN] echo 0 > /proc/sys/net/ipv4/ip_forward"
        fi

        echo "[+] Gateway teardown complete. Traffic routing reverted."
        exit 0
        ;;

    start)
        echo "[*] Initializing isolated Wi-Fi gateway on ${AP_IFACE}..."
        run_cmd mkdir -p "${OUTPUT_DIR}"

        # 1. Enable IPv4 packet forwarding
        echo "  [*] Enabling IPv4 forwarding..."
        if [ -f /proc/sys/net/ipv4/ip_forward ] && [ "$DRY_RUN" = false ]; then
            echo 1 > /proc/sys/net/ipv4/ip_forward
        elif [ "$DRY_RUN" = true ]; then
            echo "[DRY-RUN] echo 1 > /proc/sys/net/ipv4/ip_forward"
        fi

        # 2. Configure AP interface address
        echo "  [*] Assigning gateway IP ${GATEWAY_IP}/24 to ${AP_IFACE}..."
        run_cmd ip addr flush dev "${AP_IFACE}" 2>/dev/null || true
        run_cmd ip addr add "${GATEWAY_IP}/24" dev "${AP_IFACE}" 2>/dev/null || true
        run_cmd ip link set "${AP_IFACE}" up 2>/dev/null || true

        # 3. Configure iptables NAT
        echo "  [*] Configuring iptables transparent NAT masquerade..."
        run_cmd iptables -t nat -A POSTROUTING -o "${UPSTREAM_IFACE}" -j MASQUERADE
        run_cmd iptables -A FORWARD -i "${AP_IFACE}" -o "${UPSTREAM_IFACE}" -j ACCEPT
        run_cmd iptables -A FORWARD -i "${UPSTREAM_IFACE}" -o "${AP_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT

        # 4. Start hostapd & dnsmasq
        echo "  [*] Starting hostapd and dnsmasq..."
        if command -v systemctl >/dev/null 2>&1; then
            run_cmd systemctl restart hostapd 2>/dev/null || true
            run_cmd systemctl restart dnsmasq 2>/dev/null || true
        fi

        # 5. Launch full-payload tcpdump in background
        echo "  [*] Launching background tcpdump (full frames, no truncating)..."
        if [ "$DRY_RUN" = true ]; then
            echo "[DRY-RUN] nohup tcpdump -i ${AP_IFACE} -s 0 -n -w ${PCAP_FILE} > ${LOG_FILE} 2>&1 &"
            echo "[DRY-RUN] echo \$! > ${PID_FILE}"
        else
            nohup tcpdump -i "${AP_IFACE}" -s 0 -n -w "${PCAP_FILE}" > "${LOG_FILE}" 2>&1 &
            echo $! > "${PID_FILE}"
        fi

        echo "[+] Gateway active: AP=${AP_IFACE}, IP=${GATEWAY_IP}"
        echo "    Full L3/L4 PCAP stream: ${PCAP_FILE}"
        echo "    DNS Query Log: /var/log/dnsmasq.log"
        exit 0
        ;;
esac
