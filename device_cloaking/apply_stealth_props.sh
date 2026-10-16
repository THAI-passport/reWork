#!/system/bin/sh
# apply_stealth_props.sh: Masks Android system properties to present an un-debugged production state.
# Designed for Magisk, KernelSU, and APatch environments using resetprop.
# Usage:
#   apply_stealth_props.sh apply    - Mask properties for malware analysis
#   apply_stealth_props.sh restore  - Revert properties for standard debugging
#   apply_stealth_props.sh status   - Print current property values
#   apply_stealth_props.sh verify   - Return exit code 0 if stealth, 1 if unmasked

ACTION="${1:-apply}"

# Discover resetprop binary
find_resetprop() {
    if command -v resetprop >/dev/null 2>&1; then
        echo "resetprop"
        return 0
    fi
    for p in /data/adb/ksu/bin/resetprop /data/adb/ap/bin/resetprop /data/adb/magisk/resetprop /system/bin/resetprop /sbin/resetprop; do
        if [ -x "$p" ]; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

RESETPROP=$(find_resetprop)

if [ -z "$RESETPROP" ]; then
    echo "[!] Error: 'resetprop' binary not found. Requires Magisk, KernelSU, or APatch root."
    exit 1
fi

set_prop() {
    PROP="$1"
    VAL="$2"
    "$RESETPROP" "$PROP" "$VAL"
}

get_prop() {
    PROP="$1"
    getprop "$PROP"
}

case "$ACTION" in
    restore)
        echo "[*] Restoring standard developer debug properties..."
        set_prop ro.debuggable 1
        set_prop sys.usb.state adb
        set_prop sys.usb.config adb
        set_prop init.svc.adbd running
        echo "[+] Restore complete. Properties reverted to developer defaults."
        exit 0
        ;;

    status)
        echo "============================================================"
        echo "CURRENT DEVICE STEALTH PROPERTY STATUS"
        echo "============================================================"
        printf "%-25s %-15s %-15s\n" "Property" "Current Value" "Stealth Target"
        echo "------------------------------------------------------------"
        printf "%-25s %-15s %-15s\n" "ro.debuggable" "$(get_prop ro.debuggable)" "0"
        printf "%-25s %-15s %-15s\n" "ro.secure" "$(get_prop ro.secure)" "1"
        printf "%-25s %-15s %-15s\n" "ro.build.type" "$(get_prop ro.build.type)" "user"
        printf "%-25s %-15s %-15s\n" "ro.build.tags" "$(get_prop ro.build.tags)" "release-keys"
        printf "%-25s %-15s %-15s\n" "sys.usb.state" "$(get_prop sys.usb.state)" "mtp"
        printf "%-25s %-15s %-15s\n" "sys.usb.config" "$(get_prop sys.usb.config)" "mtp"
        printf "%-25s %-15s %-15s\n" "persist.sys.usb.config" "$(get_prop persist.sys.usb.config)" "mtp"
        printf "%-25s %-15s %-15s\n" "init.svc.adbd" "$(get_prop init.svc.adbd)" "stopped"
        echo "============================================================"
        exit 0
        ;;

    verify)
        FAIL=0
        [ "$(get_prop ro.debuggable)" = "0" ] || FAIL=1
        [ "$(get_prop ro.secure)" = "1" ] || FAIL=1
        [ "$(get_prop sys.usb.state)" = "mtp" ] || FAIL=1
        [ "$(get_prop sys.usb.config)" = "mtp" ] || FAIL=1
        [ "$(get_prop init.svc.adbd)" = "stopped" ] || FAIL=1

        if [ "$FAIL" -eq 0 ]; then
            echo "[+] All stealth properties VERIFIED."
            exit 0
        else
            echo "[-] Stealth property verification FAILED."
            exit 1
        fi
        ;;

    apply|*)
        echo "[*] Applying stealth cloaking properties via $RESETPROP..."

        # 1. Mask debuggable and security flags
        set_prop ro.debuggable 0
        set_prop ro.secure 1
        set_prop ro.build.type user
        set_prop ro.build.tags release-keys

        # 2. Mask USB state to simulate ordinary charging or MTP
        set_prop sys.usb.state mtp
        set_prop sys.usb.config mtp
        set_prop persist.sys.usb.config mtp

        # 3. Mask adbd service status without killing the active socket
        set_prop init.svc.adbd stopped

        echo "[+] Stealth properties applied successfully."
        echo "    Device reports stock production state to user-space applications."
        exit 0
        ;;
esac
