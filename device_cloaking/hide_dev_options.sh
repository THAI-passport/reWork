#!/system/bin/sh
# hide_dev_options.sh: Hides Android Developer Options from user-space apps.
#
# Writes adb_enabled=0 and development_settings_enabled=0 to Settings.Global
# via root (su -c), so malware and RASP engines reading these settings observe
# a clean production device. System properties (ro.debuggable, etc.) are handled
# separately by apply_stealth_props.sh.
#
# Usage:
#   hide_dev_options.sh [--dry-run] apply    - Hide developer options
#   hide_dev_options.sh [--dry-run] restore  - Revert to developer defaults
#   hide_dev_options.sh [--dry-run] status   - Print current values
#   hide_dev_options.sh [--dry-run] verify   - Exit 0 if both are 0, exit 1 otherwise

DRY_RUN=false

# Parse --dry-run flag
if [ "$1" = "--dry-run" ]; then
    DRY_RUN=true
    shift
fi

ACTION="${1:-apply}"

set_global() {
    KEY="$1"
    VAL="$2"
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY-RUN] Would settings put global $KEY $VAL"
        return 0
    fi
    settings put global "$KEY" "$VAL"
}

get_global() {
    KEY="$1"
    if [ "$DRY_RUN" = true ]; then
        echo "0"
        return 0
    fi
    settings get global "$KEY"
}

case "$ACTION" in
    apply)
        echo "[*] Hiding Android developer options via Settings.Global..."
        set_global adb_enabled 0
        set_global development_settings_enabled 0
        echo "[+] adb_enabled=0"
        echo "[+] development_settings_enabled=0"
        ;;
    restore)
        echo "[*] Restoring developer options to defaults..."
        set_global adb_enabled 1
        set_global development_settings_enabled 1
        echo "[+] adb_enabled=1"
        echo "[+] development_settings_enabled=1"
        ;;
    status)
        echo "=================================================================="
        echo "ANDROID DEVELOPER OPTIONS STATUS (Settings.Global)"
        echo "=================================================================="
        printf "%-40s %-15s\n" "Setting" "Current Value"
        echo "--------------------------------------------------------------"
        printf "%-40s %-15s\n" "adb_enabled" "$(get_global adb_enabled)"
        printf "%-40s %-15s\n" "development_settings_enabled" "$(get_global development_settings_enabled)"
        echo "=================================================================="
        ;;
    verify)
        ADB_VAL="$(get_global adb_enabled)"
        DEV_VAL="$(get_global development_settings_enabled)"
        if [ "$ADB_VAL" = "0" ] && [ "$DEV_VAL" = "0" ]; then
            echo "[+] Developer options are HIDDEN (adb_enabled=0, development_settings_enabled=0)"
            exit 0
        else
            echo "[-] Developer options are EXPOSED (adb_enabled=$ADB_VAL, development_settings_enabled=$DEV_VAL)"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 [--dry-run] {apply|restore|status|verify}"
        exit 1
        ;;
esac
