#!/system/bin/sh
# apply_emulator_stealth.sh: Cloak Android emulator (AVD) indicators so target
# malware/RASP cannot detect it is running in an emulator under analysis.
#
# Layer C (emulator-specific), on top of Layer A
# (device_cloaking/apply_stealth_props.sh: kernel/property masking) and Layer B
# (device_cloaking/hide_dev_options.sh: Settings.Global via LSPosed HideDevMode).
#
# Requires resetprop (a rooted emulator: Magisk / KernelSU / APatch).
#
# Usage:
#   apply_emulator_stealth.sh [--dry-run] apply    - Cloak emulator indicators
#   apply_emulator_stealth.sh [--dry-run] restore  - Revert to emulator defaults
#   apply_emulator_stealth.sh [--dry-run] status   - Print current values
#   apply_emulator_stealth.sh [--dry-run] verify   - Print values (best effort, exit 0)
#
# Notes:
#   ro.kernel.qemu and ro.hardware are set by the kernel/init at boot and are
#   read-only on many system images; resetprop can override them at runtime in
#   the init property namespace, but some readers may still see the boot value.
#   Where resetprop cannot reach a property, use a pre-cloaked AVD system image
#   (edit build.prop / default.prop) instead. All bypasses here are best-effort
#   [I]; none is claimed undetectable.

DRY_RUN=false
if [ "$1" = "--dry-run" ]; then
    DRY_RUN=true
    shift
fi

ACTION="${1:-apply}"

# Target property -> cloaked value (non-emulator, production-like).
set_prop() {
    PROP="$1"
    VAL="$2"
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY-RUN] Would resetprop $PROP $VAL"
        return 0
    fi
    resetprop "$PROP" "$VAL" 2>/dev/null || echo "[!] resetprop $PROP $VAL failed (read-only or unsupported)"
}

get_prop() {
    PROP="$1"
    if [ "$DRY_RUN" = true ]; then
        echo "<simulated>"
        return 0
    fi
    getprop "$PROP"
}

case "$ACTION" in
    apply)
        echo "[*] Cloaking emulator (AVD) indicators via resetprop..."
        # Emulator kernel/boot flags
        set_prop ro.kernel.qemu 0
        set_prop ro.emulator 0
        # Build identity (non-emulator model)
        set_prop ro.product.model "Pixel 6"
        set_prop ro.product.brand google
        set_prop ro.product.manufacturer Google
        set_prop ro.product.device oriole
        set_prop ro.product.name oriole
        set_prop ro.product.board oriole
        set_prop ro.hardware oriole
        set_prop ro.build.product oriole
        set_prop ro.serialno RF8A4100000
        # Release-like build fingerprint (avoid "generic"/"sdk"/"google" emulator tokens)
        set_prop ro.build.fingerprint "google/oriole/oriole:13/TD1A.220804.031/9876543:user/release-keys"
        set_prop ro.build.description "oriole-user 13 TD1A.220804.031 9876543 release-keys"
        echo "[+] Emulator stealth properties applied (best effort)."
        ;;
    restore)
        echo "[*] Restoring emulator defaults..."
        set_prop ro.kernel.qemu 1
        set_prop ro.emulator 1
        set_prop ro.product.model "sdk_gphone_x86_64"
        set_prop ro.product.brand google
        set_prop ro.product.manufacturer Google
        set_prop ro.product.device emulator
        set_prop ro.product.name sdk_gphone_x86_64
        set_prop ro.product.board goldfish
        set_prop ro.hardware goldfish
        set_prop ro.build.product sdk_gphone_x86_64
        set_prop ro.serialno unknown
        set_prop ro.build.fingerprint "google/sdk_gphone_x86_64/sdk_gphone_x86_64:13/...:user/release-keys"
        set_prop ro.build.description "sdk_gphone_x86_64-user 13 ... release-keys"
        echo "[+] Emulator defaults restored."
        ;;
    status)
        echo "============================================================"
        echo "EMULATOR STEALTH PROPERTY STATUS"
        echo "============================================================"
        printf "%-30s %-20s %-20s\n" "Property" "Current Value" "Cloak Target"
        echo "------------------------------------------------------------"
        printf "%-30s %-20s %-20s\n" "ro.kernel.qemu" "$(get_prop ro.kernel.qemu)" "0"
        printf "%-30s %-20s %-20s\n" "ro.emulator" "$(get_prop ro.emulator)" "0"
        printf "%-30s %-20s %-20s\n" "ro.product.model" "$(get_prop ro.product.model)" "non-emulator"
        printf "%-30s %-20s %-20s\n" "ro.product.device" "$(get_prop ro.product.device)" "non-emulator"
        printf "%-30s %-20s %-20s\n" "ro.product.name" "$(get_prop ro.product.name)" "non-emulator"
        printf "%-30s %-20s %-20s\n" "ro.product.board" "$(get_prop ro.product.board)" "non-goldfish"
        printf "%-30s %-20s %-20s\n" "ro.hardware" "$(get_prop ro.hardware)" "non-goldfish"
        printf "%-30s %-20s %-20s\n" "ro.build.fingerprint" "$(get_prop ro.build.fingerprint)" "release build"
        printf "%-30s %-20s %-20s\n" "ro.serialno" "$(get_prop ro.serialno)" "non-unknown"
        echo "============================================================"
        ;;
    verify|*)
        echo "[*] Emulator stealth property values (best effort):"
        get_prop ro.kernel.qemu
        get_prop ro.emulator
        get_prop ro.product.model
        get_prop ro.hardware
        get_prop ro.build.fingerprint
        exit 0
        ;;
esac
