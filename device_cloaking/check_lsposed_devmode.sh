#!/system/bin/sh
# check_lsposed_devmode.sh: Audits system_server SettingsProvider cloaking and LSPosed HideDevMode.
# Run on Android device via root: adb shell su -c "sh /data/local/tmp/check_lsposed_devmode.sh"

echo "============================================================"
echo "AUDITING SYSTEM_SERVER CLOAKING & SETTINGS.GLOBAL STATUS"
echo "============================================================"

FAIL=0

# 1. Audit LSPosed Framework Presence
echo "[*] Step 1: Checking LSPosed Framework State..."
if [ -d "/data/adb/lspd" ] || [ -d "/data/adb/modules/zygisk_lsposed" ] || [ -d "/data/adb/modules/riru_lsposed" ]; then
    echo "  [+] LSPosed directory detected on device (PASS)"
else
    echo "  [-] WARNING: LSPosed installation directory not detected in standard paths."
    echo "      Ensure Zygisk + LSPosed is installed in Magisk/KernelSU/APatch."
fi

# 2. Check for HideDevMode or Developer Hiding Modules
echo "[*] Step 2: Checking for HideDevMode Module..."
HIDEDEV_PKG=$(pm list packages | grep -E "hidedev|devmode|hide_dev" | head -n 1)
if [ -n "$HIDEDEV_PKG" ]; then
    echo "  [+] HideDevMode package found: $HIDEDEV_PKG (PASS)"
else
    echo "  [-] WARNING: No package matching 'hidedev' found in package manager."
    echo "      If HideDevMode is enabled as an internal module or system_server hook,"
    echo "      verify return values below."
fi

# 3. Query Settings.Global directly via CLI
echo "[*] Step 3: Querying Settings.Global via SettingsProvider..."
ADB_VAL=$(settings get global adb_enabled 2>/dev/null)
DEV_VAL=$(settings get global development_settings_enabled 2>/dev/null)

echo "  [*] Settings.Global.adb_enabled = '$ADB_VAL'"
echo "  [*] Settings.Global.development_settings_enabled = '$DEV_VAL'"

if [ "$ADB_VAL" = "0" ] || [ "$ADB_VAL" = "null" ] || [ -z "$ADB_VAL" ]; then
    echo "  [+] adb_enabled is successfully masked or 0 (PASS)"
else
    echo "  [!] VIOLATION: adb_enabled reports '$ADB_VAL'. Expected '0' or unexposed."
    FAIL=1
fi

if [ "$DEV_VAL" = "0" ] || [ "$DEV_VAL" = "null" ] || [ -z "$DEV_VAL" ]; then
    echo "  [+] development_settings_enabled is 0 or unexposed (PASS)"
else
    echo "  [-] Recommendation: Set development_settings_enabled to 0."
fi

# 4. Query via Content Provider
echo "[*] Step 4: Querying content://settings/global content provider..."
CP_QUERY=$(content query --uri content://settings/global --where "name='adb_enabled'" 2>/dev/null)
echo "  [*] Content provider result: $CP_QUERY"

echo "============================================================"
if [ "$FAIL" -eq 0 ]; then
    echo "[+] SYSTEM_SERVER SETTINGS AUDIT PASSED: Developer flags masked."
    exit 0
else
    echo "[!] SYSTEM_SERVER SETTINGS AUDIT FAILED."
    echo "    To fix: Enable LSPosed 'HideDevMode' targeting system_server,"
    echo "    or execute: settings put global adb_enabled 0"
    exit 1
fi
