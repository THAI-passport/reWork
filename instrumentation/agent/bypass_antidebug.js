/**
 * bypass_antidebug.js: In-process fallback stealth cloak for dbug.
 * Intercepts Java Settings.Global, Debugger checks, and libc system properties.
 */

Java.perform(() => {
    // -------------------------------------------------------------------------
    // 1. Spoof Settings.Global Developer & ADB Flags
    // -------------------------------------------------------------------------
    try {
        const SettingsGlobal = Java.use("android.provider.Settings$Global");
        
        // Overload 1: getInt(ContentResolver cr, String name, int def)
        SettingsGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, def) {
            if (name === "adb_enabled" || name === "development_settings_enabled") {
                return 0;
            }
            return this.getInt(cr, name, def);
        };

        // Overload 2: getInt(ContentResolver cr, String name)
        SettingsGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
            if (name === "adb_enabled" || name === "development_settings_enabled") {
                return 0;
            }
            return this.getInt(cr, name);
        };
    } catch (e) {
        // Class or overload may vary across custom OEM ROMs
    }

    try {
        const SettingsSecure = Java.use("android.provider.Settings$Secure");
        SettingsSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, def) {
            if (name === "adb_enabled" || name === "development_settings_enabled") {
                return 0;
            }
            return this.getInt(cr, name, def);
        };
    } catch (e) {}

    // -------------------------------------------------------------------------
    // 2. Spoof Java Framework Debugger Connection Checks
    // -------------------------------------------------------------------------
    try {
        const Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = () => false;
        Debug.waitingForDebugger.implementation = () => false;
    } catch (e) {}
});

// -----------------------------------------------------------------------------
// 3. Native libc __system_property_get Interceptor
// -----------------------------------------------------------------------------
(() => {
    const propGet = Module.findExportByName("libc.so", "__system_property_get");
    if (propGet) {
        Interceptor.attach(propGet, {
            onEnter(args) {
                this.name = args[0].readCString();
                this.valuePtr = args[1];
            },
            onLeave(retval) {
                if (!this.name || !this.valuePtr) return;

                if (this.name === "ro.debuggable") {
                    this.valuePtr.writeUtf8String("0");
                } else if (this.name === "ro.secure") {
                    this.valuePtr.writeUtf8String("1");
                } else if (this.name === "sys.usb.state" || this.name === "sys.usb.config" || this.name === "persist.sys.usb.config") {
                    this.valuePtr.writeUtf8String("mtp");
                } else if (this.name === "init.svc.adbd") {
                    this.valuePtr.writeUtf8String("stopped");
                }
            }
        });
    }

    // -------------------------------------------------------------------------
    // 4. Native ptrace(PTRACE_TRACEME) Denial Interceptor
    // -------------------------------------------------------------------------
    const ptracePtr = Module.findExportByName("libc.so", "ptrace");
    if (ptracePtr) {
        Interceptor.attach(ptracePtr, {
            onEnter(args) {
                this.request = args[0].toInt32();
            },
            onLeave(retval) {
                // PTRACE_TRACEME is 0. If called, spoof return code 0 (success)
                if (this.request === 0) {
                    retval.replace(ptr(0));
                }
            }
        });
    }

    // -------------------------------------------------------------------------
    // 5. Anti-Root File Existence Checks (access / faccessat)
    // -------------------------------------------------------------------------
    const accessPtr = Module.findExportByName("libc.so", "access");
    if (accessPtr) {
        Interceptor.attach(accessPtr, {
            onEnter(args) {
                this.path = args[0].readCString();
            },
            onLeave(retval) {
                if (this.path && (this.path.indexOf("/su") !== -1 || this.path.indexOf("magisk") !== -1 || this.path.indexOf("busybox") !== -1)) {
                    // Spoof file not found (-1)
                    retval.replace(ptr(-1));
                }
            }
        });
    }

    // -------------------------------------------------------------------------
    // 6. Evasion Termination Watchdog (Logging self-kill attempts)
    // -------------------------------------------------------------------------
    const killPtr = Module.findExportByName("libc.so", "kill");
    if (killPtr) {
        Interceptor.attach(killPtr, {
            onEnter(args) {
                const pid = args[0].toInt32();
                const sig = args[1].toInt32();
                if (sig === 9 || sig === 15 || sig === 6) {
                    send({
                        event: "SELF_TERMINATION_ATTEMPT",
                        target_pid: pid,
                        signal: sig,
                        callstack: Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n")
                    });
                }
            }
        });
    }
})();
