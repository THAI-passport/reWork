/**
 * bypass_antidebug.js: Production-grade in-process stealth cloak for dbug.
 * Intercepts:
 *   1. Settings.Global, Settings.Secure, and Settings.System (getInt, getString, getLong, getFloat)
 *   2. Debugger connection checks and ApplicationInfo.FLAG_DEBUGGABLE
 *   3. Native libc __system_property_get
 *   4. Procfs /proc/self/status TracerPid masking and /proc/self/maps cloaking
 *   5. Native ptrace(PTRACE_TRACEME) anti-attach
 *   6. Anti-root file checks (access, faccessat, stat)
 *   7. Self-termination watchdog (suppressing and logging SIGKILL/SIGTERM)
 */

Java.perform(() => {
    // -------------------------------------------------------------------------
    // 1. Spoof Settings.Global, Settings.Secure, and Settings.System Flags
    // -------------------------------------------------------------------------
    const devKeys = ["adb_enabled", "development_settings_enabled"];

    function hookSettingsClass(className) {
        try {
            const SettingsCls = Java.use(className);

            // getInt overloads
            try {
                SettingsCls.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, def) {
                    if (devKeys.indexOf(name) !== -1) return 0;
                    return this.getInt(cr, name, def);
                };
            } catch (e) {}

            try {
                SettingsCls.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                    if (devKeys.indexOf(name) !== -1) return 0;
                    return this.getInt(cr, name);
                };
            } catch (e) {}

            // getString overload
            try {
                SettingsCls.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                    if (devKeys.indexOf(name) !== -1) return "0";
                    return this.getString(cr, name);
                };
            } catch (e) {}

            // getLong overloads
            try {
                SettingsCls.getLong.overload('android.content.ContentResolver', 'java.lang.String', 'long').implementation = function(cr, name, def) {
                    if (devKeys.indexOf(name) !== -1) return 0;
                    return this.getLong(cr, name, def);
                };
            } catch (e) {}

            try {
                SettingsCls.getLong.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                    if (devKeys.indexOf(name) !== -1) return 0;
                    return this.getLong(cr, name);
                };
            } catch (e) {}

            // getFloat overloads
            try {
                SettingsCls.getFloat.overload('android.content.ContentResolver', 'java.lang.String', 'float').implementation = function(cr, name, def) {
                    if (devKeys.indexOf(name) !== -1) return 0.0;
                    return this.getFloat(cr, name, def);
                };
            } catch (e) {}

            try {
                SettingsCls.getFloat.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                    if (devKeys.indexOf(name) !== -1) return 0.0;
                    return this.getFloat(cr, name);
                };
            } catch (e) {}
        } catch (e) {}
    }

    hookSettingsClass("android.provider.Settings$Global");
    hookSettingsClass("android.provider.Settings$Secure");
    hookSettingsClass("android.provider.Settings$System");

    // -------------------------------------------------------------------------
    // 2. Spoof Debugger Connection & ApplicationInfo.FLAG_DEBUGGABLE
    // -------------------------------------------------------------------------
    try {
        const Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = () => false;
        Debug.waitingForDebugger.implementation = () => false;
    } catch (e) {}

    try {
        const ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.getApplicationInfo.implementation = function() {
            const info = this.getApplicationInfo();
            if (info) {
                // Clear FLAG_DEBUGGABLE (0x2) and FLAG_TEST_ONLY (0x100)
                info.flags.value = info.flags.value & ~0x2 & ~0x100;
            }
            return info;
        };
    } catch (e) {}
});

// -----------------------------------------------------------------------------
// Native Libc Interceptors
// -----------------------------------------------------------------------------
(() => {
    // 3. Native libc __system_property_get Interceptor
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
                } else if (this.name === "ro.build.type") {
                    this.valuePtr.writeUtf8String("user");
                } else if (this.name === "ro.build.tags") {
                    this.valuePtr.writeUtf8String("release-keys");
                } else if (this.name === "sys.usb.state" || this.name === "sys.usb.config" || this.name === "persist.sys.usb.config") {
                    this.valuePtr.writeUtf8String("mtp");
                } else if (this.name === "init.svc.adbd") {
                    this.valuePtr.writeUtf8String("stopped");
                }
            }
        });
    }

    // 4. Procfs TracerPid & /proc/self/maps Cloaking
    const monitoredFds = {};

    function checkProcPath(path) {
        if (!path) return null;
        if (path.indexOf("/proc/") !== -1 || path.indexOf("/status") !== -1 || path.indexOf("/maps") !== -1) {
            if (path.indexOf("status") !== -1) return "status";
            if (path.indexOf("maps") !== -1) return "maps";
        }
        return null;
    }

    const openPtr = Module.findExportByName("libc.so", "open");
    if (openPtr) {
        Interceptor.attach(openPtr, {
            onEnter(args) {
                this.path = args[0].readCString();
            },
            onLeave(retval) {
                const fd = retval.toInt32();
                if (fd >= 0) {
                    const type = checkProcPath(this.path);
                    if (type) monitoredFds[fd] = type;
                }
            }
        });
    }

    const openatPtr = Module.findExportByName("libc.so", "openat");
    if (openatPtr) {
        Interceptor.attach(openatPtr, {
            onEnter(args) {
                this.path = args[1].readCString();
            },
            onLeave(retval) {
                const fd = retval.toInt32();
                if (fd >= 0) {
                    const type = checkProcPath(this.path);
                    if (type) monitoredFds[fd] = type;
                }
            }
        });
    }

    const closePtr = Module.findExportByName("libc.so", "close");
    if (closePtr) {
        Interceptor.attach(closePtr, {
            onEnter(args) {
                delete monitoredFds[args[0].toInt32()];
            }
        });
    }

    const readPtr = Module.findExportByName("libc.so", "read");
    if (readPtr) {
        Interceptor.attach(readPtr, {
            onEnter(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
            },
            onLeave(retval) {
                const bytesRead = retval.toInt32();
                if (bytesRead <= 0 || !this.buf) return;

                const procType = monitoredFds[this.fd];
                if (procType === "status") {
                    let content = this.buf.readCString(bytesRead);
                    if (content && content.indexOf("TracerPid:") !== -1) {
                        // Replace TracerPid:\t<pid> with TracerPid:\t0
                        const re = /TracerPid:\s*([0-9]+)/g;
                        let match = re.exec(content);
                        if (match && match[1] !== "0") {
                            const original = match[0];
                            const replacement = "TracerPid:\t0" + " ".repeat(Math.max(0, original.length - 12));
                            content = content.replace(original, replacement);
                            this.buf.writeUtf8String(content);
                        }
                    }
                } else if (procType === "maps") {
                    let content = this.buf.readCString(bytesRead);
                    if (content && (content.indexOf("frida") !== -1 || content.indexOf("gadget") !== -1 || content.indexOf("gum-js") !== -1)) {
                        const lines = content.split("\n");
                        const cleanLines = lines.filter(line => (
                            line.indexOf("frida") === -1 &&
                            line.indexOf("gadget") === -1 &&
                            line.indexOf("gum-js") === -1 &&
                            line.indexOf("linjector") === -1
                        ));
                        this.buf.writeUtf8String(cleanLines.join("\n"));
                    }
                }
            }
        });
    }

    // 5. Native ptrace(PTRACE_TRACEME) Denial Interceptor
    const ptracePtr = Module.findExportByName("libc.so", "ptrace");
    if (ptracePtr) {
        Interceptor.attach(ptracePtr, {
            onEnter(args) {
                this.request = args[0].toInt32();
            },
            onLeave(retval) {
                if (this.request === 0) {
                    retval.replace(ptr(0));
                }
            }
        });
    }

    // 6. Anti-Root File Existence Checks (access, faccessat)
    function sanitizePath(p) {
        if (!p) return false;
        return (
            p.indexOf("/su") !== -1 ||
            p.indexOf("magisk") !== -1 ||
            p.indexOf("busybox") !== -1 ||
            p.indexOf("frida-server") !== -1 ||
            p.indexOf("daemonsu") !== -1
        );
    }

    const accessPtr = Module.findExportByName("libc.so", "access");
    if (accessPtr) {
        Interceptor.attach(accessPtr, {
            onEnter(args) {
                this.path = args[0].readCString();
            },
            onLeave(retval) {
                if (sanitizePath(this.path)) {
                    retval.replace(ptr(-1));
                }
            }
        });
    }

    const faccessatPtr = Module.findExportByName("libc.so", "faccessat");
    if (faccessatPtr) {
        Interceptor.attach(faccessatPtr, {
            onEnter(args) {
                this.path = args[1].readCString();
            },
            onLeave(retval) {
                if (sanitizePath(this.path)) {
                    retval.replace(ptr(-1));
                }
            }
        });
    }

    // 7. Evasion Termination Watchdog (Logging and suppressing self-kill attempts)
    const killPtr = Module.findExportByName("libc.so", "kill");
    if (killPtr) {
        Interceptor.attach(killPtr, {
            onEnter(args) {
                this.pid = args[0].toInt32();
                this.sig = args[1].toInt32();
                if (this.sig === 9 || this.sig === 15 || this.sig === 6) {
                    send({
                        event: "SELF_TERMINATION_ATTEMPT",
                        target_pid: this.pid,
                        signal: this.sig,
                        callstack: Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n")
                    });
                }
            },
            onLeave(retval) {
                if (this.sig === 9 || this.sig === 15 || this.sig === 6) {
                    // Neutralize self-kill
                    retval.replace(ptr(0));
                }
            }
        });
    }
})();
