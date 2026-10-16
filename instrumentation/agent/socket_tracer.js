/**
 * socket_tracer.js: Low-level native socket and DNS resolution tracer for dbug.
 * Intercepts libc connect(), send(), sendto() and Java InetAddress/URL to catch
 * direct TCP/UDP C2 beacons and DGA lookups.
 */

// -----------------------------------------------------------------------------
// 1. Native libc Socket Interceptor
// -----------------------------------------------------------------------------
(() => {
    function parseSockAddr(sockaddr) {
        if (!sockaddr) return null;
        try {
            const family = sockaddr.readU16();
            if (family === 2) { // AF_INET (IPv4)
                const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                const ip = [
                    sockaddr.add(4).readU8(),
                    sockaddr.add(5).readU8(),
                    sockaddr.add(6).readU8(),
                    sockaddr.add(7).readU8()
                ].join('.');
                return { family: "AF_INET", ip: ip, port: port };
            } else if (family === 10) { // AF_INET6 (IPv6)
                const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                let parts = [];
                for (let i = 0; i < 16; i += 2) {
                    parts.push(((sockaddr.add(8 + i).readU8() << 8) | sockaddr.add(9 + i).readU8()).toString(16));
                }
                return { family: "AF_INET6", ip: parts.join(':'), port: port };
            }
        } catch (e) {}
        return null;
    }

    function bufferToSnippet(bufPtr, len) {
        if (!bufPtr || len <= 0) return { hex: null, utf8: null };
        try {
            const maxLen = Math.min(len, 1024);
            const bytes = bufPtr.readByteArray(maxLen);
            const u8 = new Uint8Array(bytes);
            let hex = [];
            let str = "";
            for (let i = 0; i < u8.length; i++) {
                let b = u8[i];
                hex.push((b < 16 ? "0" : "") + b.toString(16));
                str += (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".";
            }
            return { hex: hex.join(""), text: str, total_len: len };
        } catch (e) {
            return { hex: null, text: null, total_len: len };
        }
    }

    const connectPtr = Module.findExportByName("libc.so", "connect");
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter(args) {
                const addr = parseSockAddr(args[1]);
                if (addr) {
                    send({
                        event: "SOCKET_CONNECT",
                        family: addr.family,
                        destination_ip: addr.ip,
                        destination_port: addr.port
                    });
                }
            }
        });
    }

    const sendPtr = Module.findExportByName("libc.so", "send");
    if (sendPtr) {
        Interceptor.attach(sendPtr, {
            onEnter(args) {
                const len = args[2].toInt32();
                if (len > 0) {
                    const snippet = bufferToSnippet(args[1], len);
                    send({
                        event: "SOCKET_SEND",
                        length: len,
                        payload_hex: snippet.hex,
                        payload_ascii: snippet.text
                    });
                }
            }
        });
    }

    const sendtoPtr = Module.findExportByName("libc.so", "sendto");
    if (sendtoPtr) {
        Interceptor.attach(sendtoPtr, {
            onEnter(args) {
                const len = args[2].toInt32();
                const addr = parseSockAddr(args[4]);
                if (len > 0) {
                    const snippet = bufferToSnippet(args[1], len);
                    send({
                        event: "SOCKET_SENDTO",
                        length: len,
                        destination_ip: addr ? addr.ip : null,
                        destination_port: addr ? addr.port : null,
                        payload_hex: snippet.hex,
                        payload_ascii: snippet.text
                    });
                }
            }
        });
    }
})();

// -----------------------------------------------------------------------------
// 2. Java Framework DNS & URL Tracer
// -----------------------------------------------------------------------------
Java.perform(() => {
    try {
        const InetAddress = Java.use("java.net.InetAddress");
        InetAddress.getByName.overload('java.lang.String').implementation = function(host) {
            send({
                event: "DNS_LOOKUP",
                hostname: host
            });
            return this.getByName(host);
        };
    } catch (e) {}

    try {
        const URL = Java.use("java.net.URL");
        URL.$init.overload('java.lang.String').implementation = function(spec) {
            send({
                event: "HTTP_URL_INIT",
                url: spec
            });
            return this.$init(spec);
        };
    } catch (e) {}
});
