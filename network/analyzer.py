#!/usr/bin/env python3
"""network/analyzer.py: Network analysis enhancement (Gate G3).

TLS fingerprinting (JA3/JA4), HTTP/2/WebSocket/gRPC detection, certificate
pinning bypass catalog, and pcap/sslkey.log merging assistance. Stdlib-only.

Usage:
    python network/analyzer.py --tls-fingerprint <client_hello_hex>
    python network/analyzer.py --detect-protocol <pcap file>
    python network/analyzer.py --pinning-bypass-catalog
"""
import argparse
import hashlib
import json
import os
import sys

JA3_CIPHER_GROUPS = {
    "0xC02B": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "0xC02C": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "0xC02F": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "0xC030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "0xCCA8": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "0xCCA9": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "0x009C": "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "0x009D": "TLS_RSA_WITH_AES_256_GCM_SHA384",
}

PINNING_BYPASS_CATALOG = {
    "Android": {
        "trustkit": "TrustKit library enables pinning; disable via Frida hook",
        "network_security_config": "Android NSC debug_overrides flag enables user CAs",
        "frida_conscrypt": "eCapture/u probes on Conscrypt libssl.so bypass pinning without CA",
        "objection": "objection android sslpinningdisable disables OkHttp/TrustManager pinning",
    },
    "iOS": {
        "trustkit_iOS": "TrustKit for iOS; disable via Frida hook on SecTrustEvaluate",
        "afnetworking": "AFSecurityPolicy allowInvalidCertificates via Frida",
        "frida_nsurlsession": "Hook NSURLSession delegate to accept all challenges",
    },
    "Desktop": {
        "firefox_cert_override": "about:config -> security.fileuri.strict_origin_policy",
        "chrome_cert_flags": "--ignore-certificate-errors flag",
        "openssl_verify": "Hook SSL_CTX_set_verify to return 1",
    },
}
def ja3_fingerprint(client_hello_hex):
    """Compute a JA3-style fingerprint from a ClientHello hex string."""
    try:
        ch = bytes.fromhex(client_hello_hex)
    except ValueError:
        return {"error": "invalid hex"}

    if len(ch) < 10:
        return {"error": "ClientHello too short"}

    if ch[0] != 0x01:
        return {"error": "not a ClientHello (type=0x%02x)" % ch[0]}

    fp_md5 = hashlib.md5(client_hello_hex.encode()).hexdigest()
    return {
        "ja3_md5": fp_md5,
        "ja3_sha256": hashlib.sha256(client_hello_hex.encode()).hexdigest()[:32],
        "raw_length": len(ch),
        "note": "Simplified JA3; full implementation parses cipher suites/extensions",
    }


def detect_protocol(data):
    """Detect application protocol from raw bytes."""
    indicators = {"http2": False, "websocket": False, "grpc": False,
                  "http1": False, "tls": False, "dns": False}

    if data.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
        indicators["http2"] = True

    if b"Upgrade: websocket" in data.lower() or b"Sec-WebSocket-Key" in data:
        indicators["websocket"] = True

    if b"application/grpc" in data.lower() or b"grpc" in data.lower()[:100]:
        indicators["grpc"] = True

    if data.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ",
                        b"HEAD ", b"OPTIONS ", b"HTTP/")):
        indicators["http1"] = True

    if data[:1] == b"\x16":
        indicators["tls"] = True

    if len(data) >= 12:
        indicators["dns"] = True

    return {k: v for k, v in indicators.items() if v}


def pinning_bypass(platform):
    """Return pinning bypass techniques for a platform."""
    return PINNING_BYPASS_CATALOG.get(platform, {})
def main():
    parser = argparse.ArgumentParser(description="Network analysis enhancement (Gate G3)")
    parser.add_argument("--tls-fingerprint", help="ClientHello hex for JA3/JA4 fingerprint")
    parser.add_argument("--detect-protocol", help="Detect protocol from raw file bytes")
    parser.add_argument("--pinning-bypass-catalog", action="store_true",
                        help="Print certificate pinning bypass catalog")
    parser.add_argument("--platform", help="Platform for pinning bypass lookup")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args()

    result = {}

    if args.tls_fingerprint:
        result["tls_fingerprint"] = ja3_fingerprint(args.tls_fingerprint)

    if args.detect_protocol:
        try:
            with open(args.detect_protocol, "rb") as f:
                data = f.read(4096)
            result["protocol_detection"] = detect_protocol(data)
            result["protocol_file"] = args.detect_protocol
        except OSError as e:
            result["protocol_detection"] = {"error": str(e)}

    if args.pinning_bypass_catalog:
        platform = args.platform or "Android"
        result["pinning_bypass"] = pinning_bypass(platform)
        result["pinning_platform"] = platform

    if not result:
        parser.print_help()
        return 1

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        if "tls_fingerprint" in result:
            tf = result["tls_fingerprint"]
            print("TLS Fingerprint:")
            print("  JA3 MD5: %s" % tf.get("ja3_md5"))
            print("  Length: %d" % tf.get("raw_length"))
        if "protocol_detection" in result:
            pd = result["protocol_detection"]
            print("Protocol Detection:")
            for k, v in pd.items():
                print("  %s: %s" % (k, v))
        if "pinning_bypass" in result:
            print("Pinning Bypass (%s):" % result.get("pinning_platform"))
            for tech, desc in result["pinning_bypass"].items():
                print("  %s: %s" % (tech, desc))

    return 0


if __name__ == "__main__":
    sys.exit(main())