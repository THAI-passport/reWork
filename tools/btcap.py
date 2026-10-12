#!/usr/bin/env python3
"""List ATT traffic from a Bluetooth capture, grouped by characteristic UUID (stdlib only).

    python tools/btcap.py capture.btsnoop|.pcap|.pcapng [--hex-limit 48] [--json out.json]

Reads btsnoop (datalinks 1001/1002), pcap and pcapng (linktype 187 or 201), reassembles ACL fragments, maps value handles to UUIDs
from discovery responses seen in the capture, and prints writes (W), notifications (N), reads (R). It does not interpret payloads:
decode them with the protocol spec of the target. Handles whose discovery was not captured print as h=0x....
"""
import argparse
import json
import struct
import sys

BTSNOOP_MAGIC = b"btsnoop\x00"


def read_capture(path):
    """Return a list of (ts_seconds, direction, h4_bytes). direction: 'tx' host to controller, 'rx', or None."""
    data = open(path, "rb").read()
    if data[:8] == BTSNOOP_MAGIC:
        return _btsnoop(data)
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return _pcapng(data)
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return _pcap(data)
    raise ValueError("not a btsnoop, pcap or pcapng file")


def _btsnoop(d):
    _ver, link = struct.unpack(">II", d[8:16])
    if link not in (1001, 1002):
        raise ValueError("btsnoop datalink %d not supported (need 1001 or 1002)" % link)
    out, i = [], 16
    while i + 24 <= len(d):
        _orig, incl, flags, _drops, ts = struct.unpack(">IIIIQ", d[i:i + 24])
        pkt = d[i + 24:i + 24 + incl]
        i += 24 + incl
        direction = "rx" if flags & 1 else "tx"
        if link == 1001:
            if flags & 2:
                continue
            pkt = b"\x02" + pkt
        out.append(((ts - 0x00dcddb30f2f8000) / 1e6, direction, pkt))
    return out


def _wrap_h4(link, raw):
    if link == 187:
        return None, raw
    if link == 201:
        return ("tx" if struct.unpack(">I", raw[:4])[0] == 0 else "rx"), raw[4:]
    raise ValueError("pcap linktype %d not supported (need 187 or 201)" % link)


def _pcap(d):
    big = d[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")
    e = ">" if big else "<"
    nano = d[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    link = struct.unpack(e + "I", d[20:24])[0]
    out, i = [], 24
    while i + 16 <= len(d):
        sec, frac, incl, _orig = struct.unpack(e + "IIII", d[i:i + 16])
        raw = d[i + 16:i + 16 + incl]
        i += 16 + incl
        direction, h4 = _wrap_h4(link, raw)
        out.append((sec + frac / (1e9 if nano else 1e6), direction, h4))
    return out


def _pcapng(d):
    out, i, e, links = [], 0, "<", []
    while i + 12 <= len(d):
        if d[i:i + 4] == b"\x0a\x0d\x0d\x0a":
            e = "<" if d[i + 8:i + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            links = []
        btype, blen = struct.unpack(e + "II", d[i:i + 8])
        body = d[i + 8:i + blen - 4]
        if btype == 1:
            links.append(struct.unpack(e + "H", body[:2])[0])
        elif btype == 6:
            iface, hi, lo, cap, _orig = struct.unpack(e + "IIIII", body[:20])
            direction, h4 = _wrap_h4(links[iface], body[20:20 + cap])
            out.append((((hi << 32) | lo) / 1e6, direction, h4))
        if blen < 12:
            break
        i += blen
    return out


def att_events(packets):
    """Yield dicts {ts, dir, conn, opcode, pdu} for every complete L2CAP ATT PDU (CID 4), reassembling ACL fragments."""
    pend = {}
    for ts, direction, pkt in packets:
        if not pkt or pkt[0] != 0x02 or len(pkt) < 5:
            continue
        hf, ln = struct.unpack("<HH", pkt[1:5])
        conn, pb = hf & 0x0FFF, (hf >> 12) & 3
        chunk = pkt[5:5 + ln]
        key = (direction, conn)
        if pb in (0, 2):
            if len(chunk) < 4:
                continue
            l2len, cid = struct.unpack("<HH", chunk[:4])
            pend[key] = [cid, l2len, bytearray(chunk[4:])]
        elif pb == 1 and key in pend:
            pend[key][2] += chunk
        else:
            continue
        cid, l2len, buf = pend[key]
        if len(buf) >= l2len:
            del pend[key]
            if cid == 4 and l2len:
                yield {"ts": ts, "dir": direction, "conn": conn, "opcode": buf[0], "pdu": bytes(buf[:l2len])}


def uuid_text(raw):
    """2-byte or 16-byte little-endian UUID to text: 4 hex digits for Bluetooth base UUIDs."""
    if len(raw) == 2:
        return "%04x" % struct.unpack("<H", raw)[0]
    h = raw[::-1].hex()
    full = "%s-%s-%s-%s-%s" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:])
    if full.endswith("-0000-1000-8000-00805f9b34fb") and full.startswith("0000"):
        return full[4:8]
    return full


def handle_map(events):
    """value handle -> uuid text, from characteristic declarations and Find Information responses."""
    m = {}
    for ev in events:
        p = ev["pdu"]
        if ev["opcode"] == 0x09 and len(p) > 2 and p[1] in (7, 21):
            n = p[1]
            for k in range(2, len(p) - n + 1, n):
                item = p[k:k + n]
                m[struct.unpack("<H", item[3:5])[0]] = uuid_text(item[5:])
        elif ev["opcode"] == 0x05 and len(p) > 2:
            w = 4 if p[1] == 1 else 18
            for k in range(2, len(p) - w + 1, w):
                h = struct.unpack("<H", p[k:k + 2])[0]
                u = uuid_text(p[k + 2:k + w])
                if u not in ("2800", "2801", "2802", "2803", "2900", "2901", "2902", "2903", "2904"):
                    m.setdefault(h, u)
    return m


KIND = {0x52: "W", 0x12: "W", 0x1B: "N", 0x1D: "N", 0x0B: "R"}   # write cmd, write req, notification, indication, read response


def summarize(events, hexlimit=48):
    hm = handle_map(events)
    rows = []
    for ev in events:
        p, op = ev["pdu"], ev["opcode"]
        if op in (0x52, 0x12, 0x1B, 0x1D) and len(p) >= 3:
            h = struct.unpack("<H", p[1:3])[0]
            rows.append({"ts": ev["ts"], "kind": KIND[op], "dir": ev["dir"], "handle": h, "uuid": hm.get(h), "value": p[3:]})
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture")
    ap.add_argument("--hex-limit", type=int, default=48)
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    try:
        events = list(att_events(read_capture(a.capture)))
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    rows = summarize(events)
    t0 = rows[0]["ts"] if rows else 0
    for r in rows:
        v = r["value"]
        hx = v[:a.hex_limit].hex() + ("..." if len(v) > a.hex_limit else "")
        print("%8.3f %s %-4s %-36s len=%-4d %s" % (r["ts"] - t0, r["kind"], r["dir"] or "-", r["uuid"] or "h=0x%04x" % r["handle"], len(v), hx))
    print("%d ATT PDUs, %d data PDUs" % (len(events), len(rows)))
    if a.json:
        json.dump([dict(r, value=r["value"].hex()) for r in rows], open(a.json, "w"), indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
