---
name: dbug-c2-protocol
description: Reverse engineering, specification, and framing reconstruction of malware Command & Control (C2) protocols (Gate G3/G5). Decodes custom binary framing, WebSocket handshakes, Protobuf payloads, JSON-RPC schemas, and Telegram/Discord Bot APIs used for bot registration, heartbeats, tasking, and exfiltration. Use when documenting C2 protocol mechanics or authoring network signatures.
---

# dbug-c2-protocol

Decode, structure, and document the malware's Command & Control (C2) protocol into a byte-exact, reproducible specification.

---

## 1. Common Android C2 Protocol Architectures

| Architecture | Signature / Transport | Decoding Method |
|---|---|---|
| **JSON over TLS / HTTP POST** | Base64-encoded or AES-encrypted JSON bodies | Intercept via Conscrypt eBPF uprobe or Frida `Cipher.doFinal` |
| **WebSocket Continuous Tunnel** | `ws://` / `wss://` headers; persistent TCP channel | Extract upgrade request; parse frame opcodes (`0x1` text, `0x2` binary) |
| **Telegram Bot API** | `api.telegram.org/bot<token>/sendMessage` | Grep for bot token in memory/network; parse `chat_id` and payload |
| **Raw TCP Binary Framing** | Magic header bytes + length prefix + encrypted body | Read length endianness and opcodes via `socket_tracer.js` and `tcpdump` |
| **Protobuf Payloads** | Payloads starting with wire-type tags (`0x08`, `0x12`) | Decompile with `protoc --decode_raw` or inspect Java generated classes |

---

## 2. Framing & Command Recovery Protocol

### A. Frame Structure Documentation (`C2_PROTOCOL.md`)
Record the wire format in a standard layout:
```markdown
| Field | Offset | Length | Type | Description |
|---|---|---|---|---|
| Magic Header | 0 | 4 bytes | ASCII | `\xAA\xBB\xCC\xDD` or custom string |
| Packet Length | 4 | 4 bytes | uint32 (Big-Endian) | Total payload size in bytes |
| Command Opcode | 8 | 2 bytes | uint16 | 0x0001 (Register), 0x0002 (Tasking), 0x0003 (Exfil) |
| Payload | 10 | N bytes | Encrypted Blob | AES-128-CBC encrypted JSON |
| Checksum | 10+N | 4 bytes | CRC32 / MD5 | Integrity check |
```

### B. Command Dispatch Inventory
Map incoming tasking commands to their internal handler methods in Java/native code:
```markdown
| Opcode / Action | Meaning | Malware Handler Method | Expected Arguments | Evidence Tag |
|---|---|---|---|---|
| `send_sms` | Send SMS from victim device | `SmsManagerModule.dispatch()` | Phone number, body | `[C]` |
| `dump_contacts` | Harvest phonebook | `ContactsProvider.readAll()` | None | `[C]` |
| `start_stream` | Live screen streaming / VNC | `ScreenCastService.start()` | Port, framerate | `[D]` |
| `push_overlay` | Display banking phishing dialog | `OverlayManager.render()` | Target package, HTML | `[C]` |
```

---

## 3. Parsing Encrypted WebSockets & HTTP
When TLS is stripped via eBPF or eCapture:
1. Extract HTTP headers (Host, User-Agent, X-Bot-ID, X-Signature).
2. Note custom headers used for authentication or anti-analysis (e.g., passing device build fingerprints).
3. If payloads are doubly encrypted at the application layer, cross-reference with the keys dumped by `crypto_dumper.js`.
