---
name: dbug-step-rationale
description: Guidelines and structured entry format for recording engineering steps and analysis decisions in docs/steps.md. Ensures every tool choice, anti-evasion workaround, canary format decision, and timeout parameter has a clear rationale, evidence citation, and falsifiable revisit condition for subsequent analysts and automated agents. Use whenever logging steps, writing handoffs, or modifying existing analysis configurations.
---

# dbug-step-rationale

All engineering choices and analysis actions in `dbug` are logged in `docs/steps.md`. This file serves as the chronological ledger for teammates and AI agents who have none of the current session's memory.

---

## 1. When to Write an Entry
| Scenario | Write an Entry? |
|---|---|
| Chose between two or more tools (e.g., eBPF vs. Frida; tshark vs. custom parser) | **Yes** |
| Configured an anti-evasion workaround (e.g., spoofing specific property, port shift) | **Yes** |
| Rejected or downgraded a third-party claim about malware behavior | **Yes** (with check that failed) |
| Chosen arbitrary constants / placeholders (timeout duration, port number, canary format) | **Yes** (with revisit condition) |
| Routine commands with no alternative (e.g., `git status`, directory listing) | **No** (belongs in commit or session log) |

---

## 2. Structured Entry Format

```markdown
- **Step:** <action, command, or script modification, exact enough to reproduce>
  **Decision:** <what was chosen>; rejected: <alternative approaches considered, or "none">
  **Rationale:** <the evasion constraint, crash, or operational requirement that forced this choice>
  **Evidence:** <evidence tag + citation: [C] decompiled class->method, [E] eBPF uprobe log, [M] Frida hook, [N] PCAP packet #>
  **Revisit if:** <the specific observation or device condition that would invalidate this choice>
```

### Example Entries:

```markdown
- **Step:** Run Frida server on TCP port 38921 instead of default 27042.
  **Decision:** Custom randomized port 38921; rejected: default 27042.
  **Rationale:** Malware contains native check querying `/proc/net/tcp` for hex port `69A2` (27042) and self-terminates if found.
  **Evidence:** [C] `libcheck.so` string table offset 0x4810 `27042`.
  **Revisit if:** Target sample does not inspect procfs or local TCP sockets.

- **Step:** Deployed static eCapture ARM64 binary to `/data/local/tmp/ecapture` for Conscrypt libssl.so uprobe.
  **Decision:** Kernel eBPF TLS interception; rejected: installing user CA certificate in Android trust store.
  **Rationale:** Infostealer implements OkHttp CertificatePinner in Java and aborts TLS handshake if CA is not recognized.
  **Evidence:** [C] `com.malware.network.ApiClient$Pinner`.
  **Revisit if:** Target uses custom statically-linked OpenSSL/BoringSSL inside its own native .so rather than system Conscrypt.
```

---

## 3. Rules of Evidence
- **Rationale must cite an external constraint:** "To intercept traffic" is a goal, not a rationale. "Sample inspects TracerPid in `/proc/self/status`" is a rationale.
- **Always include "Revisit if":** This turns assumptions into falsifiable hypotheses.
- **Append-only:** Never delete or overwrite prior entries in `docs/steps.md`. When a decision changes, add a new entry referencing the superseded step.
- **Zero secrets or raw payloads:** Never paste raw malware decryption keys, real analyst paths, or active threat actor credentials into the steps ledger.
