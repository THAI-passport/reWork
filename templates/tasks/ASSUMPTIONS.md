# Assumptions: {{name}}

Use these instead of asking. Each is reversible and has a test that would prove it wrong. Add rows to the log for anything not covered.

## Pre-made defaults
| Id | Assumption | Basis | How it is proven wrong | Effect if wrong |
|---|---|---|---|---|
| A1 | The device under test is the model named in TARGET.md; if several, start with the first listed | Brief | Advertised name / box / app shows another | Re-run discovery for that model |
| A2 | Transport follows service discovery, not the device name | Method | Discovery shows another stack | Switch transport flag; update PROTOCOL.md |
| A3 | No second radio (for example Wi-Fi) unless a regulatory filing or scan shows one | Filing/scan | An SSID or port appears | Add the transport task |
| A4 | Picture/data sizes are what the device reports, else the app's constant | FACTS.md | Report differs from behaviour | Follow the device; update FACTS.md |
| A5 | Vendor server contact is out of scope | Rules | Owner approves | Record approval |
| A6 | The simulator proves consistency only | Written from our reading of the spec | A hardware result disagrees | Fix simulator and spec together, retag |
| A7 | The pinned artifact version in SOURCES.md is the one analysed | SOURCES.md | Hash mismatch on rebuild | Do not accept a new hash without telling the owner |
| A8 | Flash/storage has finite endurance and unknown wear levelling | Typical hardware | Free-space and rewrite tests | Adjust guard defaults only with approval |

## Log (append; newest last)
| Id | Date | By | Assumption | Why | How to falsify | Impact |
|---|---|---|---|---|---|---|
