# dbug Fork v1 - Robustness & Component Integration Plan

**Base repository (fork target):** https://github.com/THAI-passport/dbug (this repo), branch cline/vw3w3wp1.
**Operational profile scope:** all four profiles - malware, privacy, appsec, all - across Gates G0-G5.
**Timestamp:** 2026-10-16 (Asia/Saigon +07:00).
**Evidence tags:** [C] code/static, [D] dynamic, [M] memory/hook, [N] network, [E] eBPF. No emoji anywhere in this document.

---

## 1. Fork Decision: Which Repo to Fork

Question: Is there an existing open-source repository that already does the full dbug pipeline (G0 static triage -> G1 device cloaking -> G2 canary seeding -> G3 eBPF/AP-gateway capture -> G4 Frida instrumentation -> G5 multi-profile reporting) better than dbug, and is it free to fork?

Answer: No.

| Candidate | GitHub | Strength | Why it cannot replace dbug as the fork base |
| :--- | :--- | :--- | :--- |
| MobSF | Mobile-Security-Framework-MobSF | Mature static + dynamic analysis, malware detection, API scanning, extensive reporting. | Not stealth-focused; standard proxy/instrumentation that malware and RASP detect. No canary seeding, no eBPF TLS, no transparent AP gateway, no STIX/YARA/privacy-appsec reporting. |
| Objection | sensepost/objection | Frida-based runtime exploration, SSL unpinning, root-hide helpers. | Interactive exploration tool, not an automated G0-G5 pipeline. No canary correlation, no gateway/eBPF capture, no executive reporting. |
| gojue/eCapture | gojue/eCapture | Canonical eBPF uprobe TLS/plaintext capture on Conscrypt libssl.so. | Single-component (G3 TLS capture only). No static triage, cloaking, canaries, orchestration, or reporting. |
| dongdevcom/HideDevMode | dongdevcom/HideDevMode | LSPosed module spoofing Settings.Global (adb_enabled=0, development_settings_enabled=0) at system_server Binder level. | Single-component (G1 developer-option hiding only). |
| dbug (this repo) | THAI-passport/dbug | Only cohesive G0-G5 zero-trace stealth pipeline: canary seeding + transparent ap0 gateway + eBPF TLS + multi-profile (malware/privacy/appsec) reporting with evidence-tagged documentation. | G1 currently relies on a one-shot settings put global shell script rather than a persistent system_server-level LSPosed module. |

Decision: fork dbug itself (THAI-passport/dbug) as the v1 base. It is the only free-to-fork repository that already implements the complete integrated stealth pipeline. Improve it by integrating, not reimplementing, two superior upstream components:

1. Gate G1 - Developer-option hiding: fork/integrate dongdevcom/HideDevMode as the LSPosed module on the physical test device; dbug verifies its installed+active state in verify_stealth_state.py instead of maintaining a shell-only settings put global approach. resetprop (apply_stealth_props.sh) remains the kernel/property layer; HideDevMode covers the system_server SettingsProvider layer, surviving app-process restarts and cached Binder proxies.
2. Gate G3 - eBPF TLS capture: track gojue/eCapture upstream; pin the on-device static ARM64 binary by version + SHA-256 in config/lab_config.yaml rather than maintaining a custom eBPF implementation.

No other repository is forked as the base because none covers canary seeding, transparent AP gateway capture, Frida telemetry on a stealth port, and combined malware/privacy/appsec reporting.

---

## 2. Gate-by-Gate Integration Plan (fork-v1)

| Gate | Phase | Base Component | Upstream Integration | Robustness Work |
| :--- | :--- | :--- | :--- | :--- |
| G0 | Static Intake & Triage | sample_triage/triage_apk.py, native_emulator.py | MobSF packer/RASP signature patterns referenced (signature catalog only, no code fork) | Expand anti-analysis cue catalog; CI test coverage |
| G1 | Device Cloaking & Pre-Flight | device_cloaking/apply_stealth_props.sh + verify_stealth_state.py | HideDevMode (dongdevcom/HideDevMode) LSPosed module for Settings.Global spoofing | New Layer 6 audit: HideDevMode package presence + enabled state; halts G1 when hide_dev_mode_required: true |
| G2 | Canary Data Seeding | config/seed_canaries.py, mock_canaries.json | None (canary design is dbug-native) | Idempotent seeding, dry-run CI |
| G3 | Zero-Footprint Capture | network_capture/gateway_setup.sh, ecapture_runner.py | gojue/eCapture upstream binary pinned by version + SHA-256 | Graceful shutdown retained; offline CI validates script syntax |
| G4 | Dynamic Instrumentation | instrumentation/frida_loader.py + agent JS hooks | Objection patterns referenced for socket/API tracing (no code fork) | Non-default port 38921 + renamed hl_daemon retained; dry-run CI |
| G5 | Correlation & Reporting | parser_correlator/*.py (STIX 2.1, YARA, OpenAPI 3.0, privacy, appsec) | None (dbug-native) | Profile-tailored reports retained; CI validates all parsers |

---

## 3. Task Checklist (fork-v1 implementation)

- [x] T-01 Author fork-v1.md: fork decision matrix, gate integration plan, task checklist.
- [x] T-02 Gate G1 hardening: Layer 6 LSPosed HideDevMode module audit in device_cloaking/verify_stealth_state.py (package presence, enabled/disabled state, dry-run simulation, configurable package, non-fatal unless hide_dev_mode_required: true).
- [x] T-03 Extend config/lab_config.yaml: lsposed block (hide_dev_mode_package, hide_dev_mode_required, lsposed_manager_package) and stealth_properties block (target property values).
- [x] T-04 Document HideDevMode as the system_server-level spoof companion in device_cloaking/apply_stealth_props.sh; add device_cloaking/HIDEDEVMODE_INTEGRATION.md install/runbook.
- [x] T-05 Fix orchestrator.py syntax error (nested quotes in f-string at line 344) breaking all orchestrator execution; add G1 HideDevMode requirement hint.
- [~] T-06 Offline GitHub Actions CI (.github/workflows/ci.yml) prepared locally: py_compile all Python scripts, bash -n all shell scripts, run tests/test_framework_e2e.py dry-run suite - no device, no network, no secrets. Push to origin DEFERRED: the GitHub App token lacks `workflows` permission to create `.github/workflows/ci.yml` (remote rejected). A repository maintainer with `workflows` permission can add the prepared workflow file from branch cline/vw3w3wp1. Locally verified equivalent: py_compile OK, bash -n OK, 17/17 e2e tests OK.
- [x] T-07 Add test_17 HideDevMode pre-flight layer to tests/test_framework_e2e.py (dry-run).
- [x] T-08 Chronological step log entry in docs/steps.md (Asia/Saigon); tooling log in LOG.md; fixes ledger rows in FIXES.md.
- [x] T-09 Commit all changes to branch cline/vw3w3wp1 and push to origin (commit 9990a04).
- [x] T-10 Post-push verification: pushed branch state verified - 17/17 e2e tests OK, py_compile OK, bash -n OK, working tree clean.

---

## 4. What Is NOT Forked (and Why)

MobSF: static-analysis reference only; its proxy-based dynamic analysis trips anti-analysis checks - excluded by the stealth hierarchy mandate (out-of-band first, in-process last).

Objection: interactive exploration reference only; not an automated pipeline and produces no STIX/YARA/privacy/appsec artifacts.

HideDevMode / eCapture: integrated as on-device components, not forked into this repo. dbug never ships prebuilt binaries or APKs (AGENTS.md ground rule: never commit raw binaries). The device operator installs them from upstream releases.

---

## 5. Acceptance Criteria (verified offline, dry-run)

1. python3 -m unittest tests/test_framework_e2e.py -> 17 tests, 0 failures.
2. python3 -m py_compile passes for every modified/new .py file.
3. bash -n passes for device_cloaking/apply_stealth_props.sh and network_capture/gateway_setup.sh.
4. orchestrator.py --dry-run --profile all --duration 1 exits 0 and emits all G0-G5 stage summaries.
5. verify_stealth_state.py --dry-run prints Layer 6 HideDevMode audit and exits 0.
6. All changes committed and pushed to origin cline/vw3w3wp1.
