# Ragnar — Comparative Grade

_Assessment date: 2026-05-31 · Based on direct review of the codebase, not marketing claims._

## Overview

Ragnar is best understood as a **hybrid portable security platform** — offensive
recon + vulnerability management + web app scanning + lightweight network
monitoring + threat intelligence + wardriving — packaged on a self-hardened
Raspberry Pi appliance. It is not a pure attack tool, nor a drop-in replacement
for any single enterprise platform.

This document grades Ragnar against established software/enterprise security
platforms plus the Kali-on-Pi drop box.

## Capability Comparison

Legend: `✅✅` strong · `✅` yes · `⚠️` partial · `❌` no

| Capability | Ragnar | Nmap | OpenVAS | Nessus | ZAP | Burp | Zeek | Wazuh | Kali-Pi |
|---|---|---|---|---|---|---|---|---|---|
| Portable HW appliance | ✅✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Autonomous unattended loop | ✅✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ | ✅ | ✅✅ | ⚠️ |
| Host discovery / network map | ✅✅ | ✅✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ⚠️ | ✅✅ |
| CVE vuln scanning | ✅ | ⚠️ | ✅✅ | ✅✅ | ⚠️ | ⚠️ | ❌ | ✅ | ✅ |
| Web app scanning (XSS/SQLi) | ✅ | ❌ | ⚠️ | ⚠️ | ✅✅ | ✅✅ | ❌ | ❌ | ✅ |
| Credential brute-force | ✅✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ✅ | ❌ | ❌ | ✅ |
| Traffic analysis / NSM | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅✅ | ✅ | ⚠️ |
| Host/log SIEM, FIM, rootkit | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ | ✅✅ | ❌ |
| External threat intel (MISP/VT/Shodan) | ✅ | ❌ | ❌ | ⚠️ | ❌ | ❌ | ⚠️ | ✅ | ❌ |
| Vulns-by-host tracking | ✅✅ | ❌ | ✅ | ✅✅ | ⚠️ | ⚠️ | ❌ | ✅ | ⚠️ |
| Wireless attacks / wardriving | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| RF / NFC / USB-HID | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ |
| Compliance reporting (PCI/CIS) | ✅ | ❌ | ✅ | ✅✅ | ⚠️ | ⚠️ | ❌ | ✅✅ | ❌ |
| FP accuracy / QA discipline | ⚠️ | ✅ | ✅ | ✅✅ | ✅ | ✅✅ | ✅ | ✅ | ✅ |
| Standalone display UX | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Data store / reporting | ✅ | ⚠️ | ✅ | ✅✅ | ✅ | ✅ | ✅ | ✅✅ | ⚠️ |
| Tool hardening (encrypted DB/auth) | ✅✅ | — | ✅ | ✅✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| Approx. cost | $60–120 | Free | Free | ~$4k/yr | Free | ~$450/yr | Free | Free | ~$60 |
| Community / ecosystem | ❌ solo | ✅✅ | ✅✅ | ✅✅ | ✅✅ | ✅✅ | ✅✅ | ✅✅ | ✅✅ |
| **Ragnar's grade vs it** | **8/10** | 7 | 6 | 6 | 7 | 6 | 4 | 3 | 7 |

## Per-Lane Grades

| Tool | Lane | What separates them | Grade |
|---|---|---|---|
| Nmap | Network discovery | Gold-standard scanner; Ragnar uses it under the hood + adds CVE mapping & autonomy | 7/10 |
| OpenVAS / Greenbone | Vuln scanning | Curated NVT feed, credentialed scans, FP QA | 6/10 |
| Nessus | Vuln scanning (commercial) | Huge QA'd plugin DB, low FP, compliance audits | 6/10 |
| OWASP ZAP | Web app scanning | Ragnar *is* ZAP + a custom context-aware fuzzer → automation parity-plus | 7/10 |
| Burp Suite | Web app pentest | Burp Pro's manual proxy/Repeater/Intruder + Collaborator OOB still ahead | 6/10 |
| Zeek | NSM (passive/defensive) | `traffic_analyzer` does C2/DNS-tunnel/port-scan detection — same categories, heuristic depth, 8GB-gated | 4/10 |
| Wazuh | SIEM/XDR/HIDS | `threat_intelligence` (MISP/VT/Shodan/OpenCTI) gives enrichment — but no agents, FIM, compliance, fleet scale | 3/10 |
| Kali-on-Pi (drop box) | Portable pentest | More raw power, but manual, headless, no autonomy/UX/hardening | 7/10 |

## Final Grade: 8 / 10

Ragnar's edge is **breadth + portability + self-hardening in a single box**: it
covers recon, CVE + web vuln scanning, credential attacks, lightweight NSM,
threat-intel enrichment, and wardriving — with an encrypted-at-rest DB and a real
auth layer that most hobby tools lack.

### What caps it at 8 (not 9–10)

1. **Breadth over depth** — every module trails its specialist (Zeek / Wazuh /
   Nessus / Burp) on depth, QA, and false-positive discipline.
2. **8GB-gating** — traffic analysis, advanced vuln scanning, and the heavy intel
   features do not run on the Pi Zero tier.
3. **Unverified claims** — e.g. the "predictive ML / threat attribution" in
   `threat_intelligence.py` is credited from docstrings, not confirmed behavior.
4. **Solo maintenance, no ecosystem** — the one weakness that appears in every
   lane versus the established platforms.

### Code-verified strengths

- `actions/nmap_vuln_scanner.py` — Nmap `-sV` + `vulners.nse` with CVSS→severity
  mapping and incremental per-MAC port scanning (efficient on constrained HW).
- `advanced_vuln_scanner.py` — full ZAP orchestration (spider, AJAX spider,
  active scan, custom policies, 7 auth types, OpenAPI import, crash recovery) plus
  a custom `ragnar-fuzz` engine with a 19-category payload library and
  context-aware reflection triage. Also wires Nuclei, Nikto, SQLMap, WhatWeb.
- `traffic_analyzer.py` — tcpdump capture, C2 beacon detection, DNS tunneling and
  port-scan detection (server-mode / 8GB+).
- `threat_intelligence.py` — multi-source TI fusion (MISP, OpenCTI, VirusTotal,
  Shodan), risk scoring, IOC management.
- `network_intelligence.py` — network-aware, active/resolved vuln + credential
  tracking (vulns-by-host backbone).

### Known issue found during review

- The custom fuzzer's SSTI verification searches the response for the literal
  payload (`{{7*7}}`) instead of the evaluated result (`49`), so SSTI detection is
  effectively inverted. See `_verify_fuzz_reflections` in `advanced_vuln_scanner.py`.
