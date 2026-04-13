# 🛡️ Log Anamoly Detector: Log-Based Threat Detection System

> **A SOC Analyst Toolkit for detecting brute-force attacks and suspicious authentication patterns in Linux auth logs.**

---

## 📋 Project Overview

Security Operations Center (SOC) analysts routinely monitor authentication logs to identify malicious activity targeting SSH services. Manual review of high-volume log files is impractical — this tool automates the triage process.

The **Log-Based Threat Detection System** parses Linux `auth.log` (or equivalent syslog-format files), aggregates per-IP behaviour, and applies rule-based detection logic to surface actionable alerts — colour-coded by severity and exportable to CSV/TXT for further investigation or ticketing.

Designed to reflect real-world SOC tooling workflows, the project demonstrates:
- Log ingestion and structured parsing with regex
- Threat intelligence aggregation (per-IP behavioural profiling)
- Rule-based alerting with severity classification
- Clean CLI-driven interface suitable for integration into SOC playbooks

---

## ✨ Features

| Feature | Description |
|---|---|
| **Log Parsing** | Regex-based extraction of IP, username, timestamp, and event type from SSH auth logs |
| **Brute-Force Detection** | Flags IPs exceeding a configurable failed-attempt threshold |
| **Credential Spraying Detection** | Detects IPs attempting many distinct usernames (automated spraying) |
| **Suspicious Login Detection** | Alerts when a successful login follows multiple failures from the same IP |
| **Low-Volume Probe Detection** | Identifies reconnaissance activity below the brute-force threshold |
| **Per-IP Profiling** | Tracks attempt counts, unique usernames, time windows, and login outcomes per IP |
| **Severity Classification** | CRITICAL / HIGH / MEDIUM / LOW — colour-coded for fast triage |
| **CSV Export** | Machine-readable IP report for SIEM ingestion or analyst handoff |
| **TXT Export** | Plain-text report for email/archiving |
| **Configurable Thresholds** | CLI flags to tune detection sensitivity without code changes |
| **Coloured Terminal Output** | ANSI colour coding following SOC traffic-light conventions |

---

## 🔍 How It Works

```
auth.log
   │
   ▼
┌─────────────┐     regex patterns      ┌──────────────────┐
│  parser.py  │ ──────────────────────► │  LogEntry list   │
└─────────────┘                         └──────────────────┘
                                                 │
                                                 ▼
                                        ┌────────────────────┐
                                        │   detector.py      │
                                        │                    │
                                        │  1. Build IP       │
                                        │     profiles       │
                                        │  2. Apply rules    │
                                        │  3. Raise alerts   │
                                        └────────────────────┘
                                                 │
                                    ┌────────────┴────────────┐
                                    ▼                         ▼
                           ┌──────────────┐         ┌──────────────────┐
                           │  Terminal    │         │  report.py       │
                           │  Output      │         │  CSV + TXT files │
                           └──────────────┘         └──────────────────┘
```

### Detection Rules

| Rule | Trigger | Severity |
|---|---|---|
| `BRUTE_FORCE` | ≥ threshold failed attempts from one IP | HIGH / CRITICAL |
| `CREDENTIAL_SPRAY` | ≥ spray-threshold unique usernames + ≥ threshold failures | CRITICAL |
| `SUSPICIOUS_LOGIN` | Successful login after ≥ 1 prior failure from same IP | MEDIUM |
| `PROBE` | 1 < failures < threshold (low-noise recon) | LOW |

---

## 📁 Project Structure

```
threat-detection/
│
├── detect.py       # CLI entry point — orchestrates the full pipeline
├── parser.py       # Log file reader and regex-based event parser
├── detector.py     # Threat detection engine (profiling + rule evaluation)
├── report.py       # Terminal output and file report generation
│
├── sample.log      # Synthetic auth.log with brute-force and spray scenarios
└── README.md       # This file
```

---

## 🚀 How to Run

### Requirements

- Python 3.10+ (no external dependencies — stdlib only)

### Basic Usage

```bash
python detect.py --file sample.log
```

### All Options

```bash
python detect.py --file <LOG_PATH> [OPTIONS]

Required:
  --file, -f PATH         Path to the auth.log file to analyse

Detection Tuning:
  --threshold, -t N       Failed attempts to trigger BRUTE_FORCE (default: 5)
  --spray-threshold, -s N Unique usernames to trigger CREDENTIAL_SPRAY (default: 4)

Output:
  --output, -o BASENAME   Write BASENAME.csv and BASENAME.txt reports
  --no-color              Disable ANSI colour codes (for piping/logging)
  --quiet, -q             Suppress terminal output; only write files
```

### Examples

```bash
# Analyse sample log with defaults
python detect.py --file sample.log

# Stricter threshold (10 failures required for brute-force alert)
python detect.py --file /var/log/auth.log --threshold 10

# Save reports to disk
python detect.py --file sample.log --output /tmp/soc_report

# CI/logging-friendly (no colour, only files)
python detect.py --file sample.log --output report --no-color --quiet
```

---

## 📊 Sample Output

```
  Initialising SOC Threat Detection Engine…
  Log      : sample.log
  Threshold: 5 failed attempts (brute-force)

  ✔  Parsed 73 log lines → 73 SSH events extracted  (0.001s)
  ✔  Analysed 14 unique IPs → 10 alerts raised  (0.000s)

╔══════════════════════════════════════════════════════════════════════╗
║               LOG-BASED THREAT DETECTION SYSTEM                     ║
║   Security Operations Center — Authentication Log Analyser          ║
╠══════════════════════════════════════════════════════════════════════╣
║  Log File : /path/to/sample.log                                     ║
║  Run Time : 2026-04-13 08:00:00                                     ║
╚══════════════════════════════════════════════════════════════════════╝

  ▶  THREAT ALERTS
  ────────────────────────────────────────────────────────────────────

  🔴 [CRITICAL] BRUTE_FORCE  ─  IP: 185.220.101.15
     15 failed login attempts detected (threshold: 5). Target accounts: pi.
     ├─ Failures : 15   Successes : 0
     ├─ Usernames tried : pi
     └─ Window : Apr 13 08:20:00  →  Apr 13 08:20:28

  🔴 [CRITICAL] CREDENTIAL_SPRAY  ─  IP: 45.33.32.156
     Tried 8 different usernames — indicative of automated credential spraying.
     ├─ Failures : 8   Successes : 0
     ├─ Usernames tried : admin, daemon, ftp, mysql, nobody, oracle, postgres, root
     └─ Window : Apr 13 09:00:01  →  Apr 13 09:00:15

  ▶  ANALYSIS SUMMARY
  ────────────────────────────────────────────────────────────────────

    Total IPs Observed          14
    Total Failed Attempts       65
    Total Successful Logins     8
    Alerts Raised               10
    Suspicious IPs              6
    Flagged IPs                 185.220.101.15, 192.168.1.105, ...
```

### CSV Report Preview

| IP Address | Failed Attempts | Success Attempts | Unique Usernames | Status | Alert Type | Severity |
|---|---|---|---|---|---|---|
| 185.220.101.15 | 15 | 0 | 1 | Suspicious | BRUTE_FORCE | CRITICAL |
| 45.33.32.156 | 8 | 0 | 8 | Suspicious | CREDENTIAL_SPRAY | CRITICAL |
| 192.168.1.105 | 11 | 1 | 2 | Suspicious | BRUTE_FORCE | HIGH |
| 10.0.0.5 | 0 | 1 | 1 | Normal | N/A | N/A |

---

## 🖼️ Screenshots

> *Screenshots coming soon — run the tool with `python detect.py --file sample.log` to see live terminal output.*

<!-- Add terminal screenshots here -->

---

## 🧩 Extending the Tool

The modular design makes it straightforward to add new capabilities:

- **New detection rules** → add a method to `ThreatDetector._evaluate_profiles()` in `detector.py`
- **New log formats** → add a regex pattern and handler in `parser.py`
- **New output formats** → add a method to `ReportGenerator` in `report.py` (e.g., `write_json()`, `write_html()`)
- **GeoIP enrichment** → enrich `IPProfile` with geolocation data in `detector.py`

---

## 🔐 SOC Use Cases

- **Tier 1 alert triage** — quick overnight scan of auth logs before handoff
- **Incident response** — first-pass evidence gathering for SSH-based intrusions
- **Threat hunting** — identify low-noise probes that evade threshold-based SIEM rules
- **Compliance reporting** — generate audit-ready CSV of all authentication anomalies

---

## ⚖️ Disclaimer

This tool is intended for use on systems and log files you are authorised to analyse. Always follow your organisation's security policies and applicable laws when conducting log analysis.

---

## 📄 Licence

MIT — free to use, modify, and distribute with attribution.
