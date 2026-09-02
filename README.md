# 🛡️ Windows Endpoint Persistence Detection & Security Monitoring Platform (v2.0 PRO)

[![Live SOC Dashboard Demo](https://img.shields.io/badge/Live_Demo-GitHub_Pages-06b6d4?style=for-the-badge&logo=google-chrome&logoColor=white)](https://sabsec-h4x.github.io/Windows-Registry-Change-Monitoring-System/)
[![Platform](https://img.shields.io/badge/Platform-Windows_10%20%2F%2011%20%2F%20Server-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/sabsec-h4x/Windows-Registry-Change-Monitoring-System)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Persistence%20%26%20Evasion-red?style=for-the-badge&logo=target&logoColor=white)](https://attack.mitre.org/)
[![SIEM Ready](https://img.shields.io/badge/SIEM-Wazuh%20%7C%20Splunk%20%7C%20JSONL-blueviolet?style=for-the-badge&logo=wazuh&logoColor=white)](https://wazuh.com/)

> **🌐 Live Interactive Dashboard**: Experience the full Cyber SOC Dashboard live directly in your browser without installing anything:  
> 👉 **[Launch Live GitHub Pages Interactive Demo](https://sabsec-h4x.github.io/Windows-Registry-Change-Monitoring-System/)**

---

## 📌 Overview

An enterprise-grade, real-time Windows Endpoint Persistence Detection, Correlation, and Incident Response Platform. It transforms simple registry inspection into a high-fidelity endpoint sensor that captures persistence mechanisms with **zero latency** via native Windows APIs, attributes modifications to processes and users, extracts executable PE forensics, computes risk scores (0–100), maps detections to MITRE ATT&CK techniques, auto-generates forensic incident dossiers with 1-click `.reg` rollback patches, and provides an interactive Cyber SOC Web Dashboard with SIEM/Wazuh integration.

---

## ⚡ Key Architecture & Features

### 1. Zero-Latency Event Loop (`core/realtime_engine.py`)
- Replaces polling (`time.sleep(30)`) with multi-threaded Win32 `RegNotifyChangeKeyValue` event handles.
- OS kernel change notifications wake the sensor instantly with **0% idle CPU utilization**.
- Dual 32-bit (`KEY_WOW64_32KEY`) and 64-bit (`KEY_WOW64_64KEY`) architecture inspection with recursive subkey tracking.

### 2. Comprehensive MITRE ATT&CK Persistence & Evasion Matrix
- **T1547.001**: Registry Run Keys & Startup Folder (`HKCU\...\Run`, `HKLM\...\Run`, `RunOnce`, `StartupApproved`)
- **T1546.012**: Image File Execution Options (IFEO) Debugger Hijacking
- **T1547.004**: Winlogon Helper DLL, Userinit & Shell Alteration
- **T1546.010**: AppInit_DLLs Global Injection
- **T1547.002**: LSA Security & Authentication Packages
- **T1543.003**: Windows Service ImagePath Hijacking
- **T1546.015**: COM Object Hijacking (`HKCU\Software\Classes\CLSID\InprocServer32`)
- **T1562.001**: Defense Evasion — Windows Defender AV Policy Tampering
- **T1548.002**: Privilege Escalation — UAC Elevation Policy Bypasses (`EnableLUA`)
- **T1562.004**: Defense Evasion — Windows Firewall Policy Tampering
- **T1059.001**: Encoded PowerShell Execution (`-enc`, `IEX`, `DownloadString`)
- **T1218**: Living-off-the-Land Binaries (LOLBins: `mshta`, `rundll32`, `regsvr32`, `certutil`, `wscript`)
- **T1000.001**: Honey-Key Decoy Canary Trigger

### 3. Multi-Layer Risk Scoring Engine (`core/detection_engine.py`)
- Replaces flat keyword matching with configurable rules (`config/rules.json`) and regex heuristics.
- Tiered risk scoring (0–100) with severity classifications: `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- Dynamic Allowlisting (`config/allowlist.json`) filters trusted software (Microsoft, Google, NVIDIA, etc.) to prevent false positives.

### 4. Process & User Attribution (`core/attribution.py`)
- Answers *"Who changed it?"* by correlating registry events with Sysmon (Event ID 13/12/1), Windows Security Event Logs (4657/4688), and live process tree snapshotting.
- Extracts: Process Name, PID, Parent Process, Parent PID, Command Line, Token User, and Integrity Level.

### 5. Static PE Binary Forensics (`core/pe_analyzer.py`)
- Analyzes referenced executable binaries:
  - SHA-256 and MD5 hashes
  - Authenticode digital signature validation (`Valid`, `NotSigned`)
  - Shannon entropy calculation to detect packed or encrypted payloads
  - PE header metadata (compiler timestamp, sections, architecture)

### 6. Automated Forensic Incident Packages & 1-Click Rollback (`core/incident_manager.py`)
- For every High/Critical detection, auto-generates `incidents/INC-YYYYMMDD-XXXX/`:
  - `incident_report.json`: Machine-readable forensic dossier
  - `timeline.json`: Chronological event reconstruction
  - `rollback.reg`: **1-Click `.reg` Windows Registry patch** to undo the malicious change
  - `remediate.ps1`: Automated PowerShell remediation script to terminate processes and quarantine binaries
  - `remediation_playbook.md`: Actionable SOC analyst triage guidance

### 7. Honey-Key Decoy Canary System (`core/canary.py`)
- Deploys hidden bait registry keys that legitimate software never touches.
- Any modification immediately triggers a CRITICAL zero-day / automated malware persistence alert.

### 8. Cryptographic Baseline Integrity (`core/baseline_manager.py`)
- Computes HMAC-SHA256 signatures over baseline keys.
- Built-in anti-tampering engine detects if an adversary modified the baseline.

### 9. SIEM & Wazuh Ingestion Ready (`integrations/`)
- Outputs machine-parsable JSON Lines (`logs/events.jsonl`, `logs/alerts.jsonl`) and CEF logs.
- Includes custom Wazuh decoders (`wazuh_decoder.xml`) and detection rules (`wazuh_rules.xml`).
- Webhook alert dispatcher for Discord, Slack, and Microsoft Teams.

### 10. Cyber SOC Web Dashboard (`dashboard/index.html`, `api/app.py`)
- Dark-mode web interface featuring live SSE alert feeds, metric cards, MITRE matrix, incident explorer, and alert triage modal (`Investigate`, `Mark False Positive`, `Mark Resolved`).
- **Dual-Mode**: Connects to the local FastAPI + Win32 backend when running on Windows, or runs an interactive simulation when hosted publicly on GitHub Pages!

---

## 🚀 Quickstart & Setup

### 1. Clone & Install Dependencies
```powershell
git clone https://github.com/sabsec-h4x/Windows-Registry-Change-Monitoring-System.git
cd Windows-Registry-Change-Monitoring-System
pip install -r requirements.txt
```

### 2. Generate Cryptographically Signed Baseline
```powershell
python main.py --mode baseline
```

### 3. Verify Baseline Integrity
```powershell
python main.py --mode verify-baseline
```

### 4. Launch Real-Time Monitoring Agent + SOC Dashboard
```powershell
python main.py --mode agent --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser.

### 5. Run Safe Persistence Attack Simulator
In a second PowerShell window:
```powershell
python main.py --mode simulate
```
Watch the immediate alert trigger on the dashboard and console!

To clean up all test entries:
```powershell
python main.py --mode cleanup-simulate
```

### 6. Run Automated Test Suite
```powershell
python tests/test_suite.py
```

---

## 🌐 How to Host the Dashboard on GitHub Pages

1. Go to your GitHub repository: `https://github.com/sabsec-h4x/Windows-Registry-Change-Monitoring-System`.
2. Click **Settings** ➔ **Pages** (under Code and automation in the left sidebar).
3. Under **Build and deployment**:
   - **Source**: `Deploy from a branch`
   - **Branch**: `main` / `(root)` or `/docs` ➔ Click **Save**.
4. Within 1–2 minutes, GitHub will publish your live dashboard at:  
   👉 **`https://sabsec-h4x.github.io/Windows-Registry-Change-Monitoring-System/`**

---

## 📂 Project Structure

```
WindowsRegistryMonitor/
├── api/
│   └── app.py                      # FastAPI REST API & SSE streaming server
├── baseline/
│   └── baseline_registry.json      # HMAC-SHA256 signed baseline snapshot
├── config/
│   ├── allowlist.json              # Trusted publishers, paths & approved values
│   ├── monitored_keys.json         # MITRE ATT&CK registry persistence matrix
│   ├── rules.json                  # Detection rules, scores & regex heuristics
│   └── settings.json               # Global configuration (ports, database, logging)
├── core/
│   ├── attribution.py              # Sysmon, Event Log & live process correlator
│   ├── baseline_manager.py         # Cryptographic baseline generation & verification
│   ├── canary.py                   # Honey-Key decoy generator & monitor
│   ├── detection_engine.py         # Multi-layered risk scoring (0-100) & allowlist filter
│   ├── incident_manager.py         # Automated incident dossier & .reg rollback generator
│   ├── monitor.py                  # Master platform orchestrator
│   ├── pe_analyzer.py              # Authenticode signatures, SHA-256 & entropy analysis
│   ├── realtime_engine.py          # Native Win32 RegNotifyChangeKeyValue watcher threads
│   ├── registry_reader.py          # 32/64-bit recursive registry enumerator
│   ├── reporter.py                 # Central event dispatcher & alert router
│   └── state_manager.py            # Dynamic known-state tracker (prevents alert spam)
├── dashboard/
│   └── index.html                  # Cyber SOC web dashboard template
├── database/
│   └── db.py                       # SQLite database layer for events, alerts & incidents
├── docs/
│   └── index.html                  # GitHub Pages static deployment
├── incidents/                      # Auto-generated incident folders (reports, .reg, .ps1)
├── index.html                      # Root GitHub Pages entry point
├── integrations/
│   ├── siem_exporter.py            # JSONL, CEF & human log formatters
│   ├── webhook_alerter.py          # Discord, Slack & Teams alert dispatcher
│   └── wazuh/                      # Custom Wazuh decoders & detection rules XML
├── logs/                           # events.jsonl, alerts.jsonl, registry_changes.log
├── tests/
│   ├── test_scenarios.py           # Heuristic detection scenario tests
│   ├── test_live_cycle.py          # Full attack, attribution & rollback lifecycle test
│   └── test_suite.py               # Comprehensive unit & integration test suite
├── tools/
│   └── simulate_attack.py          # Safe persistence attack simulation suite
├── create_baseline.py              # Standalone baseline generation utility
├── main.py                         # Unified multi-mode CLI entry point
├── requirements.txt                # Python package dependencies
└── README.md                       # Documentation
```

---

## 🔌 Wazuh SIEM Integration

To feed alerts into your Wazuh SIEM:
1. Add `logs/events.jsonl` to `/var/ossec/etc/ossec.conf` on your Wazuh agent:
   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>C:\Path\To\WindowsRegistryMonitor\logs\events.jsonl</location>
   </localfile>
   ```
2. Copy `integrations/wazuh/wazuh_decoder.xml` to `/var/ossec/etc/decoders/local_decoder.xml`.
3. Copy `integrations/wazuh/wazuh_rules.xml` to `/var/ossec/etc/rules/local_rules.xml`.
4. Restart the Wazuh manager: `systemctl restart wazuh-manager`.
