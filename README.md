# 🛡 Windows Registry Change Monitoring System  
### 🔍 Endpoint Integrity Monitoring Tool

> Monitor registry changes. Detect persistence. Strengthen endpoint security.

---

## 📖 Overview

The **Windows Registry Change Monitoring System** is a Python-based Blue Team endpoint integrity monitoring tool designed to detect unauthorized or suspicious modifications in critical Windows Registry locations.

The system captures a trusted baseline snapshot of sensitive registry keys and continuously compares the current registry state against this baseline to identify configuration tampering, persistence mechanisms, and security policy changes.

This project simulates real-world monitoring techniques used in Security Operations Centers (SOC) and Endpoint Detection & Response (EDR) systems.

---

## 🚀 Core Features

- Monitor **Run / RunOnce** autorun registry keys (HKCU & HKLM)
- Detect startup persistence injection attempts
- Monitor security policy registry paths
- Monitor firewall configuration changes
- Baseline-based registry integrity verification
- Detect and classify registry changes:
  - **ADDED**
  - **MODIFIED**
  - **DELETED**
- Structured console logging for forensic analysis
- Lightweight and easy deployment

---

## 🏗 Architecture Flow

Baseline Creation  
→ Continuous Monitoring  
→ Registry State Comparison  
→ Change Classification  
→ Logging & Alert Output  

---

## ⚙️ Installation

Python **3.8+** recommended.

### Create Virtual Environment

```bash
python -m venv venv

 Activate Environment

Windows

venv\Scripts\activate

Linux/macOS

source venv/bin/activate
Install Dependencies
pip install -r requirements.txt
▶️ Usage
Step 1: Create Baseline Snapshot
python create_baseline.py

This generates:

baseline/baseline_registry.json
Step 2: Start Monitoring
python main.py

The system will continuously monitor configured registry keys and detect any unauthorized changes.

🖥 Example Detection Output
('ADDED', 'HKCU\\...\\Run', 'test_value', None, 'C:\\Users\\Public\\test.exe')

('MODIFIED', 'HKCU\\...\\Run', 'test_value',
 'C:\\Users\\Public\\test.exe',
 'C:\\Users\\Public\\modified.exe')

('DELETED', 'HKCU\\...\\Run', 'test_value',
 'C:\\Users\\Public\\modified.exe', None)
🎯 Use Case

Designed for:

Blue Team training environments

Cybersecurity labs

SOC workflow simulations

Registry-based forensic analysis

Persistence detection demonstrations

⚠️ Limitations

Polling-based monitoring (interval dependent)

Manual execution required

No kernel-level monitoring

No SIEM integration

🔮 Future Enhancements

Convert to Windows background service

Event-driven registry monitoring

SIEM integration (Splunk / ELK)

Severity-based alert classification

Centralized dashboard interface

📦 Project Deliverables

Project documentation (PDF)

Registry monitoring toolkit (source code)

Monitoring screenshots

Baseline & integrity logs

Architecture & workflow diagrams

Final presentation (PPT)

👩‍💻 Author

Sabareeshwari S
Cybersecurity Intern
