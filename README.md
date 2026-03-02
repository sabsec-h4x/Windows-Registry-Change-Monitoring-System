Windows Registry Change Monitoring System
Endpoint Integrity Monitoring Project
📌 Overview

The Windows Registry Change Monitoring System is a Blue Team cybersecurity project designed to detect unauthorized or suspicious modifications in critical Windows Registry locations.

The system captures a trusted baseline snapshot of sensitive registry keys and continuously monitors them using polling-based state comparison. It detects:

ADDED registry values

MODIFIED registry values

DELETED registry values

Autorun persistence entries

Security configuration tampering

This project simulates practical endpoint integrity monitoring techniques used in Security Operations Centers (SOC).

🎯 Problem Statement

The Windows Registry stores critical system configurations including:

Startup programs

Security policies

Firewall rules

User privileges

System behavior parameters

Attackers frequently modify registry keys to:

Achieve persistence

Disable Windows Defender

Manipulate firewall policies

Bypass UAC

Escalate privileges

Without monitoring mechanisms, such changes may remain undetected.

🚀 Project Objectives

Monitor autorun registry keys

Detect malware-like configuration changes

Implement baseline-based integrity verification

Classify changes as ADDED, MODIFIED, DELETED

Generate structured forensic logs

🏗 System Architecture

The system consists of the following components:

Configuration Module
Defines sensitive registry paths (monitored_keys.json)

Baseline Manager
Captures trusted registry snapshot (baseline_registry.json)

Monitoring Engine
Continuously polls registry state

Delta Analysis Engine
Performs dictionary-based state comparison

Logging & Alert Module
Generates alerts and structured logs

Data Flow:

Configuration
→ Baseline Snapshot
→ Continuous Monitoring
→ State Comparison
→ Change Detection
→ Logging & Alerts

⚙️ Technologies Used

Python 3.x

winreg (Windows Registry access)

JSON (Configuration & baseline storage)

Polling-based monitoring logic

Structured console logging

🧠 Detection Logic

The system compares:

Baseline Registry State
vs
Current Registry State

It detects:

Change Type	Description
ADDED	New registry value detected
MODIFIED	Registry value altered
DELETED	Registry value removed
🖥 Installation & Usage
1️⃣ Clone Repository
git clone https://github.com/yourusername/Windows-Registry-Change-Monitoring-System.git
cd Windows-Registry-Change-Monitoring-System
2️⃣ Create Baseline
python create_baseline.py

This generates:

baseline/baseline_registry.json
3️⃣ Start Monitoring
python main.py

The system will continuously monitor registry keys.

📊 Example Output
('ADDED', 'HKCU\\...\\Run', 'test_realtime_check', None, 'C:\\Users\\Public\\test.exe')

('MODIFIED', 'HKCU\\...\\Run', 'test_realtime_check',
 'C:\\Users\\Public\\test.exe',
 'C:\\Users\\Public\\modified.exe')

('DELETED', 'HKCU\\...\\Run', 'test_realtime_check',
 'C:\\Users\\Public\\modified.exe', None)
🧪 Practical Demonstration

Testing steps performed:

Created baseline snapshot

Executed monitoring script

Added new registry value → System detected ADDED

Modified registry value → System detected MODIFIED

Deleted registry value → System detected DELETED

🔐 Blue Team Relevance

This project demonstrates:

Endpoint integrity monitoring

Registry persistence detection

Configuration tampering detection

Forensic trace logging

Defensive Python scripting

Similar techniques are used in:

Endpoint Detection & Response (EDR)

SIEM platforms

SOC monitoring frameworks

⚠️ Limitations

Polling-based detection introduces slight delay

No kernel-level monitoring

No ETW integration

No centralized SIEM integration

🔮 Future Improvements

Convert into Windows background service

Integrate with SIEM solutions (Splunk, ELK)

Implement event-based registry monitoring

Add dashboard interface

Implement severity-based alert classification

📁 Project Deliverables

✔ Project documentation (PDF)
✔ Registry monitoring toolkit
✔ Screenshots of monitoring results
✔ Baseline and integrity check logs
✔ Architecture & workflow diagrams
✔ Final presentation (PPT)

👨‍💻 Author
Sabareeshwari S
Cybersecurity Intern
