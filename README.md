##windows-registry-change-monitoring-system

Blue Team endpoint integrity monitoring tool for detecting unauthorized Windows Registry modifications.

A Python-based registry monitoring toolkit that:

Monitors autorun registry keys (Run / RunOnce)

Detects persistence mechanisms

Identifies security configuration tampering

Performs baseline-based integrity verification

Classifies registry changes as ADDED, MODIFIED, or DELETED

Generates structured forensic logs

##1.Features

Registry Monitoring

Autorun key detection (HKCU / HKLM)

Security policy monitoring

Firewall configuration monitoring

Integrity Verification

Baseline snapshot creation

Dictionary-based delta comparison

Change classification engine

Detection Capabilities

Persistence injection detection

Security tool tampering detection

Unauthorized configuration changes

Logging

Structured console output

Change type identification

Registry path tracking

Previous vs current value comparison

##2.Architecture

Baseline Creation → Continuous Monitoring → State Comparison → Change Detection → Logging

##3.Quickstart

Create virtual environment:

python -m venv venv

Activate environment:

Windows:

venv\Scripts\activate

Linux/macOS:

source venv/bin/activate

Install dependencies:

pip install -r requirements.txt

Create baseline snapshot:

python create_baseline.py

Start monitoring:

python main.py
Example Output
('ADDED', 'HKCU\\...\\Run', 'test_value', None, 'C:\\Users\\Public\\test.exe')

('MODIFIED', 'HKCU\\...\\Run', 'test_value',
 'C:\\Users\\Public\\test.exe',
 'C:\\Users\\Public\\modified.exe')

('DELETED', 'HKCU\\...\\Run', 'test_value',
 'C:\\Users\\Public\\modified.exe', None)
##4.Use Case

Designed to simulate:

Endpoint Detection & Response (EDR) logic

SOC monitoring workflows

Registry-based persistence detection

Blue Team defensive scripting

##5.Limitations

Polling-based monitoring

Manual execution required

No kernel-level monitoring

No SIEM integration

##6.Future Improvements

Convert to Windows service

Event-driven registry monitoring

SIEM integration

Dashboard interface

Severity-based alert classification

Author
Sabareeshwari S
Cybersecurity Intern
