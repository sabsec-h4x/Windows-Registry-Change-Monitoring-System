Windows Registry Change Monitoring System
Endpoint Integrity Monitoring Project
Overview

The Windows Registry Change Monitoring System is a Blue Team cybersecurity project designed to detect unauthorized or suspicious modifications in critical Windows Registry locations. The system establishes a trusted baseline snapshot of sensitive registry keys and continuously monitors them using a polling-based state comparison mechanism.

It detects and classifies registry changes as ADDED, MODIFIED, or DELETED, enabling early identification of persistence mechanisms, security policy tampering, and configuration manipulation. This project simulates practical endpoint integrity monitoring techniques used in Security Operations Centers (SOC).

Problem Statement

The Windows Registry stores critical system configurations including startup programs, security policies, firewall rules, and system behavior parameters. Attackers frequently target registry keys to:

Achieve persistence through autorun entries

Disable Windows Defender or security tools

Modify firewall configurations

Bypass User Account Control (UAC)

Escalate privileges

Manipulate security policies

Without active monitoring, such modifications may remain undetected, increasing the risk of endpoint compromise and delayed incident response.

Objectives

The primary objectives of this project are:

Monitor autorun registry keys for persistence detection

Detect malicious or unauthorized configuration changes

Implement baseline-based integrity verification

Classify registry changes as ADDED, MODIFIED, or DELETED

Generate structured logs for forensic analysis

Simulate endpoint integrity monitoring aligned with Blue Team operations

System Architecture

The system is composed of the following modular components:

Configuration Module
Defines sensitive registry paths in monitored_keys.json.

Baseline Manager
Captures and stores a trusted registry snapshot in baseline_registry.json.

Monitoring Engine
Continuously reads current registry state at defined polling intervals.

Delta Analysis Engine
Compares current registry values with baseline values using dictionary-based comparison logic.

Logging and Alert Module
Generates structured console output and logs detected changes.

Data Flow

Configuration → Baseline Creation → Continuous Monitoring → State Comparison → Change Detection → Logging and Alerting

Technical Implementation
Baseline Creation

The script create_baseline.py:

Reads configured registry paths

Extracts key-value pairs

Stores the trusted state in baseline/baseline_registry.json

Command:

python create_baseline.py
Monitoring Engine

The script main.py:

Loads the baseline snapshot

Reads current registry values

Compares dictionaries

Detects ADDED, MODIFIED, and DELETED values

Runs in a continuous polling loop

Command:

python main.py
Change Detection Logic

The system compares the baseline dictionary with the current dictionary.

Detection logic:

ADDED → Value exists in current state but not in baseline

MODIFIED → Value differs from baseline

DELETED → Value exists in baseline but not in current state

Example output:

('ADDED', 'HKCU\\...\\Run', 'test_value', None, 'C:\\Users\\Public\\test.exe')

('MODIFIED', 'HKCU\\...\\Run', 'test_value',
 'C:\\Users\\Public\\test.exe',
 'C:\\Users\\Public\\modified.exe')

('DELETED', 'HKCU\\...\\Run', 'test_value',
 'C:\\Users\\Public\\modified.exe', None)
Practical Demonstration

The system was tested using the following procedure:

Created a baseline snapshot

Started the monitoring script

Manually added a new registry value → System detected ADDED event

Modified the registry value → System detected MODIFIED event

Deleted the registry value → System detected DELETED event

This confirms functional real-time change detection within polling intervals.

Logging and Forensic Traceability

All detected changes are:

Displayed on the console

Logged with structured metadata

Timestamped for traceability

Each log entry contains:

Change type

Registry path

Value name

Old value

New value

Timestamp

This structure supports forensic investigation and audit trails.

Blue Team Relevance

This project demonstrates practical concepts used in:

Endpoint integrity monitoring

Registry persistence detection

Configuration tampering detection

Incident response logging

Similar techniques are implemented in:

Endpoint Detection and Response (EDR) systems

Security Information and Event Management (SIEM) platforms

SOC monitoring frameworks

Limitations

Polling-based detection introduces minor delay

No kernel-level monitoring

No Event Tracing for Windows (ETW) integration

No centralized SIEM integration

Requires manual execution

Future Enhancements

Convert into a Windows background service

Integrate with SIEM platforms (e.g., Splunk, ELK)

Implement event-based registry monitoring

Add a graphical dashboard interface

Implement severity-based alert classification

Develop enterprise endpoint agent architecture

Project Deliverables

Project documentation (PDF)

Registry monitoring toolkit (source code)

Screenshots of monitoring results

Baseline and integrity check logs

Architecture and workflow diagrams

Final presentation (PPT)

Author

Sabareeshwari S
Cybersecurity Intern
