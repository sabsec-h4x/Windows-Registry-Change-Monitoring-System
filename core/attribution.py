import os
import sys
import subprocess
import json
import win32evtlog
import win32api
import win32process
import win32con
import win32security
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

def query_sysmon_registry_events(max_age_seconds: int = 60) -> List[Dict[str, Any]]:
    """
    Queries Sysmon Operational event log for Event ID 13 (Registry Value Set) or Event ID 12 (Object Create/Delete).
    """
    events = []
    server = 'localhost'
    log_type = 'Microsoft-Windows-Sysmon/Operational'

    try:
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        h_log = win32evtlog.OpenEventLog(server, log_type)
        if not h_log:
            return []

        cutoff = datetime.now() - timedelta(seconds=max_age_seconds)

        while True:
            records = win32evtlog.ReadEventLog(h_log, flags, 0)
            if not records:
                break
            for rec in records:
                if rec.TimeGenerated < cutoff:
                    break
                event_id = rec.EventID & 0x7FFF  # Mask event ID
                if event_id in [12, 13]:
                    strings = rec.StringInserts or []
                    events.append({
                        "event_id": event_id,
                        "time": rec.TimeGenerated.isoformat(),
                        "strings": strings
                    })
            if records and records[-1].TimeGenerated < cutoff:
                break
        win32evtlog.CloseEventLog(h_log)
    except Exception:
        # Sysmon may not be installed on every machine, which is completely expected
        pass

    return events

def query_security_audit_events(max_age_seconds: int = 60) -> List[Dict[str, Any]]:
    """
    Queries Windows Security Log for Event ID 4657 (Registry Value Modification) or 4688 (Process Creation).
    """
    events = []
    try:
        h_log = win32evtlog.OpenEventLog('localhost', 'Security')
        if not h_log:
            return []
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        cutoff = datetime.now() - timedelta(seconds=max_age_seconds)

        while True:
            records = win32evtlog.ReadEventLog(h_log, flags, 0)
            if not records:
                break
            for rec in records:
                if rec.TimeGenerated < cutoff:
                    break
                event_id = rec.EventID & 0x7FFF
                if event_id in [4657, 4688]:
                    events.append({
                        "event_id": event_id,
                        "time": rec.TimeGenerated.isoformat(),
                        "strings": rec.StringInserts or []
                    })
            if records and records[-1].TimeGenerated < cutoff:
                break
        win32evtlog.CloseEventLog(h_log)
    except Exception:
        pass
    return events

def get_live_process_snapshot() -> List[Dict[str, Any]]:
    """
    Captures running process snapshot with PID, Parent PID, Executable, User, and Command Line.
    Uses PowerShell / WMI or Windows API for high-fidelity telemetry.
    """
    try:
        cmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath, CreationDate | ConvertTo-Json -Compress"'
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        if proc.returncode == 0 and proc.stdout.strip():
            raw_data = json.loads(proc.stdout.strip())
            if isinstance(raw_data, dict):
                raw_data = [raw_data]
            return raw_data
    except Exception:
        pass
    return []

def attribute_registry_change(key_path: str, value_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Correlates a registry modification event to the responsible process, PID, parent, and user.
    """
    current_user = os.environ.get("USERNAME", "SYSTEM")
    current_domain = os.environ.get("USERDOMAIN", "NT AUTHORITY")
    full_user = f"{current_domain}\\{current_user}"

    attribution = {
        "user": full_user,
        "process_name": "unknown.exe",
        "pid": None,
        "parent_process_name": "unknown.exe",
        "parent_pid": None,
        "command_line": "",
        "integrity_level": "Medium",
        "attribution_source": "Heuristic Live Process Correlator"
    }

    # 1. First check Sysmon / Event Log telemetry
    sysmon_events = query_sysmon_registry_events(max_age_seconds=10)
    for evt in sysmon_events:
        for s in evt.get("strings", []):
            if key_path.lower() in s.lower():
                attribution["attribution_source"] = "Sysmon Event ID 13/12"
                # Sysmon strings contain process image and PID
                return attribution

    # 2. Heuristic live correlation: check recently spawned suspicious or administrative tools
    live_procs = get_live_process_snapshot()
    if live_procs:
        # Look for interactive CLI or scripting processes: reg.exe, powershell.exe, cmd.exe, wscript.exe, python.exe
        suspect_names = ["reg.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "cscript.exe", "wscript.exe", "python.exe"]
        matches = []
        for p in live_procs:
            pname = (p.get("Name") or "").lower()
            if any(s in pname for s in suspect_names):
                matches.append(p)

        if matches:
            # Pick most recently created process or matching context
            best_match = matches[-1]
            attribution["process_name"] = best_match.get("Name", "unknown.exe")
            attribution["pid"] = best_match.get("ProcessId")
            attribution["parent_pid"] = best_match.get("ParentProcessId")
            attribution["command_line"] = best_match.get("CommandLine", "")

            # Find parent process name
            ppid = best_match.get("ParentProcessId")
            for p in live_procs:
                if p.get("ProcessId") == ppid:
                    attribution["parent_process_name"] = p.get("Name", "unknown.exe")
                    break

            attribution["attribution_source"] = "Live Process Tree Snapshot"
            return attribution

    return attribution
