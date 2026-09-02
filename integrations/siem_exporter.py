import os
import json
import socket
import threading
from datetime import datetime
from typing import Dict, Any, Optional

_log_lock = threading.Lock()

def get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "UNKNOWN_HOST"

def format_cef_event(event: Dict[str, Any]) -> str:
    """
    Formats an event as a Common Event Format (CEF) string for ArcSight / Splunk / QRadar.
    Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
    """
    severity_map = {"INFORMATIONAL": 1, "LOW": 3, "MEDIUM": 6, "HIGH": 8, "CRITICAL": 10}
    sev_num = severity_map.get(event.get("severity", "LOW"), 3)

    vendor = "WindowsSecurity"
    product = "RegistryMonitor"
    version = "2.0"
    signature_id = event.get("technique_id", "REG-001")
    name = event.get("rule_name", "RegistryModification")

    extension_parts = [
        f"rt={event.get('timestamp')}",
        f"dhost={get_hostname()}",
        f"act={event.get('action')}",
        f"cs1={event.get('registry_key')}",
        f"cs1Label=RegistryKey",
        f"cs2={event.get('value_name') or ''}",
        f"cs2Label=ValueName",
        f"duser={event.get('user', 'SYSTEM')}",
        f"dproc={event.get('process_name', 'unknown')}",
        f"dpid={event.get('pid') or 0}",
        f"cn1={event.get('risk_score', 0)}",
        f"cn1Label=RiskScore"
    ]
    extension = " ".join(extension_parts)

    return f"CEF:0|{vendor}|{product}|{version}|{signature_id}|{name}|{sev_num}|{extension}"

def write_jsonl_event(event: Dict[str, Any], file_path: str = "logs/events.jsonl"):
    """Writes a machine-parsable JSON Lines record."""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with _log_lock:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

def write_human_log(message: str, file_path: str = "logs/registry_changes.log"):
    """Appends to human-readable log file."""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with _log_lock:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
