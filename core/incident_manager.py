import os
import json
import uuid
from datetime import datetime
from typing import Dict, Any, Optional

def generate_rollback_reg(change: Dict[str, Any]) -> str:
    """
    Generates a valid Windows .reg file script to restore original registry state.
    """
    key_path = change.get("registry_key", "")
    val_name = change.get("value_name") or ""
    old_val = change.get("old_value")
    action = change.get("action", "")

    reg_content = "Windows Registry Editor Version 5.00\n\n"
    reg_content += f"[{key_path}]\n"

    if action == "ADDED":
        # To delete the newly added value in a .reg file: "ValueName"=-
        reg_content += f'"{val_name}"=-\n'
    elif action == "MODIFIED":
        if old_val is not None:
            if isinstance(old_val, int):
                reg_content += f'"{val_name}"=dword:{old_val:08x}\n'
            else:
                # Escape backslashes and quotes
                escaped_val = str(old_val).replace("\\", "\\\\").replace('"', '\\"')
                reg_content += f'"{val_name}"="{escaped_val}"\n'
        else:
            reg_content += f'"{val_name}"=-\n'
    elif action in ["DELETED", "SUBKEY_DELETED"]:
        if old_val is not None:
            escaped_val = str(old_val).replace("\\", "\\\\").replace('"', '\\"')
            reg_content += f'"{val_name}"="{escaped_val}"\n'

    return reg_content

def generate_powershell_remediation(change: Dict[str, Any], attribution: Dict[str, Any], pe_info: Dict[str, Any]) -> str:
    """
    Generates an automated PowerShell incident response script.
    """
    key_path = change.get("registry_key", "")
    val_name = change.get("value_name") or ""
    pid = attribution.get("pid")
    pname = attribution.get("process_name")
    exe_path = pe_info.get("file_path", "")

    ps = "# Windows Endpoint Security Platform - Automated Incident Remediation Script\n"
    ps += f"# Generated: {datetime.now().isoformat()}\n\n"

    ps += "# 1. Terminate Malicious/Suspicious Process\n"
    if pid:
        ps += f"try {{ Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue; Write-Host '[+] Terminated PID {pid}' }} catch {{}}\n"
    if pname and pname != "unknown.exe":
        ps += f"try {{ Stop-Process -Name '{os.path.splitext(pname)[0]}' -Force -ErrorAction SilentlyContinue }} catch {{}}\n"

    ps += "\n# 2. Revert/Delete Malicious Registry Persistence Entry\n"
    if "\\" in key_path:
        root_name, subkey = key_path.split("\\", 1)
        ps_root = "HKCU:" if "HKCU" in root_name else "HKLM:"
        ps_path = f"{ps_root}\\{subkey}"
        if val_name:
            ps += f"try {{ Remove-ItemProperty -Path '{ps_path}' -Name '{val_name}' -Force; Write-Host '[+] Removed registry value {val_name}' }} catch {{}}\n"
        else:
            ps += f"try {{ Remove-Item -Path '{ps_path}' -Recurse -Force; Write-Host '[+] Removed registry key {ps_path}' }} catch {{}}\n"

    ps += "\n# 3. Quarantine Suspicious Binary (Move to Quarantine folder)\n"
    if exe_path and os.path.exists(exe_path):
        ps += f"$quarantineDir = '$env:SystemDrive\\EndpointQuarantine'\n"
        ps += f"if (-not (Test-Path $quarantineDir)) {{ New-Item -ItemType Directory -Path $quarantineDir | Out-Null }}\n"
        ps += f"try {{ Move-Item -Path '{exe_path}' -Destination $quarantineDir -Force; Write-Host '[+] Quarantined binary {exe_path}' }} catch {{}}\n"

    return ps

def create_incident_dossier(alert: Dict[str, Any], change: Dict[str, Any], attribution: Dict[str, Any], pe_info: Dict[str, Any], base_dir: str = "incidents") -> Dict[str, Any]:
    """
    Creates a full forensic case folder for HIGH and CRITICAL alerts.
    """
    inc_date = datetime.now().strftime("%Y%m%d")
    inc_random = uuid.uuid4().hex[:6].upper()
    incident_id = f"INC-{inc_date}-{inc_random}"
    folder_path = os.path.join(base_dir, incident_id)
    os.makedirs(folder_path, exist_ok=True)

    timestamp = datetime.now().isoformat()
    rule_name = alert.get("rule_name", "Persistence Detection")
    severity = alert.get("severity", "HIGH")
    key_path = change.get("registry_key", "")

    # 1. incident_report.json
    report_data = {
        "incident_id": incident_id,
        "created_at": timestamp,
        "title": f"[{severity}] {rule_name} on {key_path}",
        "severity": severity,
        "risk_score": alert.get("risk_score", 0),
        "rule_id": alert.get("rule_id"),
        "rule_name": rule_name,
        "mitre_attack": {
            "technique_id": alert.get("technique_id", "T1547.001"),
            "technique_name": alert.get("technique_name", "Registry Persistence")
        },
        "registry_target": {
            "key": key_path,
            "value_name": change.get("value_name"),
            "action": change.get("action"),
            "new_value": change.get("new_value"),
            "old_value": change.get("old_value")
        },
        "attribution": attribution,
        "pe_forensics": pe_info,
        "remediation_status": "READY_FOR_ANALYSIS"
    }
    with open(os.path.join(folder_path, "incident_report.json"), "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # 2. timeline.json
    timeline_data = [
        {"time": timestamp, "stage": "DETECTION", "event": f"Registry {change.get('action')} detected in {key_path}"},
        {"time": timestamp, "stage": "CORRELATION", "event": f"Process attribution linked to {attribution.get('process_name')} (PID: {attribution.get('pid')})"},
        {"time": timestamp, "stage": "ANALYSIS", "event": f"Risk Score computed as {alert.get('risk_score')}/100. Severity: {severity}"}
    ]
    with open(os.path.join(folder_path, "timeline.json"), "w", encoding="utf-8") as f:
        json.dump(timeline_data, f, indent=2)

    # 3. rollback.reg
    reg_content = generate_rollback_reg(change)
    with open(os.path.join(folder_path, "rollback.reg"), "w", encoding="utf-8") as f:
        f.write(reg_content)

    # 4. remediate.ps1
    ps_content = generate_powershell_remediation(change, attribution, pe_info)
    with open(os.path.join(folder_path, "remediate.ps1"), "w", encoding="utf-8") as f:
        f.write(ps_content)

    # 5. remediation_playbook.md
    playbook = f"""# Incident Remediation Playbook: {incident_id}
**Severity**: {severity} | **Risk Score**: {alert.get('risk_score')}/100 | **MITRE ATT&CK**: {alert.get('technique_id')} ({alert.get('technique_name')})

## 1. Incident Overview
- **Registry Key**: `{key_path}`
- **Value Name**: `{change.get('value_name')}`
- **Action**: `{change.get('action')}`
- **Responsible Process**: `{attribution.get('process_name')}` (PID: `{attribution.get('pid')}`)
- **User / Principal**: `{attribution.get('user')}`
- **Command Line**: `{attribution.get('command_line')}`

## 2. Immediate Response Actions
1. **Review Rollback Patch**:
   - Double-click or run `reg import rollback.reg` in this directory to revert the registry value.
2. **Execute Automated PowerShell Remediation**:
   - Run `powershell -ExecutionPolicy Bypass -File remediate.ps1` to terminate the process and remove persistence.
3. **Isolate Endpoint / Analyze Hashes**:
   - Target SHA-256: `{pe_info.get('hashes', {}).get('sha256', 'N/A')}`
   - Check hash reputation on VirusTotal or internal threat intel.
"""
    with open(os.path.join(folder_path, "remediation_playbook.md"), "w", encoding="utf-8") as f:
        f.write(playbook)

    return {
        "incident_id": incident_id,
        "title": report_data["title"],
        "severity": severity,
        "folder_path": folder_path,
        "summary": f"{rule_name} on {key_path} by {attribution.get('process_name', 'unknown')}"
    }
