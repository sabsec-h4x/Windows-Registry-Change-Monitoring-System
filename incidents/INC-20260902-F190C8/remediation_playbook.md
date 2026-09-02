# Incident Remediation Playbook: INC-20260902-F190C8
**Severity**: HIGH | **Risk Score**: 75/100 | **MITRE ATT&CK**: T1218 (Registry Persistence)

## 1. Incident Overview
- **Registry Key**: `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- **Value Name**: `LOLBinSimTest`
- **Action**: `ADDED`
- **Responsible Process**: `powershell.exe` (PID: `12640`)
- **User / Principal**: `LAPTOP-8IAQT2P0\Asus`
- **Command Line**: `powershell.exe  -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath, CreationDate | ConvertTo-Json -Compress"`

## 2. Immediate Response Actions
1. **Review Rollback Patch**:
   - Double-click or run `reg import rollback.reg` in this directory to revert the registry value.
2. **Execute Automated PowerShell Remediation**:
   - Run `powershell -ExecutionPolicy Bypass -File remediate.ps1` to terminate the process and remove persistence.
3. **Isolate Endpoint / Analyze Hashes**:
   - Target SHA-256: `N/A`
   - Check hash reputation on VirusTotal or internal threat intel.
