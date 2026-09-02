# Incident Remediation Playbook: INC-20260828-E5B3CF
**Severity**: CRITICAL | **Risk Score**: 100/100 | **MITRE ATT&CK**: T1000.001 (Registry Persistence)

## 1. Incident Overview
- **Registry Key**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\SystemPersistenceCheck`
- **Value Name**: `IntegrityToken`
- **Action**: `ADDED`
- **Responsible Process**: `powershell.exe` (PID: `6684`)
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
