# Windows Endpoint Security Platform - Automated Incident Remediation Script
# Generated: 2026-08-28T00:16:20.217115

# 1. Terminate Malicious/Suspicious Process
try { Stop-Process -Id 18628 -Force -ErrorAction SilentlyContinue; Write-Host '[+] Terminated PID 18628' } catch {}
try { Stop-Process -Name 'powershell' -Force -ErrorAction SilentlyContinue } catch {}

# 2. Revert/Delete Malicious Registry Persistence Entry
try { Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'SecUpdateMockTest' -Force; Write-Host '[+] Removed registry value SecUpdateMockTest' } catch {}

# 3. Quarantine Suspicious Binary (Move to Quarantine folder)
