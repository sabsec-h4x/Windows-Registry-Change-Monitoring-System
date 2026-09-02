import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools.simulate_attack import inject_test_persistence, cleanup_test_persistence
from core.monitor import RegistryMonitorPlatform

class TestLiveLifecycle(unittest.TestCase):
    def test_full_attack_detection_and_remediation_lifecycle(self):
        print("\n--- Testing Full Attack, Detection, Attribution & Incident Lifecycle ---")
        
        # 1. Clean first
        cleanup_test_persistence()
        
        # 2. Inject simulated attack
        inject_test_persistence()
        
        # 3. Perform scan and detect
        platform = RegistryMonitorPlatform()
        alerts = platform.perform_full_scan()
        
        self.assertGreaterEqual(len(alerts), 2)
        print(f"[+] Successfully captured {len(alerts)} persistence alerts.")
        
        for a in alerts:
            print(f"    - [{a['severity']}] {a['rule_name']} (Score: {a['risk_score']}/100) on {a['registry_key']}")
            proc = a.get("process_attribution", {})
            print(f"      Process: {proc.get('process_name')} (PID: {proc.get('pid')}) | User: {proc.get('user')}")
        
        # 4. Verify incident case folder
        incidents = [d for d in os.listdir("incidents") if d.startswith("INC-")]
        self.assertTrue(len(incidents) > 0)
        latest_inc = os.path.join("incidents", sorted(incidents)[-1])
        contained_files = os.listdir(latest_inc)
        
        self.assertIn("incident_report.json", contained_files)
        self.assertIn("timeline.json", contained_files)
        self.assertIn("rollback.reg", contained_files)
        self.assertIn("remediate.ps1", contained_files)
        self.assertIn("remediation_playbook.md", contained_files)
        
        with open(os.path.join(latest_inc, "rollback.reg"), "r") as f:
            reg_patch = f.read()
            self.assertIn("Windows Registry Editor Version 5.00", reg_patch)
            print(f"[+] Rollback .reg verified:\n{reg_patch}")
            
        # 5. Clean up simulated attack
        cleanup_test_persistence()
        print("[+] Attack simulation cleaned up and restored.")

if __name__ == "__main__":
    unittest.main(verbosity=2)
