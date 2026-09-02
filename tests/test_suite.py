import os
import sys
import unittest
import json
import tempfile
from fastapi.testclient import TestClient

# Ensure root directory is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.registry_reader import read_registry_key
from core.baseline_manager import compute_json_hmac, verify_baseline_integrity, create_baseline
from core.state_manager import StateManager
from core.detection_engine import DetectionEngine
from core.pe_analyzer import extract_file_path_from_command, compute_entropy
from core.incident_manager import generate_rollback_reg, create_incident_dossier
from database.db import init_db, insert_event, get_events, insert_alert, get_alerts, get_stats
from api.app import app

class TestRegistryMonitorPlatform(unittest.TestCase):

    def setUp(self):
        init_db()

    def test_01_registry_reader(self):
        """Test reading a standard Windows registry key."""
        result = read_registry_key(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", view="64")
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)

    def test_02_baseline_hmac_integrity(self):
        """Test HMAC calculation and tamper detection."""
        test_data = {"test_key": {"val": 123}}
        secret = "test-secret"
        sha, sig = compute_json_hmac(test_data, secret)
        self.assertTrue(len(sha) == 64)
        self.assertTrue(len(sig) == 64)

        # Test tamper detection with corrupted data
        tampered_data = {"test_key": {"val": 999}}
        tampered_sha, tampered_sig = compute_json_hmac(tampered_data, secret)
        self.assertNotEqual(sig, tampered_sig)

    def test_03_state_manager_diff(self):
        """Test in-memory dynamic state diffing."""
        initial = {
            "[64-bit] HKCU\\Software\\Test": {
                "data": {
                    "ExistingVal": {"value": "safe.exe", "type": "REG_SZ"}
                }
            }
        }
        sm = StateManager(initial)

        # Current state has an added value
        current_data = {
            "ExistingVal": {"value": "safe.exe", "type": "REG_SZ"},
            "MaliciousVal": {"value": "powershell.exe -enc AAAA", "type": "REG_SZ"}
        }

        deltas = sm.diff_key("[64-bit] HKCU\\Software\\Test", "HKCU\\Software\\Test", "64", current_data)
        self.assertEqual(len(deltas), 1)
        self.assertEqual(deltas[0]["action"], "ADDED")
        self.assertEqual(deltas[0]["value_name"], "MaliciousVal")

    def test_04_detection_engine_scoring(self):
        """Test multi-layered risk scoring and MITRE mapping."""
        engine = DetectionEngine()

        # 1. Encoded PowerShell in Run key
        change_ps = {
            "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value_name": "Backdoor",
            "action": "ADDED",
            "new_value": "powershell.exe -w hidden -enc JAB4ACAAPQAgACcAdABlAHMAdAAnAA==",
            "view": "64"
        }
        res_ps = engine.evaluate_change(change_ps)
        self.assertTrue(res_ps["is_alert"])
        self.assertIn(res_ps["severity"], ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(res_ps["risk_score"], 80)
        self.assertEqual(res_ps["technique_id"], "T1059.001")

        # 2. Allowlisted benign application
        change_benign = {
            "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value_name": "OneDrive",
            "action": "ADDED",
            "new_value": '"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe" /background',
            "view": "64"
        }
        res_benign = engine.evaluate_change(change_benign)
        self.assertFalse(res_benign["is_alert"])
        self.assertEqual(res_benign["severity"], "INFORMATIONAL")

    def test_05_pe_analyzer_helpers(self):
        """Test command line path extractor and entropy calculation."""
        cmd = r'"C:\Windows\System32\notepad.exe" C:\file.txt'
        extracted = extract_file_path_from_command(cmd)
        self.assertEqual(extracted, r"C:\Windows\System32\notepad.exe")

        # Entropy test
        low_entropy_bytes = b"AAAAAAAAAAAAAAAAAAAA"
        high_entropy_bytes = bytes([i % 256 for i in range(1000)])
        self.assertLess(compute_entropy(low_entropy_bytes), 1.0)
        self.assertGreater(compute_entropy(high_entropy_bytes), 7.0)

    def test_06_incident_rollback_generator(self):
        """Test .reg rollback script generation."""
        change = {
            "action": "ADDED",
            "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value_name": "MalwareKey",
            "new_value": "bad.exe"
        }
        reg = generate_rollback_reg(change)
        self.assertIn("Windows Registry Editor Version 5.00", reg)
        self.assertIn('"MalwareKey"=-', reg)

    def test_07_database_crud(self):
        """Test SQLite database insertion and querying."""
        evt = {
            "event_id": "TEST-EVT-001",
            "timestamp": "2026-08-28T00:00:00",
            "action": "ADDED",
            "registry_key": "HKCU\\Test",
            "value_name": "Val",
            "new_value": "data",
            "process_name": "cmd.exe",
            "pid": 1234,
            "severity": "HIGH",
            "risk_score": 75
        }
        insert_event(evt)
        events = get_events(limit=10)
        self.assertTrue(any(e["event_id"] == "TEST-EVT-001" for e in events))

    def test_08_fastapi_endpoints(self):
        """Test FastAPI REST endpoints."""
        client = TestClient(app)

        # Status endpoint
        resp = client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ONLINE")
        self.assertIn("baseline_integrity", data)

        # Stats endpoint
        resp_stats = client.get("/api/stats")
        self.assertEqual(resp_stats.status_code, 200)

        # Rules endpoint
        resp_rules = client.get("/api/rules")
        self.assertEqual(resp_rules.status_code, 200)
        self.assertIn("rules", resp_rules.json())

if __name__ == "__main__":
    unittest.main(verbosity=2)
