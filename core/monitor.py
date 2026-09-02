import os
import json
import time
import threading
import logging
from typing import Dict, Any, List, Optional, Callable

from core.registry_reader import read_registry_key
from core.baseline_manager import load_baseline, verify_baseline_integrity
from core.state_manager import StateManager
from core.detection_engine import DetectionEngine
from core.attribution import attribute_registry_change
from core.reporter import Reporter
from core.realtime_engine import RealtimeRegistryEngine
from core.canary import deploy_canary, check_canary_state
from database.db import init_db

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("RegistryMonitor")

class RegistryMonitorPlatform:
    """
    Main orchestrator for the Windows Endpoint Persistence Detection Platform.
    """
    def __init__(self, config_file: str = "config/monitored_keys.json", baseline_file: str = "baseline/baseline_registry.json"):
        self.config_file = config_file
        self.baseline_file = baseline_file

        # 1. Initialize SQLite Database
        init_db()

        # 2. Load Configuration
        self.locations_config = self._load_locations_config()

        # 3. Load or Initialize Baseline
        self.baseline_data = load_baseline(baseline_file)

        # 4. Initialize Core Components
        self.state_manager = StateManager(self.baseline_data)
        self.detection_engine = DetectionEngine()
        self.reporter = Reporter()

        # 5. Realtime Engine
        self.realtime_engine = RealtimeRegistryEngine(
            locations_config=self.locations_config,
            on_change_callback=self._handle_realtime_change
        )

        # Deploy canary decoy honey-key
        deploy_canary()

        self._running = False
        self._poll_thread: Optional[threading.Thread] = None
        self._alert_callbacks: List[Callable[[Dict[str, Any]], None]] = []

    def _load_locations_config(self) -> List[Dict[str, Any]]:
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    return json.load(f).get("monitored_locations", [])
            except Exception as e:
                logger.error(f"Error loading {self.config_file}: {e}")
        return []

    def register_alert_listener(self, callback: Callable[[Dict[str, Any]], None]):
        """Register an in-process listener for live UI / WebSocket push."""
        self._alert_callbacks.append(callback)

    def _notify_listeners(self, alert_payload: Dict[str, Any]):
        for cb in self._alert_callbacks:
            try:
                cb(alert_payload)
            except Exception:
                pass

    def _handle_realtime_change(self, path: str, view: str):
        """
        Zero-latency callback executed immediately when Windows fires RegNotifyChangeKeyValue.
        """
        composite_key = f"[{view}-bit] {path}"
        logger.info(f"⚡ [REAL-TIME EVENT] Registry modification triggered on: {composite_key}")

        # Find location metadata
        loc_meta = next((loc for loc in self.locations_config if loc["path"] == path), {})
        recursive = loc_meta.get("recursive", False)

        # Read current key contents
        current_data = read_registry_key(path, view=view, recursive=recursive)

        # Compute diff against known state
        deltas = self.state_manager.diff_key(composite_key, path, view, current_data or {})

        if not deltas:
            # Key touched without data delta (e.g. timestamp touch)
            return

        for change in deltas:
            # 1. Attribute responsible process / user
            attribution = attribute_registry_change(path, change.get("value_name"))

            # 2. Evaluate against detection engine rules
            detection = self.detection_engine.evaluate_change(change)

            # 3. Report & persist
            alert = self.reporter.report_change(change, detection, attribution)

            if alert:
                logger.warning(f"🚨 [ALERT {alert['severity']}] {alert['rule_name']} (Score: {alert['risk_score']}/100) on {path}")
                self._notify_listeners(alert)
            else:
                logger.info(f"ℹ️ [BENIGN/LOW] {change['action']} on {path}\\{change.get('value_name')}")

        # Update known state to prevent repeated duplicate alerts
        self.state_manager.update_key_state(composite_key, current_data or {})

    def perform_full_scan(self) -> List[Dict[str, Any]]:
        """
        Executes an on-demand complete integrity scan across all configured keys.
        """
        all_alerts = []
        logger.info("Starting on-demand deep registry persistence scan...")

        # 1. Verify baseline cryptographic integrity
        valid, msg = verify_baseline_integrity(self.baseline_file)
        if not valid:
            logger.error(f"Baseline Verification Alert: {msg}")

        # 2. Check canary honey-key
        canary_tampered, canary_msg = check_canary_state()
        if canary_tampered:
            logger.critical(f"CANARY TRIGGERED: {canary_msg}")

        # 3. Scan all keys
        for loc in self.locations_config:
            path = loc["path"]
            recursive = loc.get("recursive", False)
            views = loc.get("views", ["64"])

            for view in views:
                composite_key = f"[{view}-bit] {path}"
                current_data = read_registry_key(path, view=view, recursive=recursive)
                deltas = self.state_manager.diff_key(composite_key, path, view, current_data or {})

                for change in deltas:
                    attribution = attribute_registry_change(path, change.get("value_name"))
                    detection = self.detection_engine.evaluate_change(change)
                    alert = self.reporter.report_change(change, detection, attribution)
                    if alert:
                        all_alerts.append(alert)

                self.state_manager.update_key_state(composite_key, current_data or {})

        logger.info(f"Deep scan complete. Generated {len(all_alerts)} persistence alerts.")
        return all_alerts

    def _fallback_poll_worker(self, interval_seconds: int = 15):
        """Periodic background sweep for keys that cannot be hooked natively."""
        while self._running:
            time.sleep(interval_seconds)
            if not self._running:
                break
            # Periodic canary check
            canary_tampered, canary_msg = check_canary_state()
            if canary_tampered:
                canary_change = {
                    "action": "MODIFIED",
                    "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\SystemPersistenceCheck",
                    "composite_key": "[64-bit] HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\SystemPersistenceCheck",
                    "view": "64",
                    "value_name": "IntegrityToken",
                    "old_value": "SYSTEM_CANARY_ACTIVE_HONEYPOT",
                    "new_value": "TAMPERED",
                    "value_type": "REG_SZ"
                }
                attribution = attribute_registry_change(canary_change["registry_key"], "IntegrityToken")
                detection = {
                    "is_alert": True,
                    "rule_id": "REG-CANARY-001",
                    "rule_name": "Canary Decoy Honey-Key Triggered",
                    "severity": "CRITICAL",
                    "risk_score": 100,
                    "technique_id": "T1000.001",
                    "technique_name": "Canary Decoy Trigger",
                    "reasons": [canary_msg],
                    "pe_forensics": {}
                }
                alert = self.reporter.report_change(canary_change, detection, attribution)
                if alert:
                    self._notify_listeners(alert)

    def start(self):
        """Starts real-time watchers and honey-key canary."""
        self._running = True
        logger.info("Initializing Windows Endpoint Persistence Detection Platform...")

        # Deploy canary honey-key
        deploy_canary()

        # Start real-time win32 notification engine
        self.realtime_engine.start()

        # Start background fallback poller
        self._poll_thread = threading.Thread(target=self._fallback_poll_worker, daemon=True)
        self._poll_thread.start()

        logger.info("Platform is ACTIVE and monitoring with zero latency.")

    def stop(self):
        """Stops all monitoring threads cleanly."""
        self._running = False
        self.realtime_engine.stop()
        if self._poll_thread:
            self._poll_thread.join(timeout=1.0)
        logger.info("Platform shut down successfully.")
