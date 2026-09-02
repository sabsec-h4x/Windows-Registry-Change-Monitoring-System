import os
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from integrations.siem_exporter import write_jsonl_event, write_human_log, get_hostname
from integrations.webhook_alerter import send_webhook_alert
from database.db import insert_event, insert_alert, insert_incident
from core.incident_manager import create_incident_dossier

class Reporter:
    """
    Centralized event dispatcher and SIEM reporter.
    """
    def __init__(self, events_jsonl: str = "logs/events.jsonl", alerts_jsonl: str = "logs/alerts.jsonl", incidents_dir: str = "incidents"):
        self.events_jsonl = events_jsonl
        self.alerts_jsonl = alerts_jsonl
        self.incidents_dir = incidents_dir

    def report_change(self, change: Dict[str, Any], detection: Dict[str, Any], attribution: Dict[str, Any]):
        """
        Coordinates full logging, database persistence, SIEM export, incident creation, and alerting.
        """
        event_id = f"EVT-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.now().isoformat()
        hostname = get_hostname()

        # Build normalized event structure
        event_payload = {
            "event_type": "REGISTRY_MODIFICATION",
            "event_id": event_id,
            "timestamp": timestamp,
            "hostname": hostname,
            "action": change.get("action"),
            "registry_key": change.get("registry_key"),
            "composite_key": change.get("composite_key"),
            "view": change.get("view", "64"),
            "value_name": change.get("value_name"),
            "old_value": change.get("old_value"),
            "new_value": change.get("new_value"),
            "value_type": change.get("value_type", "REG_SZ"),
            "severity": detection.get("severity", "INFORMATIONAL"),
            "risk_score": detection.get("risk_score", 0),
            "rule_id": detection.get("rule_id"),
            "rule_name": detection.get("rule_name"),
            "technique_id": detection.get("technique_id"),
            "technique_name": detection.get("technique_name"),
            "reasons": detection.get("reasons", []),
            "process_name": attribution.get("process_name"),
            "pid": attribution.get("pid"),
            "parent_process_name": attribution.get("parent_process_name"),
            "parent_pid": attribution.get("parent_pid"),
            "command_line": attribution.get("command_line"),
            "user": attribution.get("user")
        }

        # 1. Write to raw events log (JSONL)
        write_jsonl_event(event_payload, self.events_jsonl)

        # 2. Insert into SQLite DB events table
        insert_event(event_payload)

        # 3. Write human-readable log
        summary_line = f"[{event_payload['severity']}] {change.get('action')} on '{change.get('registry_key')}' (Val: '{change.get('value_name')}') by {attribution.get('process_name')} (PID: {attribution.get('pid')})"
        write_human_log(summary_line)

        # 4. Handle Alerts
        if detection.get("is_alert"):
            alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"
            incident_id = None
            incident_folder = None

            # For HIGH and CRITICAL alerts, generate automated forensic incident folder
            if detection.get("severity") in ["HIGH", "CRITICAL"]:
                inc_meta = create_incident_dossier(
                    alert=detection,
                    change=change,
                    attribution=attribution,
                    pe_info=detection.get("pe_forensics", {}),
                    base_dir=self.incidents_dir
                )
                incident_id = inc_meta["incident_id"]
                incident_folder = inc_meta["folder_path"]
                insert_incident({
                    "incident_id": incident_id,
                    "timestamp": timestamp,
                    "title": inc_meta["title"],
                    "severity": detection.get("severity"),
                    "alert_id": alert_id,
                    "registry_key": change.get("registry_key"),
                    "folder_path": incident_folder,
                    "summary": inc_meta["summary"]
                })

            alert_payload = {
                "event_type": "REGISTRY_PERSISTENCE_ALERT",
                "alert_id": alert_id,
                "event_id": event_id,
                "incident_id": incident_id,
                "incident_folder": incident_folder,
                "timestamp": timestamp,
                "hostname": hostname,
                "rule_id": detection.get("rule_id"),
                "rule_name": detection.get("rule_name"),
                "severity": detection.get("severity"),
                "risk_score": detection.get("risk_score"),
                "technique_id": detection.get("technique_id"),
                "technique_name": detection.get("technique_name"),
                "registry_key": change.get("registry_key"),
                "value_name": change.get("value_name"),
                "action": change.get("action"),
                "new_value": change.get("new_value"),
                "old_value": change.get("old_value"),
                "reasons": detection.get("reasons", []),
                "process_attribution": attribution,
                "pe_forensics": detection.get("pe_forensics", {})
            }

            # Write to alerts.jsonl
            write_jsonl_event(alert_payload, self.alerts_jsonl)

            # Insert into SQLite alerts table
            insert_alert(alert_payload)

            # Webhook dispatch
            send_webhook_alert(alert_payload)

            # Return the alert payload for live streaming / terminal output
            return alert_payload

        return None
