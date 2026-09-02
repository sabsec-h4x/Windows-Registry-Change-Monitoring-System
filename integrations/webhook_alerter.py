import json
import os
import urllib.request
import threading
from typing import Dict, Any, Optional

def send_webhook_alert(alert_data: Dict[str, Any], settings_file: str = "config/settings.json"):
    """
    Asynchronously sends webhook notifications to Discord/Slack/Teams/SIEM webhook endpoints.
    """
    if not os.path.exists(settings_file):
        return

    try:
        with open(settings_file, "r", encoding="utf-8") as f:
            settings = json.load(f)

        webhook_config = settings.get("webhooks", {})
        if not webhook_config.get("enabled"):
            return

        webhook_url = webhook_config.get("url", "")
        if not webhook_url:
            return

        min_severity = webhook_config.get("min_severity", "HIGH")
        severity_order = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

        alert_sev = alert_data.get("severity", "LOW")
        if severity_order.get(alert_sev, 0) < severity_order.get(min_severity, 3):
            return

        def _dispatch():
            try:
                # Format payload
                rule_name = alert_data.get("rule_name", "Registry Persistence Alert")
                score = alert_data.get("risk_score", 0)
                reg_key = alert_data.get("registry_key", "")
                val_name = alert_data.get("value_name", "")
                new_val = alert_data.get("new_value", "")
                tech = f"{alert_data.get('technique_id', '')} - {alert_data.get('technique_name', '')}"

                payload = {
                    "text": f":warning: *[{alert_sev}] {rule_name}* (Risk Score: {score}/100)\n*Key:* `{reg_key}`\n*Value:* `{val_name}`\n*Data:* `{str(new_val)[:120]}`\n*MITRE ATT&CK:* {tech}",
                    "content": f"🚨 **[{alert_sev}] {rule_name}** | Score: {score}/100\nKey: `{reg_key}`\nMITRE: {tech}"
                }

                req_data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    webhook_url,
                    data=req_data,
                    headers={"Content-Type": "application/json", "User-Agent": "RegistryMonitorAgent/2.0"}
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    pass
            except Exception:
                pass

        # Run in separate thread so it doesn't block monitoring loop
        threading.Thread(target=_dispatch, daemon=True).start()

    except Exception:
        pass
