import os
import json
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, Query, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database.db import (
    get_events, get_alerts, get_alert_by_id, update_alert_status,
    get_incidents, get_stats, init_db
)
from core.baseline_manager import verify_baseline_integrity, create_baseline
from core.canary import check_canary_state

app = FastAPI(
    title="Windows Endpoint Persistence Detection & Security Platform API",
    version="2.0.0",
    description="SOC Analyst REST API for real-time Windows registry persistence monitoring, attribution, and response."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global reference to monitor instance if running in agent mode
platform_instance = None
start_time = datetime.now()
sse_subscribers = []

def set_platform_instance(instance):
    global platform_instance
    platform_instance = instance
    if platform_instance:
        platform_instance.register_alert_listener(broadcast_alert_event)

def broadcast_alert_event(alert: Dict[str, Any]):
    """Broadcast alert to all connected SSE clients."""
    msg = f"data: {json.dumps(alert)}\n\n"
    for queue in list(sse_subscribers):
        try:
            queue.put_nowait(msg)
        except Exception:
            pass

class StatusUpdateRequest(BaseModel):
    status: str
    analyst_notes: Optional[str] = None

class AllowlistEntryRequest(BaseModel):
    entry_type: str
    value: str
    description: Optional[str] = ""

@app.on_event("startup")
def startup_event():
    init_db()

@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    dashboard_path = "dashboard/index.html"
    if os.path.exists(dashboard_path):
        with open(dashboard_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>SOC Dashboard index.html not found.</h1>"

@app.get("/api/status")
def get_system_status():
    uptime_sec = int((datetime.now() - start_time).total_seconds())
    valid_base, base_msg = verify_baseline_integrity()
    canary_tampered, canary_msg = check_canary_state()

    config_path = "config/monitored_keys.json"
    key_count = 0
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                key_count = len(json.load(f).get("monitored_locations", []))
        except Exception:
            pass

    return {
        "status": "ONLINE",
        "agent_version": "2.0.0",
        "hostname": os.environ.get("COMPUTERNAME", "LOCALHOST"),
        "uptime_seconds": uptime_sec,
        "monitored_locations_count": key_count,
        "realtime_engine": "ACTIVE (RegNotifyChangeKeyValue)",
        "baseline_integrity": {
            "is_valid": valid_base,
            "message": base_msg
        },
        "honeykey_canary": {
            "tampered": canary_tampered,
            "status": canary_msg
        }
    }

@app.get("/api/stats")
def get_statistics():
    return get_stats()

@app.get("/api/events")
def list_events(limit: int = Query(50, le=500), offset: int = 0):
    return get_events(limit=limit, offset=offset)

@app.get("/api/alerts")
def list_alerts(limit: int = Query(50, le=500), severity: Optional[str] = None):
    return get_alerts(limit=limit, severity=severity)

@app.get("/api/alerts/{alert_id}")
def get_alert_detail(alert_id: str):
    alert = get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: str, payload: StatusUpdateRequest):
    valid_statuses = ["NEW", "INVESTIGATING", "FALSE_POSITIVE", "RESOLVED"]
    if payload.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")
    update_alert_status(alert_id, payload.status, payload.analyst_notes)
    return {"message": "Alert status updated successfully", "alert_id": alert_id, "status": payload.status}

@app.get("/api/incidents")
def list_incidents(limit: int = Query(20, le=100)):
    return get_incidents(limit=limit)

@app.get("/api/incidents/{incident_id}")
def get_incident_detail(incident_id: str):
    inc_dir = os.path.join("incidents", incident_id)
    if not os.path.exists(inc_dir):
        raise HTTPException(status_code=404, detail="Incident case folder not found")

    result = {"incident_id": incident_id, "folder_path": inc_dir}
    for filename in ["incident_report.json", "timeline.json", "rollback.reg", "remediate.ps1", "remediation_playbook.md"]:
        fpath = os.path.join(inc_dir, filename)
        if os.path.exists(fpath):
            try:
                if filename.endswith(".json"):
                    with open(fpath, "r", encoding="utf-8") as f:
                        result[filename.replace(".json", "")] = json.load(f)
                else:
                    with open(fpath, "r", encoding="utf-8") as f:
                        result[filename.replace(".", "_")] = f.read()
            except Exception:
                pass
    return result

@app.post("/api/scan")
def trigger_scan(background_tasks: BackgroundTasks):
    if platform_instance:
        background_tasks.add_task(platform_instance.perform_full_scan)
        return {"message": "On-demand deep persistence scan dispatched in background"}
    return {"message": "Agent monitor instance not active"}

@app.get("/api/baseline/verify")
def verify_baseline():
    valid, msg = verify_baseline_integrity()
    return {"is_valid": valid, "message": msg}

@app.post("/api/baseline/create")
def regenerate_baseline():
    config_path = "config/monitored_keys.json"
    if not os.path.exists(config_path):
        raise HTTPException(status_code=400, detail="Config file missing")
    with open(config_path, "r", encoding="utf-8") as f:
        locations = json.load(f).get("monitored_locations", [])
    payload = create_baseline(locations)
    return {"message": "Baseline refreshed and cryptographically signed", "metadata": payload.get("metadata")}

@app.get("/api/rules")
def get_detection_rules():
    rules_path = "config/rules.json"
    if os.path.exists(rules_path):
        with open(rules_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"rules": []}

@app.get("/api/allowlist")
def get_allowlist_config():
    allow_path = "config/allowlist.json"
    if os.path.exists(allow_path):
        with open(allow_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

@app.get("/api/stream")
async def sse_alert_stream():
    """Server-Sent Events endpoint for pushing live alerts to SOC UI."""
    queue = asyncio.Queue()
    sse_subscribers.append(queue)

    async def event_generator():
        try:
            # Send initial ping
            yield "data: {\"type\": \"CONNECTION_ESTABLISHED\"}\n\n"
            while True:
                msg = await queue.get()
                yield msg
        except asyncio.CancelledError:
            pass
        finally:
            if queue in sse_subscribers:
                sse_subscribers.remove(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
