import sqlite3
import os
import json
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any

DB_PATH = "data/registry_monitor.db"
_lock = threading.Lock()

def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with _lock:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                registry_key TEXT NOT NULL,
                value_name TEXT,
                old_value TEXT,
                new_value TEXT,
                value_type TEXT,
                view TEXT,
                process_name TEXT,
                pid INTEGER,
                user TEXT,
                severity TEXT,
                risk_score INTEGER
            )
        """)

        # Alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE,
                timestamp TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                technique_id TEXT,
                technique_name TEXT,
                registry_key TEXT NOT NULL,
                value_name TEXT,
                new_value TEXT,
                process_attribution TEXT,
                pe_forensics TEXT,
                incident_id TEXT,
                status TEXT DEFAULT 'NEW',
                analyst_notes TEXT
            )
        """)

        # Incidents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT UNIQUE,
                timestamp TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                alert_id TEXT,
                registry_key TEXT NOT NULL,
                status TEXT DEFAULT 'OPEN',
                folder_path TEXT,
                summary TEXT
            )
        """)

        # Baseline metadata table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS baseline_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                hmac_signature TEXT NOT NULL,
                key_count INTEGER NOT NULL,
                status TEXT NOT NULL
            )
        """)

        # Allowlist table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS allowlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_type TEXT NOT NULL,
                value TEXT NOT NULL,
                description TEXT,
                added_at TEXT NOT NULL
            )
        """)

        conn.commit()
        conn.close()

def insert_event(event_data: Dict[str, Any]):
    with _lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO events (
                event_id, timestamp, action, registry_key, value_name,
                old_value, new_value, value_type, view, process_name,
                pid, user, severity, risk_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_data.get("event_id"),
            event_data.get("timestamp", datetime.now().isoformat()),
            event_data.get("action"),
            event_data.get("registry_key"),
            event_data.get("value_name"),
            json.dumps(event_data.get("old_value")) if isinstance(event_data.get("old_value"), (dict, list)) else str(event_data.get("old_value") or ""),
            json.dumps(event_data.get("new_value")) if isinstance(event_data.get("new_value"), (dict, list)) else str(event_data.get("new_value") or ""),
            event_data.get("value_type", "REG_SZ"),
            event_data.get("view", "64"),
            event_data.get("process_name"),
            event_data.get("pid"),
            event_data.get("user"),
            event_data.get("severity", "INFORMATIONAL"),
            event_data.get("risk_score", 0)
        ))
        conn.commit()
        conn.close()

def insert_alert(alert_data: Dict[str, Any]):
    with _lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO alerts (
                alert_id, timestamp, rule_id, rule_name, severity,
                risk_score, technique_id, technique_name, registry_key,
                value_name, new_value, process_attribution, pe_forensics,
                incident_id, status, analyst_notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_data.get("alert_id"),
            alert_data.get("timestamp", datetime.now().isoformat()),
            alert_data.get("rule_id"),
            alert_data.get("rule_name"),
            alert_data.get("severity"),
            alert_data.get("risk_score", 0),
            alert_data.get("technique_id"),
            alert_data.get("technique_name"),
            alert_data.get("registry_key"),
            alert_data.get("value_name"),
            json.dumps(alert_data.get("new_value")) if isinstance(alert_data.get("new_value"), (dict, list)) else str(alert_data.get("new_value") or ""),
            json.dumps(alert_data.get("process_attribution", {})),
            json.dumps(alert_data.get("pe_forensics", {})),
            alert_data.get("incident_id"),
            alert_data.get("status", "NEW"),
            alert_data.get("analyst_notes", "")
        ))
        conn.commit()
        conn.close()

def insert_incident(incident_data: Dict[str, Any]):
    with _lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO incidents (
                incident_id, timestamp, title, severity, alert_id,
                registry_key, status, folder_path, summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident_data.get("incident_id"),
            incident_data.get("timestamp", datetime.now().isoformat()),
            incident_data.get("title"),
            incident_data.get("severity"),
            incident_data.get("alert_id"),
            incident_data.get("registry_key"),
            incident_data.get("status", "OPEN"),
            incident_data.get("folder_path"),
            incident_data.get("summary")
        ))
        conn.commit()
        conn.close()

def get_events(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_alerts(limit: int = 100, severity: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if severity:
        cursor.execute("SELECT * FROM alerts WHERE severity = ? ORDER BY id DESC LIMIT ?", (severity, limit))
    else:
        cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["process_attribution"] = json.loads(d.get("process_attribution") or "{}")
        except Exception:
            pass
        try:
            d["pe_forensics"] = json.loads(d.get("pe_forensics") or "{}")
        except Exception:
            pass
        result.append(d)
    return result

def get_alert_by_id(alert_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    try:
        d["process_attribution"] = json.loads(d.get("process_attribution") or "{}")
    except Exception:
        pass
    try:
        d["pe_forensics"] = json.loads(d.get("pe_forensics") or "{}")
    except Exception:
        pass
    return d

def update_alert_status(alert_id: str, status: str, notes: Optional[str] = None):
    with _lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        if notes is not None:
            cursor.execute("UPDATE alerts SET status = ?, analyst_notes = ? WHERE alert_id = ?", (status, notes, alert_id))
        else:
            cursor.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (status, alert_id))
        conn.commit()
        conn.close()

def get_incidents(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_stats() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM events")
    total_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'")
    critical_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'")
    high_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'MEDIUM'")
    medium_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'LOW'")
    low_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM incidents")
    total_incidents = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'NEW'")
    new_alerts = cursor.fetchone()[0]

    conn.close()

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
        "total_incidents": total_incidents,
        "unresolved_alerts": new_alerts
    }
