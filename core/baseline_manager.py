import json
import os
import hashlib
import hmac
from datetime import datetime
from typing import Dict, Any, Tuple, Optional, List
from core.registry_reader import read_registry_key

DEFAULT_SECRET = "endpoint-persistence-monitor-secret-key-2026"

def get_hmac_secret() -> str:
    settings_file = "config/settings.json"
    if os.path.exists(settings_file):
        try:
            with open(settings_file, "r") as f:
                settings = json.load(f)
                return settings.get("security", {}).get("baseline_hmac_secret", DEFAULT_SECRET)
        except Exception:
            pass
    return DEFAULT_SECRET

def compute_json_hmac(data: Dict[str, Any], secret: str) -> Tuple[str, str]:
    """Computes (sha256_hash, hmac_signature) over canonical JSON."""
    canonical_json = json.dumps(data, sort_keys=True, separators=(',', ':'))
    raw_bytes = canonical_json.encode('utf-8')
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
    signature = hmac.new(secret.encode('utf-8'), raw_bytes, hashlib.sha256).hexdigest()
    return sha256_hash, signature

def create_baseline(locations_config: List[Dict[str, Any]], output_file: str = "baseline/baseline_registry.json") -> Dict[str, Any]:
    """
    Scans all monitored locations across 32-bit & 64-bit views and creates a cryptographically signed baseline.
    """
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    baseline_entries: Dict[str, Any] = {}

    for loc in locations_config:
        path = loc["path"]
        recursive = loc.get("recursive", False)
        views = loc.get("views", ["64"])

        for view in views:
            composite_key = f"[{view}-bit] {path}"
            content = read_registry_key(path, view=view, recursive=recursive)
            baseline_entries[composite_key] = {
                "path": path,
                "view": view,
                "category": loc.get("category", "General"),
                "technique_id": loc.get("technique_id", "T1547.001"),
                "recursive": recursive,
                "data": content or {}
            }

    secret = get_hmac_secret()
    sha256_hash, signature = compute_json_hmac(baseline_entries, secret)

    payload = {
        "metadata": {
            "created_at": datetime.now().isoformat(),
            "key_count": len(baseline_entries),
            "sha256": sha256_hash,
            "hmac_signature": signature,
            "version": "2.0.0"
        },
        "baseline": baseline_entries
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return payload

def load_baseline(file_path: str = "baseline/baseline_registry.json") -> Dict[str, Any]:
    """Loads baseline from file."""
    if not os.path.exists(file_path):
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        if "baseline" in data:
            return data["baseline"]
        return data

def verify_baseline_integrity(file_path: str = "baseline/baseline_registry.json") -> Tuple[bool, str]:
    """
    Verifies that the baseline file has not been modified or tampered with.
    Returns (is_valid, message).
    """
    if not os.path.exists(file_path):
        return False, "Baseline file does not exist."

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if "metadata" not in data or "baseline" not in data:
            return False, "Legacy or invalid baseline format missing metadata signature."

        metadata = data["metadata"]
        baseline_content = data["baseline"]
        expected_sig = metadata.get("hmac_signature")

        secret = get_hmac_secret()
        sha256_hash, actual_sig = compute_json_hmac(baseline_content, secret)

        if hmac.compare_digest(expected_sig, actual_sig):
            return True, f"Baseline integrity verified (SHA256: {sha256_hash[:12]}...)"
        else:
            return False, "TAMPERING DETECTED: Baseline cryptographic signature does not match stored content!"

    except Exception as e:
        return False, f"Integrity check failed with error: {str(e)}"
