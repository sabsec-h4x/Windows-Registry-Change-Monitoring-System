import os
import json
from core.baseline_manager import create_baseline, verify_baseline_integrity
from database.db import init_db

CONFIG_FILE = "config/monitored_keys.json"
BASELINE_FILE = "baseline/baseline_registry.json"

def main():
    init_db()
    if not os.path.exists(CONFIG_FILE):
        print(f"[-] Config file {CONFIG_FILE} not found.")
        return

    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        locations = json.load(f).get("monitored_locations", [])

    print(f"[*] Scanning {len(locations)} persistence & security registry locations across 32-bit & 64-bit views...")
    payload = create_baseline(locations, BASELINE_FILE)
    meta = payload["metadata"]

    print("\n[+] ========================================================")
    print("[+] BASELINE CREATED & CRYPTOGRAPHICALLY SIGNED SUCCESSFULLY")
    print("[+] ========================================================")
    print(f"[+] Total Registry Keys Captured : {meta['key_count']}")
    print(f"[+] SHA-256 Digest              : {meta['sha256']}")
    print(f"[+] HMAC-SHA256 Signature        : {meta['hmac_signature']}")
    print(f"[+] Output File                  : {BASELINE_FILE}")
    print("[+] ========================================================\n")

    valid, msg = verify_baseline_integrity(BASELINE_FILE)
    print(f"[*] Integrity Verification: {msg}")

if __name__ == "__main__":
    main()
