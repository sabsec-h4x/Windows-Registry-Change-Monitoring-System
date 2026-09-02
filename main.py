import sys
import os
import argparse
import uvicorn
import logging
from core.monitor import RegistryMonitorPlatform
from core.baseline_manager import create_baseline, verify_baseline_integrity
from api.app import app, set_platform_instance
from database.db import init_db
from tools.simulate_attack import inject_test_persistence, cleanup_test_persistence

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

BANNER = """
========================================================================
   WINDOWS ENDPOINT PERSISTENCE DETECTION & SECURITY MONITOR v2.0
========================================================================
   [+] Zero-Latency Win32 Event Notifications (RegNotifyChangeKeyValue)
   [+] 32-bit & 64-bit Registry Architecture Inspection
   [+] Multi-Layer Risk Scoring (0-100) & MITRE ATT&CK Persistence Matrix
   [+] Live Process & User Attribution (Sysmon & Security Event Log)
   [+] PE Binary Forensics (Authenticode Signatures, Hashes & Entropy)
   [+] Cryptographic HMAC Baseline Integrity & Anti-Tamper Engine
   [+] Automated Forensic Incident Dossier & .REG Rollback Patch Generation
   [+] Honey-Key Decoy Canary System
========================================================================
"""

def run_agent(host: str = "127.0.0.1", port: int = 8000):
    print(BANNER)
    init_db()

    # 1. Start Monitor Platform
    monitor = RegistryMonitorPlatform()
    monitor.start()

    # 2. Attach monitor to FastAPI instance for SSE live streaming
    set_platform_instance(monitor)

    print(f"\n[+] SOC Web Dashboard Live at : http://{host}:{port}/")
    print(f"[+] REST API Docs available at: http://{host}:{port}/docs")
    print(f"[+] Live Event Logs streaming to: logs/events.jsonl & logs/alerts.jsonl\n")
    print("[*] Monitoring active. Press CTRL+C to terminate.\n")

    try:
        uvicorn.run(app, host=host, port=port, log_level="warning")
    except KeyboardInterrupt:
        print("\n[*] Shutting down platform...")
    finally:
        monitor.stop()

def run_scan():
    print(BANNER)
    init_db()
    monitor = RegistryMonitorPlatform()
    alerts = monitor.perform_full_scan()
    print(f"\n[+] Deep scan completed. Detected {len(alerts)} alerts.")
    for a in alerts:
        print(f"    - [{a['severity']}] {a['rule_name']} (Score: {a['risk_score']}/100) on {a['registry_key']}")

def run_baseline_creation():
    import json
    init_db()
    config_file = "config/monitored_keys.json"
    with open(config_file, "r", encoding="utf-8") as f:
        locations = json.load(f).get("monitored_locations", [])
    payload = create_baseline(locations)
    print(f"[+] Signed baseline generated with {payload['metadata']['key_count']} keys.")
    print(f"[+] HMAC Signature: {payload['metadata']['hmac_signature']}")

def run_baseline_verification():
    valid, msg = verify_baseline_integrity()
    if valid:
        print(f"[+] SUCCESS: {msg}")
    else:
        print(f"[-] WARNING: {msg}")

def main():
    parser = argparse.ArgumentParser(
        description="Windows Endpoint Persistence Detection & Security Monitoring Platform",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--mode",
        choices=["agent", "dashboard", "scan", "baseline", "verify-baseline", "simulate", "cleanup-simulate"],
        default="agent",
        help="Operational mode:\n"
             "  agent            - Launch real-time monitoring engine + Web SOC Dashboard\n"
             "  dashboard        - Start web server and API only\n"
             "  scan             - Run on-demand deep persistence scan\n"
             "  baseline         - Generate cryptographically signed baseline\n"
             "  verify-baseline  - Check baseline integrity for tampering\n"
             "  simulate         - Inject simulated persistence attack for testing\n"
             "  cleanup-simulate - Remove simulated test persistence entries"
    )
    parser.add_argument("--host", default="127.0.0.1", help="API/Dashboard host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="API/Dashboard port (default: 8000)")

    args = parser.parse_args()

    if args.mode == "agent":
        run_agent(host=args.host, port=args.port)
    elif args.mode == "dashboard":
        init_db()
        print(BANNER)
        print(f"[+] Launching SOC Dashboard at http://{args.host}:{args.port}/")
        uvicorn.run(app, host=args.host, port=args.port)
    elif args.mode == "scan":
        run_scan()
    elif args.mode == "baseline":
        run_baseline_creation()
    elif args.mode == "verify-baseline":
        run_baseline_verification()
    elif args.mode == "simulate":
        inject_test_persistence()
    elif args.mode == "cleanup-simulate":
        cleanup_test_persistence()

if __name__ == "__main__":
    main()
