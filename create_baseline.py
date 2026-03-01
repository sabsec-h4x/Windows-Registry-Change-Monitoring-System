import json
from core.baseline_manager import create_baseline

CONFIG_FILE = "config/monitored_keys.json"
BASELINE_FILE = "baseline/baseline_registry.json"

with open(CONFIG_FILE) as f:
    config = json.load(f)

keys = config["autorun_keys"] + config["security_keys"]

create_baseline(keys, BASELINE_FILE)

print("[+] Baseline created successfully")
