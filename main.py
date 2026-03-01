import json
import time
from core.baseline_manager import load_baseline
from core.registry_reader import read_registry_key
from core.monitor import compare_registry
from core.reporter import log_change, alert

CONFIG_FILE = "config/monitored_keys.json"
BASELINE_FILE = "baseline/baseline_registry.json"

with open(CONFIG_FILE) as f:
    config = json.load(f)

keys = config["autorun_keys"] + config["security_keys"]
baseline = load_baseline(BASELINE_FILE)

while True:
    current = {key: read_registry_key(key) for key in keys}
    changes = compare_registry(baseline, current)

    for change in changes:
        log_change(change)
        alert(change)

    time.sleep(30)  # polling interval
