import json
from core.registry_reader import read_registry_key

def create_baseline(keys, output_file):
    baseline = {}
    for key in keys:
        baseline[key] = read_registry_key(key)

    with open(output_file, "w") as f:
        json.dump(baseline, f, indent=4)

def load_baseline(file_path):
    with open(file_path, "r") as f:
        return json.load(f)
