from core.registry_reader import read_registry_key
from core.malware_patterns import is_suspicious
from datetime import datetime

def compare_registry(baseline, current):
    changes = []

    for key in baseline:
        old = baseline[key] or {}
        new = current.get(key) or {}

        # Added or Modified
        for name, value in new.items():
            if name not in old:
                changes.append(("ADDED", key, name, None, value))
            elif old[name] != value:
                changes.append(("MODIFIED", key, name, old[name], value))

        # Deleted
        for name in old:
            if name not in new:
                changes.append(("DELETED", key, name, old[name], None))

    return changes
