import copy
import threading
from typing import Dict, Any, List, Optional, Tuple

class StateManager:
    """
    Thread-safe in-memory state manager that tracks the known registry state
    and prevents duplicate alert storms for identical changes.
    """
    def __init__(self, initial_baseline: Optional[Dict[str, Any]] = None):
        self._lock = threading.Lock()
        self._known_state: Dict[str, Any] = {}
        if initial_baseline:
            self.load_initial_baseline(initial_baseline)

    def load_initial_baseline(self, baseline: Dict[str, Any]):
        with self._lock:
            self._known_state = copy.deepcopy(baseline)

    def get_known_state(self) -> Dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._known_state)

    def get_key_state(self, composite_key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._known_state.get(composite_key, {}).get("data", {}))

    def update_key_state(self, composite_key: str, new_data: Dict[str, Any]):
        """Updates the known state for a specific key after an event is processed."""
        with self._lock:
            if composite_key not in self._known_state:
                self._known_state[composite_key] = {"data": {}}
            self._known_state[composite_key]["data"] = copy.deepcopy(new_data)

    def diff_key(self, composite_key: str, path: str, view: str, current_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Compares current registry state against known state for a single key.
        Returns a list of delta events.
        """
        changes = []
        with self._lock:
            old_container = self._known_state.get(composite_key, {})
            old_data = old_container.get("data", {}) if isinstance(old_container, dict) else {}

        # 1. Check for Added or Modified values
        for val_name, val_meta in (current_data or {}).items():
            if val_name == "__subkeys__":
                continue
            curr_val = val_meta.get("value") if isinstance(val_meta, dict) else val_meta
            val_type = val_meta.get("type", "REG_SZ") if isinstance(val_meta, dict) else "REG_SZ"

            if val_name not in old_data:
                changes.append({
                    "action": "ADDED",
                    "registry_key": path,
                    "composite_key": composite_key,
                    "view": view,
                    "value_name": val_name,
                    "old_value": None,
                    "new_value": curr_val,
                    "value_type": val_type
                })
            else:
                old_meta = old_data[val_name]
                old_val = old_meta.get("value") if isinstance(old_meta, dict) else old_meta
                if old_val != curr_val:
                    changes.append({
                        "action": "MODIFIED",
                        "registry_key": path,
                        "composite_key": composite_key,
                        "view": view,
                        "value_name": val_name,
                        "old_value": old_val,
                        "new_value": curr_val,
                        "value_type": val_type
                    })

        # 2. Check for Deleted values
        for val_name, val_meta in (old_data or {}).items():
            if val_name == "__subkeys__":
                continue
            old_val = val_meta.get("value") if isinstance(val_meta, dict) else val_meta
            val_type = val_meta.get("type", "REG_SZ") if isinstance(val_meta, dict) else "REG_SZ"

            if current_data is None or val_name not in current_data:
                changes.append({
                    "action": "DELETED",
                    "registry_key": path,
                    "composite_key": composite_key,
                    "view": view,
                    "value_name": val_name,
                    "old_value": old_val,
                    "new_value": None,
                    "value_type": val_type
                })

        # 3. Check for Subkey changes if present
        old_subs = old_data.get("__subkeys__", {}) if isinstance(old_data, dict) else {}
        new_subs = current_data.get("__subkeys__", {}) if isinstance(current_data, dict) else {}

        for sub_name in new_subs:
            if sub_name not in old_subs:
                changes.append({
                    "action": "SUBKEY_CREATED",
                    "registry_key": f"{path}\\{sub_name}",
                    "composite_key": composite_key,
                    "view": view,
                    "value_name": None,
                    "old_value": None,
                    "new_value": f"Created subkey {sub_name}",
                    "value_type": "REG_KEY"
                })
        for sub_name in old_subs:
            if sub_name not in new_subs:
                changes.append({
                    "action": "SUBKEY_DELETED",
                    "registry_key": f"{path}\\{sub_name}",
                    "composite_key": composite_key,
                    "view": view,
                    "value_name": None,
                    "old_value": f"Deleted subkey {sub_name}",
                    "new_value": None,
                    "value_type": "REG_KEY"
                })

        return changes
