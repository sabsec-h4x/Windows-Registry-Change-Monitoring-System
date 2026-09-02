import json
import os
import re
from typing import Dict, Any, List, Optional, Tuple
from core.pe_analyzer import extract_file_path_from_command, analyze_pe_file

class DetectionEngine:
    """
    Multi-layered risk scoring and detection engine for Windows Registry Persistence.
    Evaluates rule criteria, regex heuristics, PE Authenticode signatures, entropy, and allowlists.
    """
    def __init__(self, rules_file: str = "config/rules.json", allowlist_file: str = "config/allowlist.json"):
        self.rules_file = rules_file
        self.allowlist_file = allowlist_file
        self.rules: List[Dict[str, Any]] = []
        self.allowlist: Dict[str, Any] = {}
        self.reload_config()

    def reload_config(self):
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, "r", encoding="utf-8") as f:
                    self.rules = json.load(f).get("rules", [])
            except Exception:
                self.rules = []

        if os.path.exists(self.allowlist_file):
            try:
                with open(self.allowlist_file, "r", encoding="utf-8") as f:
                    self.allowlist = json.load(f)
            except Exception:
                self.allowlist = {}

    def is_allowlisted(self, key_path: str, value_name: Optional[str], new_value: Any, pe_info: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Checks if a registry change matches known-good allowlist criteria."""
        val_str = str(new_value or "")

        # Sensitive persistence / hijacking keys must NEVER be bypassed by generic executable names
        critical_hijack_indicators = [
            "image file execution options",
            "appinit_dlls",
            "policies\\microsoft\\windows defender",
            "systempersistencecheck"
        ]
        is_critical_key = any(ind in key_path.lower() for ind in critical_hijack_indicators)

        # 1. Check exact key/value pattern allowlist
        for item in self.allowlist.get("trusted_registry_values", []):
            if item.get("key", "").lower() in key_path.lower():
                if value_name and item.get("value_name", "").lower() == value_name.lower():
                    pat = item.get("pattern", "")
                    if pat and re.search(pat, val_str, re.IGNORECASE):
                        return True, f"Matched trusted registry pattern: {item.get('value_name')}"

        if is_critical_key:
            return False, ""

        # 2. Check trusted executable names (only for standard autorun keys)
        for exe_name in self.allowlist.get("trusted_executable_names", []):
            if exe_name.lower() in val_str.lower():
                # Verify if it resides in a trusted path
                for path in self.allowlist.get("trusted_paths", []):
                    if path.lower() in val_str.lower():
                        return True, f"Matched trusted binary in protected path: {exe_name}"

        # 3. Check digital signature publisher
        if pe_info and pe_info.get("signature", {}).get("is_signed"):
            signer = pe_info["signature"].get("signer_subject", "")
            for pub in self.allowlist.get("trusted_publishers", []):
                if pub.lower() in signer.lower():
                    return True, f"Verified digital signature from trusted publisher: {pub}"

        return False, ""

    def evaluate_change(self, change: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a registry delta event against detection rules, risk scoring, and heuristics.
        """
        key_path = change.get("registry_key", "")
        value_name = change.get("value_name") or ""
        new_value = change.get("new_value")
        action = change.get("action", "MODIFIED")
        val_str = str(new_value or "")

        # 1. Perform PE & File forensics if executable path detected
        pe_forensics = {}
        target_path = extract_file_path_from_command(val_str)
        if target_path:
            pe_forensics = analyze_pe_file(target_path)

        # 2. Check allowlist first
        is_allowed, allow_reason = self.is_allowlisted(key_path, value_name, new_value, pe_forensics)
        if is_allowed:
            return {
                "is_alert": False,
                "rule_id": "ALLOWLIST_MATCH",
                "rule_name": f"Allowed: {allow_reason}",
                "severity": "INFORMATIONAL",
                "risk_score": 5,
                "technique_id": "None",
                "technique_name": "Trusted Benign Activity",
                "reasons": [allow_reason],
                "pe_forensics": pe_forensics
            }

        # 3. Match rules & accumulate risk score
        matched_rules = []
        base_score = 0
        reasons = []

        for rule in self.rules:
            cond = rule.get("conditions", {})
            match = True

            # Condition: key_contains
            if "key_contains" in cond:
                if cond["key_contains"].lower() not in key_path.lower():
                    match = False

            # Condition: value_name_matches
            if match and "value_name_matches" in cond:
                if not value_name or not re.search(cond["value_name_matches"], value_name, re.IGNORECASE):
                    match = False

            # Condition: data_regex
            if match and "data_regex" in cond:
                if not val_str or not re.search(cond["data_regex"], val_str, re.IGNORECASE):
                    match = False

            if match:
                matched_rules.append(rule)
                if rule.get("base_score", 0) > base_score:
                    base_score = rule.get("base_score", 0)
                reasons.append(rule.get("name", rule.get("id")))

        # 4. Apply forensic modifiers to risk score
        score = base_score

        if pe_forensics.get("exists"):
            sig = pe_forensics.get("signature", {})
            if sig.get("is_signed"):
                score = max(10, score - 20)
                reasons.append("Executable is digitally signed")
            else:
                score = min(100, score + 25)
                reasons.append("Unsigned executable in persistence location (+25)")

            if pe_forensics.get("is_high_entropy"):
                score = min(100, score + 20)
                reasons.append("High entropy payload / packed executable (+20)")

        # User writable path heuristic
        if re.search(r"(?i)(\\appdata\\|\\temp\\|c:\\users\\public\\)", val_str):
            if "Executable Hosted in User-Writable Directory" not in reasons:
                score = min(100, score + 20)
                reasons.append("Executable located in user-writable directory (+20)")

        # If deleted, reduce severity unless it was a security policy
        if action in ["DELETED", "SUBKEY_DELETED"]:
            if "Policies" not in key_path:
                score = max(10, score - 20)
                reasons.append("Persistence value was removed/deleted")

        # 5. Determine final severity
        if score >= 80:
            severity = "CRITICAL"
        elif score >= 60:
            severity = "HIGH"
        elif score >= 30:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Determine primary rule and technique mapping
        primary_rule = matched_rules[0] if matched_rules else {
            "id": "REG-GENERIC-CHANGE",
            "name": "Unclassified Registry Modification",
            "technique_id": "T1547.001",
            "technique_name": "Registry Run Keys / Startup Folder"
        }

        # Check if score qualifies as an alert
        is_alert = score >= 30 or severity in ["MEDIUM", "HIGH", "CRITICAL"]

        return {
            "is_alert": is_alert,
            "rule_id": primary_rule.get("id"),
            "rule_name": primary_rule.get("name"),
            "severity": severity,
            "risk_score": score,
            "technique_id": primary_rule.get("technique_id", "T1547.001"),
            "technique_name": primary_rule.get("technique_name", "Registry Persistence"),
            "reasons": reasons if reasons else ["Registry key modification detected"],
            "pe_forensics": pe_forensics
        }
