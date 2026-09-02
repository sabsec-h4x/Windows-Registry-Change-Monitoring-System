import winreg
from typing import Tuple, Optional

CANARY_PATH = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\SystemPersistenceCheck"
CANARY_VAL_NAME = "IntegrityToken"
CANARY_VAL_DATA = "SYSTEM_CANARY_ACTIVE_HONEYPOT"

def deploy_canary() -> bool:
    """
    Deploys a hidden canary decoy honey-key into HKCU.
    Legitimate Windows applications never touch this key.
    """
    try:
        root_name, subkey = CANARY_PATH.split("\\", 1)
        root = winreg.HKEY_CURRENT_USER
        with winreg.CreateKey(root, subkey) as key:
            winreg.SetValueEx(key, CANARY_VAL_NAME, 0, winreg.REG_SZ, CANARY_VAL_DATA)
        return True
    except Exception:
        return False

def check_canary_state() -> Tuple[bool, str]:
    """
    Checks if the canary honey-key is intact.
    Returns (is_tampered, message).
    """
    try:
        root_name, subkey = CANARY_PATH.split("\\", 1)
        root = winreg.HKEY_CURRENT_USER
        with winreg.OpenKey(root, subkey) as key:
            val, _ = winreg.QueryValueEx(key, CANARY_VAL_NAME)
            if val != CANARY_VAL_DATA:
                return True, f"CANARY VALUE TAMPERED: Value changed from '{CANARY_VAL_DATA}' to '{val}'"
            return False, "Canary intact"
    except FileNotFoundError:
        return True, "CANARY KEY DELETED: Honey-key was removed by an adversary or script!"
    except Exception as e:
        return True, f"Canary check exception: {str(e)}"
