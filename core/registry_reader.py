import winreg
from typing import Dict, Any, Optional, List, Tuple

ROOTS = {
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKCR": winreg.HKEY_CLASSES_ROOT,
    "HKU": winreg.HKEY_USERS
}

VALUE_TYPES = {
    winreg.REG_SZ: "REG_SZ",
    winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
    winreg.REG_BINARY: "REG_BINARY",
    winreg.REG_DWORD: "REG_DWORD",
    winreg.REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
    winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
    winreg.REG_QWORD: "REG_QWORD",
    winreg.REG_NONE: "REG_NONE"
}

def decode_registry_value(value: Any, val_type: int) -> Any:
    """Format registry values safely for serialization and analysis."""
    if val_type == winreg.REG_BINARY:
        if isinstance(value, bytes):
            return value.hex()
        return str(value)
    elif val_type == winreg.REG_MULTI_SZ:
        if isinstance(value, list):
            return value
        return [str(value)]
    elif isinstance(value, bytes):
        try:
            return value.decode("utf-16le").rstrip("\x00")
        except Exception:
            try:
                return value.decode("utf-8", errors="replace")
            except Exception:
                return value.hex()
    return value

def get_access_mask(view: str = "64", write: bool = False) -> int:
    """Compute samDesired access mask for 32-bit/64-bit registry redirection."""
    mask = winreg.KEY_ALL_ACCESS if write else winreg.KEY_READ
    if view == "32":
        mask |= winreg.KEY_WOW64_32KEY
    elif view == "64":
        mask |= winreg.KEY_WOW64_64KEY
    return mask

def read_registry_key(path: str, view: str = "64", recursive: bool = False) -> Optional[Dict[str, Any]]:
    """
    Read all values and optionally subkeys for a given registry path.
    Returns a dictionary mapping value_name -> {'value': val, 'type': val_type}
    If recursive=True, also populates '__subkeys__' -> { subkey_name: subkey_data }
    """
    if "\\" not in path:
        return None

    root_name, subkey = path.split("\\", 1)
    if root_name not in ROOTS:
        return None

    root = ROOTS[root_name]
    access_mask = get_access_mask(view=view, write=False)

    data: Dict[str, Any] = {}
    try:
        with winreg.OpenKey(root, subkey, 0, access_mask) as key:
            # 1. Enumerate values
            i = 0
            while True:
                try:
                    name, value, val_type = winreg.EnumValue(key, i)
                    type_str = VALUE_TYPES.get(val_type, f"REG_UNKNOWN_{val_type}")
                    formatted_val = decode_registry_value(value, val_type)
                    data[name] = {
                        "value": formatted_val,
                        "type": type_str
                    }
                    i += 1
                except OSError:
                    break

            # 2. Enumerate subkeys if recursive
            if recursive:
                subkeys_data: Dict[str, Any] = {}
                j = 0
                while True:
                    try:
                        sub_name = winreg.EnumKey(key, j)
                        full_sub_path = f"{path}\\{sub_name}"
                        sub_content = read_registry_key(full_sub_path, view=view, recursive=True)
                        if sub_content is not None:
                            subkeys_data[sub_name] = sub_content
                        j += 1
                    except OSError:
                        break
                if subkeys_data:
                    data["__subkeys__"] = subkeys_data

    except (FileNotFoundError, PermissionError):
        return None
    except Exception:
        return None

    return data

def enumerate_subkeys_only(path: str, view: str = "64") -> List[str]:
    """Return a list of immediate subkey names under a registry path."""
    if "\\" not in path:
        return []
    root_name, subkey = path.split("\\", 1)
    if root_name not in ROOTS:
        return []
    root = ROOTS[root_name]
    access_mask = get_access_mask(view=view, write=False)
    subkeys = []
    try:
        with winreg.OpenKey(root, subkey, 0, access_mask) as key:
            i = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(key, i)
                    subkeys.append(sub_name)
                    i += 1
                except OSError:
                    break
    except Exception:
        pass
    return subkeys
