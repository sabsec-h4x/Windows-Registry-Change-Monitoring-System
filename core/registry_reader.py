import winreg

ROOTS = {
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKLM": winreg.HKEY_LOCAL_MACHINE
}

def read_registry_key(path):
    root_name, subkey = path.split("\\", 1)
    root = ROOTS[root_name]

    data = {}
    try:
        with winreg.OpenKey(root, subkey) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    data[name] = value
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        return None

    return data
