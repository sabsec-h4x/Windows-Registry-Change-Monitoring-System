import winreg
import win32api
import win32con
import win32event
import threading
import time
import logging
from typing import Dict, Any, List, Callable, Optional
from core.registry_reader import ROOTS, get_access_mask

logger = logging.getLogger("RealtimeEngine")

# Windows Registry Notification Filter Flags
# REG_NOTIFY_CHANGE_NAME (0x1) | REG_NOTIFY_CHANGE_ATTRIBUTES (0x2) | REG_NOTIFY_CHANGE_LAST_SET (0x4) | REG_NOTIFY_CHANGE_SECURITY (0x8)
REG_NOTIFY_CHANGE_NAME = 0x00000001
REG_NOTIFY_CHANGE_ATTRIBUTES = 0x00000002
REG_NOTIFY_CHANGE_LAST_SET = 0x00000004
REG_NOTIFY_CHANGE_SECURITY = 0x00000008

NOTIFY_FLAGS = (
    REG_NOTIFY_CHANGE_NAME |
    REG_NOTIFY_CHANGE_ATTRIBUTES |
    REG_NOTIFY_CHANGE_LAST_SET |
    REG_NOTIFY_CHANGE_SECURITY
)

class RegistryWatcherThread(threading.Thread):
    """
    Dedicated worker thread that blocks on a Windows native Registry Change Event handle
    using RegNotifyChangeKeyValue for zero-latency detection.
    """
    def __init__(self, path: str, view: str, recursive: bool, callback: Callable[[str, str], None], stop_event: threading.Event):
        super().__init__(daemon=True)
        self.path = path
        self.view = view
        self.recursive = recursive
        self.callback = callback
        self.stop_event = stop_event
        self.name = f"Watcher-[{view}]-{path}"

    def run(self):
        if "\\" not in self.path:
            return
        root_name, subkey = self.path.split("\\", 1)
        if root_name not in ROOTS:
            return

        root = ROOTS[root_name]
        access_mask = get_access_mask(view=self.view, write=False)

        while not self.stop_event.is_set():
            try:
                # Open key handle
                h_key = winreg.OpenKey(root, subkey, 0, access_mask)
            except (FileNotFoundError, PermissionError):
                # If key doesn't exist yet, wait 3 seconds and retry
                if self.stop_event.wait(3.0):
                    break
                continue
            except Exception as e:
                logger.debug(f"Could not open key {self.path}: {e}")
                if self.stop_event.wait(5.0):
                    break
                continue

            # Create an auto-reset Win32 event handle
            h_event = win32event.CreateEvent(None, 0, 0, None)
            try:
                # Register native notification
                # pywin32 signature: RegNotifyChangeKeyValue(hKey, bWatchSubtree, dwNotifyFilter, hEvent, fAsynchronous)
                win32api.RegNotifyChangeKeyValue(
                    h_key.handle,
                    self.recursive,
                    NOTIFY_FLAGS,
                    h_event,
                    True
                )

                # Block waiting for either change event or stop event (check every 1000ms)
                while not self.stop_event.is_set():
                    result = win32event.WaitForSingleObject(h_event, 1000)
                    if result == win32event.WAIT_OBJECT_0:
                        # Change notification triggered!
                        try:
                            self.callback(self.path, self.view)
                        except Exception as cb_err:
                            logger.error(f"Callback error on {self.path}: {cb_err}")

                        # Re-arm notification
                        win32api.RegNotifyChangeKeyValue(
                            h_key.handle,
                            self.recursive,
                            NOTIFY_FLAGS,
                            h_event,
                            True
                        )
                    elif result == win32event.WAIT_TIMEOUT:
                        continue
                    else:
                        break
            except Exception as loop_err:
                logger.debug(f"Notification loop error on {self.path}: {loop_err}")
                time.sleep(1.0)
            finally:
                try:
                    win32api.CloseHandle(h_event)
                except Exception:
                    pass
                try:
                    h_key.Close()
                except Exception:
                    pass

class RealtimeRegistryEngine:
    """
    Manages concurrent watcher threads across all monitored registry locations
    and provides zero-latency notification dispatch.
    """
    def __init__(self, locations_config: List[Dict[str, Any]], on_change_callback: Callable[[str, str], None]):
        self.locations_config = locations_config
        self.on_change_callback = on_change_callback
        self.stop_event = threading.Event()
        self.threads: List[RegistryWatcherThread] = []

    def start(self):
        """Spawns watcher threads for all configured paths and views."""
        self.stop_event.clear()
        self.threads = []

        for loc in self.locations_config:
            path = loc["path"]
            recursive = loc.get("recursive", False)
            views = loc.get("views", ["64"])

            for view in views:
                watcher = RegistryWatcherThread(
                    path=path,
                    view=view,
                    recursive=recursive,
                    callback=self.on_change_callback,
                    stop_event=self.stop_event
                )
                watcher.start()
                self.threads.append(watcher)

        logger.info(f"Started {len(self.threads)} real-time registry watcher threads.")

    def stop(self):
        """Stops all watcher threads cleanly."""
        self.stop_event.set()
        for t in self.threads:
            t.join(timeout=1.5)
        self.threads = []
        logger.info("Realtime registry engine stopped.")
