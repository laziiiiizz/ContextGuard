"""Finds the app's folders both when run from source and when installed.
In the installed (PyInstaller) app, bundled files live in `_internal/`,
found through sys._MEIPASS; __file__ can't be trusted there.
"""
import sys
from pathlib import Path


def get_app_root() -> Path:
    if getattr(sys, 'frozen', False):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent.parent


def get_writable_data_dir() -> Path:
    """Where the app writes its own files (telemetry.db, ca_store/, settings).
    Installed: the folder with ContextGuard.exe, not `_internal/`, which holds
    the shipped read-only files. From source: the project folder."""
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).resolve().parent
    return get_app_root()
