import sys
from pathlib import Path

from proxy.paths import get_app_root, get_writable_data_dir


def test_returns_meipass_when_frozen(monkeypatch):
    monkeypatch.setattr('sys.frozen', True, raising=False)
    monkeypatch.setattr('sys._MEIPASS', r'C:\fake\frozen\root', raising=False)
    assert get_app_root() == Path(r'C:\fake\frozen\root')


def test_returns_repo_root_when_not_frozen(monkeypatch):
    monkeypatch.delattr('sys.frozen', raising=False)
    root = get_app_root()
    # proxy/paths.py lives at <repo_root>/proxy/paths.py
    assert (root / 'proxy' / 'paths.py').exists()
    assert (root / 'requirements.txt').exists()


def test_writable_data_dir_is_exe_parent_when_frozen_not_meipass(monkeypatch):
    # Regression test for a real, confirmed-live bug: writable runtime state
    # (telemetry.db, alias_vault.db, ca_store/, the proxy-restore state file)
    # was resolving via get_app_root(), which in a frozen build is
    # sys._MEIPASS (PyInstaller's `_internal/` bundled-resources directory) --
    # a sibling of the actual install directory, not the install directory
    # itself. Confirmed live: all of it ended up inside `_internal/` on a
    # real installed build instead of next to ContextGuard.exe.
    monkeypatch.setattr('sys.frozen', True, raising=False)
    monkeypatch.setattr('sys._MEIPASS', r'C:\fake\frozen\root\_internal', raising=False)
    monkeypatch.setattr(sys, 'executable', r'C:\fake\frozen\root\ContextGuard.exe')
    assert get_writable_data_dir() == Path(r'C:\fake\frozen\root')


def test_writable_data_dir_matches_app_root_when_not_frozen(monkeypatch):
    monkeypatch.delattr('sys.frozen', raising=False)
    assert get_writable_data_dir() == get_app_root()
