import os

import pytest

from scripts import autostart


@pytest.fixture(autouse=True)
def fake_startup_dir(monkeypatch, tmp_path):
    # Never let these tests touch the real Windows Startup folder.
    monkeypatch.setattr(autostart, 'STARTUP_DIR', str(tmp_path))
    monkeypatch.setattr(autostart, '_pythonw_exe', lambda: str(tmp_path / 'pythonw.exe'))
    (tmp_path / 'pythonw.exe').write_bytes(b'')  # register() checks this exists
    return tmp_path


def test_register_writes_a_hidden_silent_launcher(fake_startup_dir):
    autostart.register()

    launcher = fake_startup_dir / autostart.LAUNCHER_NAME
    assert launcher.exists()
    content = launcher.read_text()
    assert 'WScript.Shell' in content
    assert 'pythonw.exe' in content
    assert 'app.py' in content
    # windowStyle 0 (hidden) and waitOnReturn False -- must never flash a
    # console window or block the Startup sequence waiting for the tray app.
    assert ', 0, False' in content


def test_register_raises_clear_error_when_pythonw_missing(fake_startup_dir):
    os.remove(fake_startup_dir / 'pythonw.exe')

    with pytest.raises(FileNotFoundError, match='pythonw.exe'):
        autostart.register()


def test_register_is_idempotent_overwrites_existing_launcher(fake_startup_dir):
    autostart.register()
    first = (fake_startup_dir / autostart.LAUNCHER_NAME).read_text()
    autostart.register()
    second = (fake_startup_dir / autostart.LAUNCHER_NAME).read_text()
    assert first == second


def test_is_registered_reflects_launcher_file_presence(fake_startup_dir):
    assert autostart.is_registered() is False
    autostart.register()
    assert autostart.is_registered() is True


def test_unregister_removes_the_launcher(fake_startup_dir):
    autostart.register()
    assert autostart.is_registered() is True
    autostart.unregister()
    assert autostart.is_registered() is False


def test_unregister_when_never_registered_does_not_raise(fake_startup_dir):
    autostart.unregister()  # must not raise even if nothing to remove
    assert autostart.is_registered() is False


def test_register_launches_self_directly_when_frozen(fake_startup_dir, monkeypatch):
    # A packaged build IS a standalone, already-windowless executable --
    # no pythonw.exe/venv layer exists to route through at all.
    monkeypatch.setattr(autostart.sys, 'frozen', True, raising=False)
    monkeypatch.setattr(autostart.sys, 'executable', r'C:\Users\example\AppData\Local\ContextGuard\ContextGuard.exe')

    autostart.register()

    content = (fake_startup_dir / autostart.LAUNCHER_NAME).read_text()
    assert 'ContextGuard.exe' in content
    assert 'pythonw.exe' not in content
    assert ', 0, False' in content
