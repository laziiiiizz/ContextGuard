import json
import winreg

import pytest

from proxy import system_proxy


class FakeKey:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


@pytest.fixture
def fake_registry(monkeypatch, tmp_path):
    """In-memory stand-in for HKCU\\...\\Internet Settings -- never touches
    the real Windows registry. store maps value-name -> (value, reg_type)."""
    store = {}

    def fake_open_key(hive, path, reserved=0, access=0):
        return FakeKey(store)

    def fake_query_value_ex(key, name):
        if name not in key.store:
            raise FileNotFoundError(name)
        return key.store[name]

    def fake_set_value_ex(key, name, reserved, type_, value):
        key.store[name] = (value, type_)

    monkeypatch.setattr(winreg, 'OpenKey', fake_open_key)
    monkeypatch.setattr(winreg, 'QueryValueEx', fake_query_value_ex)
    monkeypatch.setattr(winreg, 'SetValueEx', fake_set_value_ex)
    monkeypatch.setattr(system_proxy, '_refresh_windows_proxy_settings', lambda: None)
    monkeypatch.setattr(system_proxy, 'STATE_FILE', tmp_path / '.system_proxy_state.json')
    return store


def test_enable_points_os_at_this_proxy(fake_registry):
    system_proxy.enable(host='127.0.0.1', port='8080')
    assert fake_registry['ProxyEnable'] == (1, winreg.REG_DWORD)
    assert fake_registry['ProxyServer'] == ('127.0.0.1:8080', winreg.REG_SZ)


def test_enable_saves_prior_state_before_overwriting(fake_registry):
    system_proxy.enable()
    saved = json.loads(system_proxy.STATE_FILE.read_text())
    assert saved == {'ProxyEnable': 0, 'ProxyServer': None}


def test_enable_warns_when_proxy_override_bypasses_a_watched_host(fake_registry, capsys):
    # Real finding from an external security review: ProxyOverride is a
    # semicolon-separated bypass list -- a matching host never routes
    # through this proxy at all, regardless of ProxyServer. A pre-existing
    # entry (left by a VPN, a corporate tool, or the user) would silently
    # exempt a watched host with no warning anywhere -- a permanent,
    # invisible hole in the watchlist.
    fake_registry['ProxyOverride'] = ('*.openai.com;localhost', winreg.REG_SZ)
    system_proxy.enable()
    out = capsys.readouterr().out
    assert 'WARNING' in out
    assert 'openai.com' in out


def test_enable_warns_on_a_blanket_wildcard_override(fake_registry, capsys):
    fake_registry['ProxyOverride'] = ('*', winreg.REG_SZ)
    system_proxy.enable()
    out = capsys.readouterr().out
    assert 'WARNING' in out
    assert '"*"' in out


def test_enable_does_not_warn_for_an_unrelated_override(fake_registry, capsys):
    fake_registry['ProxyOverride'] = ('localhost;127.*;<local>', winreg.REG_SZ)
    system_proxy.enable()
    assert 'WARNING' not in capsys.readouterr().out


def test_enable_does_not_warn_when_proxy_override_is_absent(fake_registry, capsys):
    system_proxy.enable()  # fake_registry has no ProxyOverride key at all
    assert 'WARNING' not in capsys.readouterr().out


def test_disable_restores_a_real_prior_proxy_across_a_full_cycle(fake_registry):
    # Regression test for the actual reason enable() saves state instead of
    # just always disabling on cleanup: a user with a real corporate/VPN
    # proxy already configured before ever running this tool must get that
    # exact setting back, not have it silently clobbered.
    fake_registry['ProxyEnable'] = (1, winreg.REG_DWORD)
    fake_registry['ProxyServer'] = ('corp-proxy.internal:3128', winreg.REG_SZ)

    system_proxy.enable(host='127.0.0.1', port='8080')
    assert fake_registry['ProxyServer'] == ('127.0.0.1:8080', winreg.REG_SZ)

    system_proxy.disable()
    assert fake_registry['ProxyEnable'] == (1, winreg.REG_DWORD)
    assert fake_registry['ProxyServer'] == ('corp-proxy.internal:3128', winreg.REG_SZ)


def test_enable_does_not_snapshot_its_own_leftover_state(fake_registry):
    # Regression test for a real, confirmed-live bug: if a prior session
    # was force-killed instead of gracefully quit (bypassing disable()), the
    # registry is left pointed at OUR OWN port with nothing listening. A
    # fresh enable() call would then read that as "the real previous
    # state," snapshot it, and a later graceful disable() would faithfully
    # restore back to that exact stuck-on-a-dead-port state -- confirmed
    # live via this precise sequence (force-kill, relaunch, graceful quit)
    # leaving real browsing broken. enable() must recognize its own port
    # already being set and treat that as "no real previous proxy" instead.
    fake_registry['ProxyEnable'] = (1, winreg.REG_DWORD)
    fake_registry['ProxyServer'] = ('127.0.0.1:8080', winreg.REG_SZ)  # leftover from a force-kill

    system_proxy.enable(host='127.0.0.1', port='8080')
    saved = json.loads(system_proxy.STATE_FILE.read_text())
    assert saved == {'ProxyEnable': 0, 'ProxyServer': None}

    system_proxy.disable()
    assert fake_registry['ProxyEnable'] == (0, winreg.REG_DWORD)


def test_disable_deletes_state_file_after_restoring(fake_registry):
    system_proxy.enable()
    assert system_proxy.STATE_FILE.exists()
    system_proxy.disable()
    assert not system_proxy.STATE_FILE.exists()


def test_disable_without_prior_enable_falls_back_to_turning_proxy_off(fake_registry):
    # Regression test for the real bug this whole module exists to fix:
    # the proxy process dying (Ctrl+C, crash) with no saved state must never
    # leave the OS proxy setting untouched/on -- confirmed live, this is
    # exactly what broke all browsing until manually fixed in Settings.
    fake_registry['ProxyEnable'] = (1, winreg.REG_DWORD)
    fake_registry['ProxyServer'] = ('127.0.0.1:8080', winreg.REG_SZ)

    system_proxy.disable()
    assert fake_registry['ProxyEnable'] == (0, winreg.REG_DWORD)


def test_disable_never_raises_on_registry_error(fake_registry, monkeypatch, capsys):
    # disable() is called from atexit/signal-handler cleanup paths -- an
    # uncaught exception there would mask the real shutdown while leaving
    # the OS proxy setting in exactly the broken state this module exists to
    # prevent, so this contract must hold under a real registry failure too.
    def boom(*args, **kwargs):
        raise OSError('simulated registry access failure')

    monkeypatch.setattr(winreg, 'OpenKey', boom)
    system_proxy.disable()  # must not raise
    assert 'warning' in capsys.readouterr().out.lower()


def test_enable_and_disable_are_noop_off_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(system_proxy.sys, 'platform', 'linux')
    monkeypatch.setattr(system_proxy, 'STATE_FILE', tmp_path / '.system_proxy_state.json')
    system_proxy.enable()
    system_proxy.disable()
    assert not system_proxy.STATE_FILE.exists()
