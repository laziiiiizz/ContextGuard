"""Turns the Windows proxy setting on when protection starts and back off
when it stops.

enable() first saves the proxy setting the user already had (for example a
work VPN) so disable() can put it back exactly. If the setting stayed
pointed at a proxy that is no longer running, all browsing would break.
Windows only. Neither function raises: disable() runs during shutdown,
where an error would leave the setting in the worse state.
"""
import json
import sys

from proxy.paths import get_writable_data_dir

STATE_FILE = get_writable_data_dir() / '.system_proxy_state.json'
_REG_PATH = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
_INTERNET_OPTION_SETTINGS_CHANGED = 39
_INTERNET_OPTION_REFRESH = 37

# The main watched domains, written here instead of imported from addon.py
# (which would load the whole proxy). Only used for the warning below.
_KNOWN_WATCHED_APEX_DOMAINS = (
    'openai.com', 'chatgpt.com', 'anthropic.com', 'claude.ai',
    'google.com', 'googleapis.com', 'perplexity.ai', 'huggingface.co',
)


def _warn_if_proxy_override_bypasses_a_watched_host(key) -> None:
    """Windows has a "don't use the proxy for these sites" list. If a VPN,
    a work tool or the user put a watched site (or "*") on it, that site is
    never checked. It may be there for a good reason, so this only warns
    and doesn't change it."""
    import winreg
    try:
        override, _ = winreg.QueryValueEx(key, 'ProxyOverride')
    except FileNotFoundError:
        return
    if not override:
        return
    entries = [e.strip().lower() for e in override.split(';') if e.strip()]
    if '*' in entries:
        print('[ContextGuard] WARNING: Windows\' proxy bypass list (ProxyOverride) contains "*", '
              'which exempts ALL traffic from this proxy -- protection may not actually be active. '
              'Check Settings > Network & Internet > Proxy > Manual proxy setup.')
        return
    hit = next((entry for entry in entries
                if any(entry == d or entry.endswith('.' + d) or d in entry
                       for d in _KNOWN_WATCHED_APEX_DOMAINS)), None)
    if hit:
        print(f'[ContextGuard] WARNING: Windows\' proxy bypass list (ProxyOverride) contains '
              f'"{hit}", which may exempt a watched AI host from interception entirely. Check '
              'Settings > Network & Internet > Proxy > Manual proxy setup if this is unexpected.')


def _refresh_windows_proxy_settings() -> None:
    # Tell Windows and the browser about the change now, the same way the
    # Settings app does, instead of after the next sign-in.
    import ctypes
    wininet = ctypes.WinDLL('wininet')
    wininet.InternetSetOptionW(0, _INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
    wininet.InternetSetOptionW(0, _INTERNET_OPTION_REFRESH, 0, 0)


def enable(host: str = '127.0.0.1', port: str = '8080') -> None:
    if sys.platform != 'win32':
        return
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PATH, 0, winreg.KEY_READ) as key:
        try:
            prev_enable, _ = winreg.QueryValueEx(key, 'ProxyEnable')
        except FileNotFoundError:
            prev_enable = 0
        try:
            prev_server, _ = winreg.QueryValueEx(key, 'ProxyServer')
        except FileNotFoundError:
            prev_server = None
        _warn_if_proxy_override_bypasses_a_watched_host(key)

    if prev_server == f'{host}:{port}':
        # Already pointing at our own proxy: left over from a session that was
        # killed instead of closed. Saving that as "the old setting" would make
        # disable() put the broken setting back, so treat it as "no proxy".
        prev_enable, prev_server = 0, None

    STATE_FILE.write_text(json.dumps({'ProxyEnable': prev_enable, 'ProxyServer': prev_server}))

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PATH, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, f'{host}:{port}')

    _refresh_windows_proxy_settings()


def disable() -> None:
    if sys.platform != 'win32':
        return
    import winreg

    try:
        if STATE_FILE.exists():
            state = json.loads(STATE_FILE.read_text())
            prev_enable = state.get('ProxyEnable', 0)
            prev_server = state.get('ProxyServer')
        else:
            # enable() never ran (or its state file is already gone) --
            # turning the proxy off outright is still strictly better than
            # leaving it pointed at a dead port.
            prev_enable, prev_server = 0, None

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PATH, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, prev_enable)
            if prev_server is not None:
                winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, prev_server)

        _refresh_windows_proxy_settings()
    except Exception:
        print('[ContextGuard] warning: could not restore the system proxy setting automatically -- '
              'if browsing is broken, turn the proxy off manually: Settings > Network & Internet > Proxy.')
    finally:
        STATE_FILE.unlink(missing_ok=True)
