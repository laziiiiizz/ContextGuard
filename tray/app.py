"""Starts and stops the proxy and the web dashboard, holds the tray menu
actions, and draws the tray icon. The window (gui/app.py) uses all of this.

Also runs a small local control server so the web dashboard's Pause, Resume
and Quit buttons can reach this process (the dashboard is a separate process)."""
import hmac
import math
import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from functools import wraps

import pystray
from flask import Flask, jsonify, request
from PIL import Image, ImageDraw
from werkzeug.serving import make_server

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proxy import system_proxy
from proxy.ca_provisioning import cleanup_runtime_confdir, provision_runtime_confdir, reset_ca
from proxy.control import (
    CONTROL_PORT,
    get_or_create_control_token,
    get_or_create_dashboard_token,
    rotate_control_token,
    rotate_dashboard_token,
)
from proxy.paths import get_app_root
from notify.native import notify
from scripts.install_ca_cert import install as install_ca_cert, is_installed as ca_is_installed
from telemetry.logger import log_event

REPO_ROOT = get_app_root()
ADDON_PATH = str(REPO_ROOT / 'proxy' / 'addon.py')
PROXY_PORT = 8080

# The installed app can't use a separate mitmdump.exe (it only works on the
# machine that built it), so the app starts itself again with a special flag
# and acts as mitmdump (see the start of gui/app.py). From source, the
# project's own mitmdump.exe is used.
if getattr(sys, 'frozen', False):
    MITMDUMP_CMD = [sys.executable, '--run-mitmdump']
    DASHBOARD_CMD = [sys.executable, '--run-dashboard']
else:
    MITMDUMP_CMD = [os.path.join(os.path.dirname(sys.executable), 'mitmdump.exe')]
    DASHBOARD_CMD = [sys.executable, os.path.join('dashboard', 'server.py')]

state = {'proxy': None, 'dashboard': None, 'proxy_confdir': None}
# Set by start_control_server(). `icon` lets a dashboard request update the
# tray icon; on_quit_extra lets the window close itself on a dashboard Quit.
_control_state = {'icon': None, 'on_quit_extra': None}


ICON_GREEN = (46, 160, 67, 255)
ICON_GRAY = (140, 140, 140, 255)
_ICON_TILE = (13, 17, 23, 255)
_ICON_CANVAS = 1024


def draw_logo_mark(color: tuple, size: int) -> Image.Image:
    """The ContextGuard mark: a letter C drawn as an open ring around a
    solid core. Same shape as assets/logo.svg. Drawn large and scaled
    down so the edges stay smooth at tray sizes."""
    clear = (0, 0, 0, 0)
    c = _ICON_CANVAS // 2
    img = Image.new('RGBA', (_ICON_CANVAS, _ICON_CANVAS), clear)
    draw = ImageDraw.Draw(img)
    draw.ellipse((c - 440, c - 440, c + 440, c + 440), fill=color)
    draw.ellipse((c - 270, c - 270, c + 270, c + 270), fill=clear)
    reach = 700
    rise = reach * math.tan(math.radians(33))
    draw.polygon([(c, c), (c + reach, c - rise), (c + reach, c + rise)], fill=clear)
    draw.rounded_rectangle((c - 125, c - 125, c + 125, c + 125), radius=50, fill=color)
    return img.resize((size, size), Image.LANCZOS)


def make_icon_image(active: bool) -> Image.Image:
    return draw_logo_mark(ICON_GREEN if active else ICON_GRAY, 64)  # green = active, gray = paused


def make_app_icon(size: int) -> Image.Image:
    """The exe/installer/window icon: the green mark on a dark rounded
    tile. Small sizes give the mark more of the tile so it stays readable."""
    img = Image.new('RGBA', (_ICON_CANVAS, _ICON_CANVAS), (0, 0, 0, 0))
    ImageDraw.Draw(img).rounded_rectangle(
        (0, 0, _ICON_CANVAS - 1, _ICON_CANVAS - 1), radius=220, fill=_ICON_TILE)
    mark_size = 760 if size <= 32 else 640
    offset = (_ICON_CANVAS - mark_size) // 2
    img.alpha_composite(draw_logo_mark(ICON_GREEN, mark_size), (offset, offset))
    return img.resize((size, size), Image.LANCZOS)


# After starting mitmdump, wait this long to catch it crashing right away
# (for example because port 8080 is taken). Without the check, the app would
# show Active while nothing runs and Windows points at a dead proxy.
_STARTUP_VERIFY_TIMEOUT_SECONDS = 0.4
_STARTUP_VERIFY_POLL_INTERVAL_SECONDS = 0.05

# The dashboard needs longer: it imports Flask and more before it opens its port.
_DASHBOARD_STARTUP_VERIFY_TIMEOUT_SECONDS = 2.0


def _proxy_process_is_alive() -> bool:
    """True only if the proxy process is really running, not just started
    once. After a crash, state['proxy'] still holds the dead process."""
    return state['proxy'] is not None and state['proxy'].poll() is None


def start_proxy() -> None:
    # If the proxy crashed earlier, forget the dead process and delete its
    # temp folder first, or Resume would do nothing and the temp folder
    # (which holds the decrypted CA key) would be left behind.
    if state['proxy'] is not None and not _proxy_process_is_alive():
        state['proxy'] = None
        if state['proxy_confdir'] is not None:
            cleanup_runtime_confdir(state['proxy_confdir'])
            state['proxy_confdir'] = None

    if state['proxy'] is None:
        # Preparing the CA can fail too (for example if the key in Windows
        # Credential Manager was lost), so it sits inside the try as well.
        confdir = None
        try:
            # Point Windows at this proxy first. enable() saves the old proxy
            # setting so it can be put back exactly on stop or failure.
            system_proxy.enable(port=str(PROXY_PORT))
            confdir = provision_runtime_confdir()
            # Listen on 127.0.0.1 only. mitmproxy's default listens on every
            # network card, which would let anyone on the same Wi-Fi use this
            # proxy and reach this PC's local-only services.
            state['proxy'] = subprocess.Popen(
                MITMDUMP_CMD + ['--set', f'confdir={confdir}',
                                 '-s', ADDON_PATH, '-p', str(PROXY_PORT),
                                 '--listen-host', '127.0.0.1',
                                 '--set', 'block_private=true'],
                cwd=str(REPO_ROOT))
        except Exception:
            # Delete the temp folder with the decrypted CA key if it was made.
            if confdir is not None:
                cleanup_runtime_confdir(confdir)
            # Only undo the proxy setting if enable() got far enough to change
            # it, or we would switch off a proxy the user already had.
            if system_proxy.STATE_FILE.exists():
                system_proxy.disable()
            print('[ContextGuard] failed to start the proxy (CA provisioning or mitmdump launch failed)')
            return
        state['proxy_confdir'] = confdir

        deadline = time.monotonic() + _STARTUP_VERIFY_TIMEOUT_SECONDS
        while state['proxy'].poll() is None and time.monotonic() < deadline:
            time.sleep(_STARTUP_VERIFY_POLL_INTERVAL_SECONDS)
        if state['proxy'].poll() is not None:
            # It died right away (port in use?). Clean up the same way.
            state['proxy'] = None
            cleanup_runtime_confdir(confdir)
            state['proxy_confdir'] = None
            if system_proxy.STATE_FILE.exists():
                system_proxy.disable()
            print('[ContextGuard] failed to start the proxy (mitmdump exited immediately -- '
                  'is another process already using this port?)')
            return

        # Logged so the activity log shows when protection was turned on.
        log_event(rule_id=None, category='contextguard.control', action='resume',
                  latency_ms=0.0, destination_host='local')


def stop_proxy(*, _action: str = 'pause') -> None:
    # The watchdog passes a different _action so a crash isn't logged as a Pause.
    if state['proxy'] is not None:
        state['proxy'].terminate()
        try:
            state['proxy'].wait(timeout=5)  # let mitmdump release its file handles
        except subprocess.TimeoutExpired:
            state['proxy'].kill()
            state['proxy'].wait()
        state['proxy'] = None
        cleanup_runtime_confdir(state['proxy_confdir'])
        state['proxy_confdir'] = None
        system_proxy.disable()  # Pause must restore normal browsing immediately, not just stop scanning
        log_event(rule_id=None, category='contextguard.control', action=_action,
                  latency_ms=0.0, destination_host='local')


def restore_system_proxy_if_still_enabled() -> None:
    """Exit-time safety net: if the app dies with the Windows proxy still
    pointed at this (now dead) proxy, all browsing breaks until the setting
    is turned off by hand. Does nothing after a normal Pause or Quit, which
    already restored the setting and removed the state file -- calling
    system_proxy.disable() a second time then would switch off a proxy the
    user had configured before ever running this app."""
    if system_proxy.STATE_FILE.exists():
        system_proxy.disable()


def _dashboard_process_is_alive() -> bool:
    """Same idea as _proxy_process_is_alive(), for the dashboard."""
    return state['dashboard'] is not None and state['dashboard'].poll() is None


def start_dashboard() -> None:
    # Forget a dashboard process that already crashed.
    if state['dashboard'] is not None and not _dashboard_process_is_alive():
        state['dashboard'] = None

    if state['dashboard'] is None:
        proc = subprocess.Popen(DASHBOARD_CMD, cwd=str(REPO_ROOT))
        # If port 5050 is already taken (by a leftover process, or by some
        # other program on purpose), our dashboard exits right away. Catching
        # that here stops on_open_dashboard() from sending the real token to
        # whatever program holds the port.
        deadline = time.monotonic() + _DASHBOARD_STARTUP_VERIFY_TIMEOUT_SECONDS
        while proc.poll() is None and time.monotonic() < deadline:
            time.sleep(_STARTUP_VERIFY_POLL_INTERVAL_SECONDS)
        if proc.poll() is not None:
            print('[ContextGuard] failed to start the dashboard (port 5050 already in use?)')
            return
        state['dashboard'] = proc


def stop_all() -> None:
    stop_proxy()  # logs its own 'pause'; 'quit' is logged separately below
    if state['dashboard'] is not None:
        state['dashboard'].terminate()
        state['dashboard'] = None
    log_event(rule_id=None, category='contextguard.control', action='quit',
              latency_ms=0.0, destination_host='local')


def _sync_icon_to_state(icon) -> None:
    if icon is None:
        return
    icon.icon = make_icon_image(_proxy_process_is_alive())
    icon.title = 'ContextGuard (Active)' if _proxy_process_is_alive() else 'ContextGuard (Paused)'


def on_toggle(icon, item):
    # Checks whether the proxy really runs, so after a crash one click
    # restarts protection instead of "stopping" a dead process.
    if _proxy_process_is_alive():
        stop_proxy()
    else:
        start_proxy()
    _sync_icon_to_state(icon)


def on_open_dashboard(icon, item):
    # Make sure our own dashboard is the one on port 5050 before sending it
    # the real token.
    if not _dashboard_process_is_alive():
        start_dashboard()
    if not _dashboard_process_is_alive():
        notify('ContextGuard', "Couldn't open the dashboard -- its local web server isn't running "
                                '(port 5050 may already be in use by something else). Not opening the '
                                'browser, to avoid sending the real dashboard token to whatever is there.')
        return
    # /auth swaps the token for a cookie and redirects right away, so the
    # token doesn't stay in browser history.
    token = get_or_create_dashboard_token()
    webbrowser.open(f'http://127.0.0.1:5050/auth?token={token}')


def on_rotate_tokens(icon, item):
    # Makes new dashboard and control tokens, in case one leaked (a
    # screenshot, browser history). Takes effect on the next request.
    rotate_dashboard_token()
    rotate_control_token()
    notify('ContextGuard', 'Dashboard and control tokens rotated. Any open dashboard tab will need '
                            'to be reopened via "Open Dashboard".')


def on_reset_ca_certificate(icon, item):
    # Makes a new CA certificate and trusts it again. For when browsers show
    # certificate errors, for example after antivirus removed the old one.
    was_active = _proxy_process_is_alive()
    if was_active:
        stop_proxy()
    reset_ca()
    try:
        install_ca_cert()
    except Exception:
        notify('ContextGuard', "Couldn't install the new CA certificate automatically -- try running "
                                'scripts\\install_ca_cert.py, or reinstall.')
        return
    if was_active:
        start_proxy()
    _sync_icon_to_state(icon)
    # Chrome remembers certificate decisions until it fully restarts, so a
    # page reload is not enough.
    notify('ContextGuard', 'CA certificate reset and re-trusted. Fully restart your browser (not just '
                            'reload the page) for watched sites to work again.')


# --- Control server (dashboard -> this process) ----------------------------
# A small Flask app on its own thread, on 127.0.0.1 only. It has its own
# token, separate from the dashboard's, and only accepts it in a header,
# never in a URL.
control_app = Flask('contextguard_control')


def _require_control_token(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        supplied = request.headers.get('X-ContextGuard-Token', '')
        # Read fresh every time so a rotated token works at once.
        token = get_or_create_control_token()
        # Compare as bytes: compare_digest() raises on non-ASCII text.
        if not hmac.compare_digest(supplied.encode('utf-8', 'surrogateescape'),
                                    token.encode('utf-8')):
            log_event(rule_id=None, category='contextguard.control', action='auth_failed',
                      latency_ms=0.0, destination_host=request.path)
            return jsonify({'error': 'unauthorized'}), 401
        return fn(*args, **kwargs)
    return wrapper


@control_app.route('/status')
@_require_control_token
def control_status():
    return jsonify({'active': _proxy_process_is_alive()})


@control_app.route('/pause', methods=['POST'])
@_require_control_token
def control_pause():
    stop_proxy()
    _sync_icon_to_state(_control_state['icon'])
    return jsonify({'active': _proxy_process_is_alive()})


@control_app.route('/resume', methods=['POST'])
@_require_control_token
def control_resume():
    start_proxy()
    _sync_icon_to_state(_control_state['icon'])
    return jsonify({'active': _proxy_process_is_alive()})


@control_app.route('/quit', methods=['POST'])
@_require_control_token
def control_quit():
    stop_all()
    icon = _control_state['icon']
    if icon is not None:
        icon.stop()
    # Stopping the tray icon does not close the window, so the window's own
    # quit is called too, or the app would keep running.
    on_quit_extra = _control_state.get('on_quit_extra')
    if on_quit_extra is not None:
        on_quit_extra()
    return jsonify({'ok': True})


def start_control_server(icon) -> threading.Thread | None:
    _control_state['icon'] = icon
    # Open the port ourselves first. If werkzeug fails to open it, it exits
    # the whole process (proxy included); this way a taken port only
    # disables the dashboard buttons.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('127.0.0.1', CONTROL_PORT))
        sock.listen(5)
    except OSError:
        sock.close()
        notify('ContextGuard', 'The control-plane server failed to start (port already in use) -- '
                                "the dashboard's Pause/Resume/Quit/Rotate buttons will not work this "
                                'session.')
        print('[ContextGuard] failed to start the control-plane server (port already in use?)')
        return None
    server = make_server('127.0.0.1', CONTROL_PORT, control_app, fd=sock.fileno())
    sock.close()  # werkzeug made its own copy of the socket
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def is_another_instance_running() -> bool:
    """True if ContextGuard is already running (its control port is taken).
    A second copy must stop before starting the proxy: its failed start
    would switch the Windows proxy setting off while the first copy still
    shows Active."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(('127.0.0.1', CONTROL_PORT))
    except OSError:
        return True
    finally:
        probe.close()
    return False


# How often the watchdog checks whether the proxy died on its own (antivirus,
# a crash). If it did, Windows would still point at a dead proxy and all
# browsing would break, so the watchdog turns the proxy setting back off.
_PROXY_WATCHDOG_POLL_INTERVAL_SECONDS = 3.0


def _check_proxy_watchdog_once() -> None:
    """One check, kept separate from the loop so tests can call it."""
    if state['proxy'] is not None and not _proxy_process_is_alive():
        stop_proxy(_action='crash_recovered')
        _sync_icon_to_state(_control_state.get('icon'))
        notify('ContextGuard', 'Protection stopped unexpectedly (the proxy process died) -- normal '
                                'browsing has been restored automatically. Open ContextGuard and '
                                'click Resume to turn protection back on.')


def _proxy_watchdog_loop() -> None:
    while True:
        time.sleep(_PROXY_WATCHDOG_POLL_INTERVAL_SECONDS)
        _check_proxy_watchdog_once()
