import pytest

from telemetry import logger as telemetry_logger


class _FakeRunningProcess:
    """Minimal Popen stand-in that reports itself as still running --
    start_proxy() now calls .poll() right after Popen() to catch a
    near-instant crash (see _STARTUP_VERIFY_TIMEOUT_SECONDS's own comment
    in tray/app.py), so any fake process used in these tests needs a real
    poll() that returns None (still alive), not just any object."""
    def poll(self):
        return None

    def terminate(self):
        pass

    def wait(self, timeout=None):
        pass


class _FakeCrashedProcess:
    """Reports itself as already exited from the very first poll() call --
    simulates mitmdump dying near-instantly (e.g. the port is already taken
    by something else), or having died mid-session by the time something
    (the watchdog, on_toggle's self-heal) next checks. terminate()/wait()
    are safe no-ops here, same as calling them on a real already-exited
    Popen object -- stop_proxy() always calls both unconditionally."""
    def poll(self):
        return 1  # a real exit code, i.e. "already exited"

    def terminate(self):
        pass

    def wait(self, timeout=None):
        pass


@pytest.fixture(autouse=True)
def reset_state(monkeypatch, tmp_path):
    import tray.app as tray_app
    # Never let these tests touch the real Windows registry -- start_proxy()/
    # stop_proxy() call system_proxy.enable()/disable() for real otherwise,
    # which would actually flip this machine's system proxy setting on/off
    # while running pytest (confirmed: the happy-path test below would leave
    # the real proxy turned ON afterward with no mock in place).
    monkeypatch.setattr(tray_app.system_proxy, 'enable', lambda *a, **k: None)
    monkeypatch.setattr(tray_app.system_proxy, 'disable', lambda: None)
    # Never let these tests write accounting events into the REAL
    # telemetry.db either, now that start_proxy()/stop_proxy()/stop_all() do.
    monkeypatch.setattr(telemetry_logger, 'DB_PATH', str(tmp_path / 'test_telemetry.db'))
    tray_app.state = {'proxy': None, 'dashboard': None, 'proxy_confdir': None}
    tray_app._control_state = {'icon': None, 'on_quit_extra': None}
    yield
    tray_app.state = {'proxy': None, 'dashboard': None, 'proxy_confdir': None}
    tray_app._control_state = {'icon': None, 'on_quit_extra': None}


def test_start_proxy_does_not_crash_when_provisioning_fails(monkeypatch, capsys):
    # Regression test for a real, reachable crash: main() calls start_proxy()
    # directly, with no try/except of its own, before icon.run() ever runs.
    # provision_runtime_confdir() can genuinely raise (confirmed live: the CA
    # keyring entry lost/mismatched against the already-encrypted ca_store/
    # files -- Credential Manager cleared, or the repo copied to a new
    # machine without the keyring entry -- raises a real
    # cryptography.exceptions.InvalidTag). Before this fix, that exception
    # was NOT inside start_proxy()'s try/except (only the Popen call was),
    # so it propagated uncaught out of main() -- the tray icon never
    # appeared at all, silently (no console at all when launched via
    # pythonw.exe per the documented Task Scheduler setup).
    import tray.app as tray_app

    def boom():
        raise RuntimeError('simulated CA provisioning failure (e.g. InvalidTag)')

    monkeypatch.setattr(tray_app, 'provision_runtime_confdir', boom)

    tray_app.start_proxy()  # must not raise

    assert tray_app.state['proxy'] is None
    assert tray_app.state['proxy_confdir'] is None
    assert 'failed to start the proxy' in capsys.readouterr().out


def test_start_proxy_cleans_up_confdir_when_popen_fails_after_provisioning(monkeypatch, capsys):
    # If provisioning SUCCEEDS (confdir now holds the real decrypted
    # plaintext CA key) and Popen fails afterward, the confdir must still be
    # cleaned up -- not left behind leaking the plaintext key.
    import tray.app as tray_app

    cleaned_up = []
    monkeypatch.setattr(tray_app, 'provision_runtime_confdir', lambda: '/fake/confdir')
    monkeypatch.setattr(tray_app, 'cleanup_runtime_confdir', lambda path: cleaned_up.append(path))

    def boom_popen(*args, **kwargs):
        raise FileNotFoundError('simulated mitmdump.exe missing')

    monkeypatch.setattr(tray_app.subprocess, 'Popen', boom_popen)

    tray_app.start_proxy()  # must not raise

    assert tray_app.state['proxy'] is None
    assert cleaned_up == ['/fake/confdir']
    assert 'failed to start the proxy' in capsys.readouterr().out


def test_start_proxy_happy_path_sets_state(monkeypatch):
    import tray.app as tray_app

    fake_proc = _FakeRunningProcess()
    monkeypatch.setattr(tray_app, 'provision_runtime_confdir', lambda: '/fake/confdir')
    monkeypatch.setattr(tray_app.subprocess, 'Popen', lambda *a, **k: fake_proc)

    tray_app.start_proxy()

    assert tray_app.state['proxy'] is fake_proc
    assert tray_app.state['proxy_confdir'] == '/fake/confdir'


def test_start_proxy_detects_an_immediate_crash_and_cleans_up(monkeypatch, capsys):
    # Real finding from an external security review: Popen() succeeding only
    # means the process LAUNCHED, not that mitmdump actually bound the port.
    # Before this fix, a near-instant crash (e.g. the port already in use)
    # left state['proxy'] as a live-looking-but-dead Popen object forever --
    # every "is protection active" surface (tray icon, /status, dashboard)
    # kept reporting Active with nothing actually running, while the system
    # proxy registry setting was already pointed at a dead port.
    import tray.app as tray_app
    cleaned_up = []
    monkeypatch.setattr(tray_app, 'provision_runtime_confdir', lambda: '/fake/confdir')
    monkeypatch.setattr(tray_app, 'cleanup_runtime_confdir', lambda path: cleaned_up.append(path))
    monkeypatch.setattr(tray_app.subprocess, 'Popen', lambda *a, **k: _FakeCrashedProcess())

    tray_app.start_proxy()

    assert tray_app.state['proxy'] is None
    assert tray_app.state['proxy_confdir'] is None
    assert cleaned_up == ['/fake/confdir']
    assert 'exited immediately' in capsys.readouterr().out


def test_start_proxy_does_not_log_a_resume_event_after_an_immediate_crash(monkeypatch):
    import tray.app as tray_app
    monkeypatch.setattr(tray_app, 'provision_runtime_confdir', lambda: '/fake/confdir')
    monkeypatch.setattr(tray_app, 'cleanup_runtime_confdir', lambda path: None)
    monkeypatch.setattr(tray_app.subprocess, 'Popen', lambda *a, **k: _FakeCrashedProcess())

    tray_app.start_proxy()

    events = telemetry_logger.recent_events()
    assert not any(e[4] == 'resume' for e in events)


def test_start_proxy_self_heals_a_stale_dead_reference_from_a_mid_session_crash(monkeypatch):
    # Real finding from an independent review of the round-21 security
    # fixes: if mitmdump crashed WELL AFTER a successful start (an AV/EDR
    # kill, a bug, a manual Task Manager kill -- not the near-instant crash
    # the test above already covers), state['proxy'] was left as a stale
    # non-None dead Popen object, and start_proxy()'s own `if state['proxy']
    # is None:` guard treated a Resume click as a no-op -- silently doing
    # nothing, even though the tray icon correctly showed "Paused". Confirms
    # start_proxy() now cleans up the OLD stale confdir first, then actually
    # starts a fresh proxy, rather than leaking the old plaintext-CA-key
    # temp directory by re-provisioning a new one on top of it.
    import tray.app as tray_app
    cleaned_up = []
    monkeypatch.setattr(tray_app, 'cleanup_runtime_confdir', lambda path: cleaned_up.append(path))
    monkeypatch.setattr(tray_app, 'provision_runtime_confdir', lambda: '/fresh/confdir')
    monkeypatch.setattr(tray_app.subprocess, 'Popen', lambda *a, **k: _FakeRunningProcess())

    tray_app.state['proxy'] = _FakeCrashedProcess()
    tray_app.state['proxy_confdir'] = '/stale/confdir'

    tray_app.start_proxy()

    assert cleaned_up == ['/stale/confdir']  # the OLD confdir was cleaned up, not leaked
    assert tray_app.state['proxy_confdir'] == '/fresh/confdir'  # a genuinely NEW proxy started
    assert tray_app._proxy_process_is_alive() is True


def test_on_toggle_starts_proxy_after_a_mid_session_crash_not_stop(monkeypatch):
    # The user-visible half of the same finding: a single tray-menu click
    # after a mid-session crash must actually restart protection, not
    # silently call stop_proxy() on an already-dead process.
    import tray.app as tray_app
    calls = []
    monkeypatch.setattr(tray_app, 'start_proxy', lambda: calls.append('start'))
    monkeypatch.setattr(tray_app, 'stop_proxy', lambda: calls.append('stop'))
    monkeypatch.setattr(tray_app, '_sync_icon_to_state', lambda icon: None)

    tray_app.state['proxy'] = _FakeCrashedProcess()
    tray_app.on_toggle(icon=None, item=None)

    assert calls == ['start']


def test_proxy_process_is_alive_reflects_real_liveness(monkeypatch):
    import tray.app as tray_app
    tray_app.state['proxy'] = None
    assert tray_app._proxy_process_is_alive() is False

    tray_app.state['proxy'] = _FakeRunningProcess()
    assert tray_app._proxy_process_is_alive() is True

    tray_app.state['proxy'] = _FakeCrashedProcess()
    assert tray_app._proxy_process_is_alive() is False


def test_start_proxy_logs_a_resume_accounting_event(monkeypatch):
    # Accounting gap closed per an external security review: before this,
    # nothing recorded when protection turned on/off or by what path (tray
    # menu vs the HTTP control server) -- "was my protection silently
    # paused?" was genuinely unanswerable from telemetry.db.
    import tray.app as tray_app
    monkeypatch.setattr(tray_app, 'provision_runtime_confdir', lambda: '/fake/confdir')
    monkeypatch.setattr(tray_app.subprocess, 'Popen', lambda *a, **k: _FakeRunningProcess())

    tray_app.start_proxy()

    events = telemetry_logger.recent_events()
    assert any(e[4] == 'resume' for e in events)


def test_stop_proxy_logs_a_pause_accounting_event(monkeypatch):
    import tray.app as tray_app
    fake_proc = _FakeRunningProcess()
    tray_app.state['proxy'] = fake_proc
    tray_app.state['proxy_confdir'] = '/fake/confdir'
    monkeypatch.setattr(tray_app, 'cleanup_runtime_confdir', lambda path: None)

    tray_app.stop_proxy()

    events = telemetry_logger.recent_events()
    assert any(e[4] == 'pause' for e in events)


def test_stop_all_logs_a_quit_accounting_event(monkeypatch):
    import tray.app as tray_app
    monkeypatch.setattr(tray_app, 'stop_proxy', lambda: None)

    tray_app.stop_all()

    events = telemetry_logger.recent_events()
    assert any(e[4] == 'quit' for e in events)


def test_control_status_rejects_non_ascii_token_without_crashing(monkeypatch):
    # Regression test for a real bug, same class as dashboard/server.py's
    # identical fix: hmac.compare_digest() raises TypeError outright on a
    # non-ASCII str, and a header can carry arbitrary Unicode -- confirmed
    # this previously produced an unhandled 500, not a clean 401. Uses the
    # header now, not a query string -- the control server is header-only
    # (see _require_control_token's own comment for why).
    import tray.app as tray_app
    monkeypatch.setattr(tray_app, 'get_or_create_control_token', lambda: 'a-real-token')
    tray_app.control_app.testing = True
    client = tray_app.control_app.test_client()
    resp = client.get('/status', headers={'X-ContextGuard-Token': 'é'})
    assert resp.status_code == 401


def test_start_proxy_binds_loopback_only_not_the_whole_lan(monkeypatch):
    # Regression test for a real, confirmed-live finding: mitmproxy's own
    # default listen_host is '' (all interfaces), so with no explicit
    # override this proxy silently binds 0.0.0.0 -- on any shared network
    # (coffee shop, dorm, office, a compromised LAN device) anyone else on
    # that network could point their own browser at this machine's IP:8080
    # and both browse through it AND reach every other 127.0.0.1-only
    # service on this machine, including this tool's own dashboard/control
    # server. A local privacy tool silently opening the whole machine to the
    # LAN is exactly backwards -- must always bind loopback only, with
    # block_private=true as defense-in-depth on top of that.
    import tray.app as tray_app

    captured_args = []
    monkeypatch.setattr(tray_app, 'provision_runtime_confdir', lambda: '/fake/confdir')

    def fake_popen(args, **kwargs):
        captured_args.append(args)
        return _FakeRunningProcess()

    monkeypatch.setattr(tray_app.subprocess, 'Popen', fake_popen)

    tray_app.start_proxy()

    args = captured_args[0]
    assert '--listen-host' in args
    assert args[args.index('--listen-host') + 1] == '127.0.0.1'
    assert 'block_private=true' in args


def test_dashboard_process_is_alive_reflects_real_liveness():
    import tray.app as tray_app
    tray_app.state['dashboard'] = None
    assert tray_app._dashboard_process_is_alive() is False

    tray_app.state['dashboard'] = _FakeRunningProcess()
    assert tray_app._dashboard_process_is_alive() is True

    tray_app.state['dashboard'] = _FakeCrashedProcess()
    assert tray_app._dashboard_process_is_alive() is False


def test_start_dashboard_self_heals_a_stale_dead_reference(monkeypatch):
    # Same reasoning as start_proxy()'s identical fix: an ungraceful crash
    # (port 5050 taken by a leftover zombie dashboard process, or a
    # squatter) must not leave state['dashboard'] pointing at a dead process
    # forever, silently blocking a real relaunch.
    import tray.app as tray_app
    tray_app.state['dashboard'] = _FakeCrashedProcess()

    fresh = _FakeRunningProcess()
    monkeypatch.setattr(tray_app.subprocess, 'Popen', lambda *a, **k: fresh)

    tray_app.start_dashboard()

    assert tray_app.state['dashboard'] is fresh


def test_start_dashboard_detects_an_immediate_crash_and_does_not_set_state(monkeypatch, capsys):
    # Real finding from an external security review: on_open_dashboard()
    # used to open the browser with the real dashboard token unconditionally,
    # with no check that this process's OWN dashboard is actually the thing
    # listening on port 5050. If the dashboard subprocess dies immediately
    # (port already in use -- a leftover zombie, or a local port-squatter
    # racing to bind it first), state['dashboard'] must NOT look like a live
    # process, or on_open_dashboard()'s check can never catch it.
    import tray.app as tray_app
    monkeypatch.setattr(tray_app.subprocess, 'Popen', lambda *a, **k: _FakeCrashedProcess())

    tray_app.start_dashboard()

    assert tray_app.state['dashboard'] is None
    assert 'port 5050 already in use' in capsys.readouterr().out


def test_on_open_dashboard_refuses_to_leak_token_when_dashboard_cannot_start(monkeypatch):
    # The actual fix for the "port-race token theft" gap: if our own
    # dashboard process isn't (and can't be made) alive, the real dashboard
    # token must never be handed to whatever else is listening on port 5050.
    import tray.app as tray_app
    monkeypatch.setattr(tray_app, '_dashboard_process_is_alive', lambda: False)
    monkeypatch.setattr(tray_app, 'start_dashboard', lambda: None)  # self-heal attempt also fails
    browser_calls = []
    monkeypatch.setattr(tray_app.webbrowser, 'open', lambda url: browser_calls.append(url))
    notify_calls = []
    monkeypatch.setattr(tray_app, 'notify', lambda title, message: notify_calls.append(message))

    tray_app.on_open_dashboard(icon=None, item=None)

    assert browser_calls == []  # the real token must never be sent anywhere in this state
    assert len(notify_calls) == 1


def test_on_open_dashboard_opens_browser_with_token_when_dashboard_is_alive(monkeypatch):
    import tray.app as tray_app
    monkeypatch.setattr(tray_app, '_dashboard_process_is_alive', lambda: True)
    monkeypatch.setattr(tray_app, 'get_or_create_dashboard_token', lambda: 'real-dashboard-token')
    browser_calls = []
    monkeypatch.setattr(tray_app.webbrowser, 'open', lambda url: browser_calls.append(url))

    tray_app.on_open_dashboard(icon=None, item=None)

    assert browser_calls == ['http://127.0.0.1:5050/auth?token=real-dashboard-token']


def test_start_control_server_handles_port_already_in_use(monkeypatch):
    # Real finding from an external security review: the old code's
    # control_app.run(...) bound its socket INSIDE a bare daemon thread, so a
    # port conflict raised OSError there and vanished silently (Python just
    # prints the traceback and lets the thread die) -- nothing here ever
    # found out, and the dashboard would go on sending the real control
    # token to whatever actually won that port. make_server() now binds
    # synchronously in the CALLING thread, so a real conflict (simulated here
    # with an actual competing socket, not a mock) must be visible here.
    import socket
    import tray.app as tray_app

    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(('127.0.0.1', tray_app.CONTROL_PORT))
    blocker.listen(1)
    try:
        notify_calls = []
        monkeypatch.setattr(tray_app, 'notify', lambda title, message: notify_calls.append(message))

        result = tray_app.start_control_server(icon=None)

        assert result is None
        assert len(notify_calls) == 1
    finally:
        blocker.close()


def test_proxy_watchdog_recovers_from_an_unnoticed_mid_session_crash(monkeypatch):
    # Real, live user report: mitmdump can die mid-session (AV/EDR, a crash,
    # anything) with nobody around to click Pause/Resume afterward --
    # system_proxy.py's own docstring already documented this exact failure
    # mode (ALL browsing breaks, not just watched hosts, since Windows has
    # nowhere to send traffic once the proxy setting points at a dead port)
    # but nothing before this actually watched for it happening
    # spontaneously; self-heal only ever ran the NEXT time something called
    # start_proxy() again. This is the fix: a background watchdog notices on
    # its own and restores normal browsing automatically.
    import tray.app as tray_app
    tray_app.state['proxy'] = _FakeCrashedProcess()
    tray_app.state['proxy_confdir'] = '/fake/confdir'
    monkeypatch.setattr(tray_app, 'cleanup_runtime_confdir', lambda path: None)
    disable_calls = []
    monkeypatch.setattr(tray_app.system_proxy, 'disable', lambda: disable_calls.append(True))
    notify_calls = []
    monkeypatch.setattr(tray_app, 'notify', lambda title, message: notify_calls.append(message))

    tray_app._check_proxy_watchdog_once()

    assert tray_app.state['proxy'] is None  # browsing restored, not left pointed at a dead port
    assert disable_calls == [True]
    assert len(notify_calls) == 1

    events = telemetry_logger.recent_events()
    # Distinct from an ordinary user-initiated 'pause' -- this was an
    # unexpected crash, not a deliberate Pause click, and the accounting
    # trail should say so rather than mislabeling it.
    assert any(e[4] == 'crash_recovered' for e in events)


def test_proxy_watchdog_does_nothing_when_the_proxy_is_healthy(monkeypatch):
    import tray.app as tray_app
    tray_app.state['proxy'] = _FakeRunningProcess()
    disable_calls = []
    monkeypatch.setattr(tray_app.system_proxy, 'disable', lambda: disable_calls.append(True))
    notify_calls = []
    monkeypatch.setattr(tray_app, 'notify', lambda title, message: notify_calls.append(message))

    tray_app._check_proxy_watchdog_once()

    assert tray_app.state['proxy'] is not None  # untouched -- nothing was wrong
    assert disable_calls == []
    assert notify_calls == []


def test_proxy_watchdog_does_nothing_when_the_proxy_was_never_started(monkeypatch):
    import tray.app as tray_app
    tray_app.state['proxy'] = None
    notify_calls = []
    monkeypatch.setattr(tray_app, 'notify', lambda title, message: notify_calls.append(message))

    tray_app._check_proxy_watchdog_once()  # must not raise on a None state either

    assert notify_calls == []


def test_is_another_instance_running_reflects_a_real_bound_port():
    # Real, live-diagnosed root cause fix: a second ContextGuard launch used
    # to proceed anyway and could silently corrupt the real system proxy
    # setting (see the function's own docstring). Uses a real competing
    # socket, not a mock, since this is exactly what a second real launch
    # would encounter.
    import socket
    import tray.app as tray_app

    assert tray_app.is_another_instance_running() is False

    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(('127.0.0.1', tray_app.CONTROL_PORT))
    blocker.listen(1)
    try:
        assert tray_app.is_another_instance_running() is True
    finally:
        blocker.close()

    assert tray_app.is_another_instance_running() is False  # released again after closing


def test_on_reset_ca_certificate_regenerates_and_reinstalls(monkeypatch):
    # Real-world precedent: Fiddler's own troubleshooting docs provide an
    # explicit "Reset Certificate" action as the standard recovery path when
    # a client's trust store and the proxy's actual CA have drifted apart --
    # automatic on-launch detection doesn't catch every case (a corrupted
    # ca_store file, antivirus removing the Trust Root entry, anything).
    import tray.app as tray_app
    reset_calls = []
    monkeypatch.setattr(tray_app, 'reset_ca', lambda: reset_calls.append(True))
    install_calls = []
    monkeypatch.setattr(tray_app, 'install_ca_cert', lambda: install_calls.append(True))
    notify_calls = []
    monkeypatch.setattr(tray_app, 'notify', lambda title, message: notify_calls.append(message))
    tray_app.state['proxy'] = None  # not active -- must not try to stop/restart a proxy that isn't running

    tray_app.on_reset_ca_certificate(icon=None, item=None)

    assert reset_calls == [True]
    assert install_calls == [True]
    assert len(notify_calls) == 1
    assert 'restart your browser' in notify_calls[0].lower()


def test_on_reset_ca_certificate_restarts_the_proxy_if_it_was_active(monkeypatch):
    import tray.app as tray_app
    monkeypatch.setattr(tray_app, 'reset_ca', lambda: None)
    monkeypatch.setattr(tray_app, 'install_ca_cert', lambda: None)
    monkeypatch.setattr(tray_app, 'notify', lambda title, message: None)
    tray_app.state['proxy'] = _FakeRunningProcess()
    stop_calls = []
    start_calls = []
    monkeypatch.setattr(tray_app, 'stop_proxy', lambda: stop_calls.append(True))
    monkeypatch.setattr(tray_app, 'start_proxy', lambda: start_calls.append(True))

    tray_app.on_reset_ca_certificate(icon=None, item=None)

    assert stop_calls == [True]
    assert start_calls == [True]


def test_on_reset_ca_certificate_notifies_and_stops_on_install_failure(monkeypatch):
    import tray.app as tray_app
    monkeypatch.setattr(tray_app, 'reset_ca', lambda: None)

    def boom():
        raise RuntimeError('certutil failed')
    monkeypatch.setattr(tray_app, 'install_ca_cert', boom)
    notify_calls = []
    monkeypatch.setattr(tray_app, 'notify', lambda title, message: notify_calls.append(message))
    tray_app.state['proxy'] = None
    start_calls = []
    monkeypatch.setattr(tray_app, 'start_proxy', lambda: start_calls.append(True))

    tray_app.on_reset_ca_certificate(icon=None, item=None)  # must not raise

    assert len(notify_calls) == 1
    assert start_calls == []  # was never active, so must not have been (re)started


def test_tray_icon_is_green_when_active_and_gray_when_paused():
    import tray.app as tray_app
    active = tray_app.make_icon_image(True)
    paused = tray_app.make_icon_image(False)
    assert active.size == paused.size == (64, 64)
    # Left edge of the ring, vertically centered: solid mark color.
    assert active.getpixel((10, 32)) == tray_app.ICON_GREEN
    assert paused.getpixel((10, 32)) == tray_app.ICON_GRAY
    # The gap of the C, on the right, stays transparent.
    assert active.getpixel((58, 32))[3] == 0


def test_committed_icon_file_has_every_windows_size():
    from PIL import Image

    from proxy.paths import get_app_root
    icon = Image.open(get_app_root() / 'assets' / 'icon.ico')
    assert {16, 32, 48, 256} <= {width for width, _ in icon.info['sizes']}


def test_exit_safety_net_only_restores_the_proxy_when_it_is_still_enabled(monkeypatch, tmp_path):
    import tray.app as tray_app
    calls = []
    monkeypatch.setattr(tray_app.system_proxy, 'disable', lambda: calls.append(True))
    state_file = tmp_path / '.system_proxy_state.json'
    monkeypatch.setattr(tray_app.system_proxy, 'STATE_FILE', state_file)

    tray_app.restore_system_proxy_if_still_enabled()  # already restored by Pause/Quit
    assert calls == []

    state_file.write_text('{}')  # the app died while the proxy was still on
    tray_app.restore_system_proxy_if_still_enabled()
    assert calls == [True]
