import pytest

import tray.app as tray_app
from telemetry import logger as telemetry_logger

TEST_TOKEN = 'test-token-abc123'


def _fake_running_process():
    # control_status()/control_pause()/control_resume() now check real
    # process liveness via _proxy_process_is_alive(), not just non-None --
    # a bare object() has no .poll().
    return type('FakeRunningProcess', (), {'poll': lambda self: None})()


def _auth_header():
    return {'X-ContextGuard-Token': TEST_TOKEN}


@pytest.fixture(autouse=True)
def isolated_control_state(monkeypatch, tmp_path):
    # Same discipline as test_tray_app.py: never let these tests touch the
    # real system proxy, and never let a control-route test actually spawn
    # a real mitmdump/dashboard subprocess -- start_proxy/stop_proxy/
    # stop_all are mocked here to plain state toggles so ONLY the Flask
    # routing/auth/response-shape logic is under test.
    monkeypatch.setattr(tray_app.system_proxy, 'enable', lambda *a, **k: None)
    monkeypatch.setattr(tray_app.system_proxy, 'disable', lambda: None)
    # _require_control_token now reads get_or_create_control_token() fresh
    # on every request (not a cached _control_state value -- see that
    # function's own comment for why: rotation must actually take effect
    # without a restart) -- monkeypatched here so these tests never touch
    # the real OS keyring.
    monkeypatch.setattr(tray_app, 'get_or_create_control_token', lambda: TEST_TOKEN)
    # _require_control_token logs a real 'auth_failed' accounting event on
    # every rejected request -- several tests below deliberately trigger
    # that path, so isolate the DB the same way test_tray_app.py does.
    monkeypatch.setattr(telemetry_logger, 'DB_PATH', str(tmp_path / 'test_telemetry.db'))

    def fake_start_proxy():
        # Needs a real .poll() -- control_status() now checks process
        # liveness via _proxy_process_is_alive(), not just non-None (see
        # tray/app.py's own comment on that function for why).
        tray_app.state['proxy'] = type('FakeRunningProcess', (), {'poll': lambda self: None})()

    def fake_stop_proxy():
        tray_app.state['proxy'] = None

    stop_all_calls = []

    def fake_stop_all():
        fake_stop_proxy()
        stop_all_calls.append(True)

    monkeypatch.setattr(tray_app, 'start_proxy', fake_start_proxy)
    monkeypatch.setattr(tray_app, 'stop_proxy', fake_stop_proxy)
    monkeypatch.setattr(tray_app, 'stop_all', fake_stop_all)

    tray_app.state = {'proxy': None, 'dashboard': None, 'proxy_confdir': None}
    tray_app._control_state = {'icon': None, 'on_quit_extra': None}
    yield stop_all_calls
    tray_app.state = {'proxy': None, 'dashboard': None, 'proxy_confdir': None}
    tray_app._control_state = {'icon': None, 'on_quit_extra': None}


@pytest.fixture
def client():
    tray_app.control_app.testing = True
    return tray_app.control_app.test_client()


def test_status_requires_correct_token(client):
    # Header-only now -- this server never accepts a query-string token at
    # all (a real finding from an external security review: nothing
    # legitimate ever needed to reach this server from a plain URL, so it
    # has zero URL/history exposure now).
    assert client.get('/status').status_code == 401
    assert client.get('/status', headers={'X-ContextGuard-Token': 'wrong'}).status_code == 401
    assert client.get('/status', headers=_auth_header()).status_code == 200


def test_status_via_query_string_is_rejected(client):
    # Confirms the query-string form is genuinely gone, not just
    # deprioritized -- a real token in the URL must still 401.
    resp = client.get(f'/status?token={TEST_TOKEN}')
    assert resp.status_code == 401


def test_status_reports_inactive_when_no_proxy(client):
    resp = client.get('/status', headers=_auth_header())
    assert resp.get_json() == {'active': False}


def test_status_reports_active_when_proxy_running(client):
    tray_app.state['proxy'] = _fake_running_process()
    resp = client.get('/status', headers=_auth_header())
    assert resp.get_json() == {'active': True}


def test_pause_stops_proxy_and_reports_inactive(client):
    tray_app.state['proxy'] = _fake_running_process()
    resp = client.post('/pause', headers=_auth_header())
    assert resp.status_code == 200
    assert resp.get_json() == {'active': False}
    assert tray_app.state['proxy'] is None


def test_resume_starts_proxy_and_reports_active(client):
    resp = client.post('/resume', headers=_auth_header())
    assert resp.status_code == 200
    assert resp.get_json() == {'active': True}
    assert tray_app.state['proxy'] is not None


def test_pause_and_resume_require_token(client):
    assert client.post('/pause').status_code == 401
    assert client.post('/resume').status_code == 401


def test_failed_control_auth_logs_an_accounting_event(client):
    client.post('/pause')  # no token -- rejected
    events = telemetry_logger.recent_events()
    assert any(e[4] == 'auth_failed' for e in events)


def test_quit_calls_stop_all_and_stops_the_icon(client, isolated_control_state):
    stop_all_calls = isolated_control_state

    class FakeIcon:
        def __init__(self):
            self.stopped = False

        def stop(self):
            self.stopped = True

    fake_icon = FakeIcon()
    tray_app._control_state['icon'] = fake_icon

    resp = client.post('/quit', headers=_auth_header())

    assert resp.status_code == 200
    assert stop_all_calls == [True]
    assert fake_icon.stopped is True


def test_quit_calls_on_quit_extra_when_registered(client):
    # Regression test for a real bug: stopping the pystray icon does NOT stop
    # a separate GUI event loop that might also be running (gui/app.py's
    # Tkinter mainloop) -- confirmed live, the whole process stayed running
    # indefinitely after a real /quit call until this hook was added. A
    # caller with its own event loop registers a callback here since this
    # route otherwise has no way to know such a loop exists.
    calls = []
    tray_app._control_state['on_quit_extra'] = lambda: calls.append(True)

    resp = client.post('/quit', headers=_auth_header())

    assert resp.status_code == 200
    assert calls == [True]


def test_quit_does_not_raise_when_on_quit_extra_not_registered(client):
    # Plain tray-only usage (no GUI window) never sets this -- must stay None
    # and be silently skipped, not raise.
    assert tray_app._control_state.get('on_quit_extra') is None
    resp = client.post('/quit', headers=_auth_header())
    assert resp.status_code == 200


def test_quit_requires_token(client):
    assert client.post('/quit').status_code == 401


def test_header_token_is_the_only_accepted_form(client):
    resp = client.get('/status', headers={'X-ContextGuard-Token': TEST_TOKEN})
    assert resp.status_code == 200
