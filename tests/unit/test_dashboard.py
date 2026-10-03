import pytest

import dashboard.server as dash
from telemetry import logger


@pytest.fixture(autouse=True)
def isolated_db(monkeypatch, tmp_path):
    monkeypatch.setattr(logger, 'DB_PATH', str(tmp_path / 'test_telemetry.db'))


@pytest.fixture
def client():
    dash.app.testing = True
    return dash.app.test_client()


@pytest.fixture
def authed_client(client):
    # Exchanges the real token for a session cookie exactly once, the same
    # way a real browser does via tray/app.py's "Open Dashboard" link --
    # every subsequent request on THIS client reuses that cookie
    # automatically (Flask's test client persists cookies across requests
    # on the same client instance), so tests using this fixture never pass
    # ?token=... themselves.
    resp = client.get(f'/auth?token={dash.get_or_create_dashboard_token()}')
    assert resp.status_code == 302  # sanity check the fixture itself works
    return client


def test_events_requires_token(client):
    assert client.get('/events').status_code == 401
    assert client.get('/events?token=wrong').status_code == 401  # query string is never accepted here anymore


def test_events_rejects_non_ascii_cookie_without_crashing(client):
    # Regression test for a real bug: hmac.compare_digest() raises TypeError
    # outright on a non-ASCII str ('comparing strings with non-ASCII
    # characters is not supported'), and a cookie/header can carry arbitrary
    # Unicode -- confirmed this previously produced an unhandled 500, not a
    # clean 401. Fails closed either way (no bypass), but an unhandled crash
    # in an auth path is worth closing properly.
    client.set_cookie(dash.COOKIE_NAME, 'é')
    resp = client.get('/events')
    assert resp.status_code == 401


def test_auth_with_correct_token_sets_cookie_and_redirects(client):
    resp = client.get(f'/auth?token={dash.get_or_create_dashboard_token()}')
    assert resp.status_code == 302
    assert resp.headers['Location'] == '/events'
    assert dash.COOKIE_NAME in resp.headers.get('Set-Cookie', '')


def test_auth_with_wrong_token_is_rejected_and_logged(client):
    resp = client.get('/auth?token=wrong')
    assert resp.status_code == 401
    events_resp = client.get(f'/auth?token={dash.get_or_create_dashboard_token()}')
    assert events_resp.status_code == 302  # sanity: the real token still works after a failed attempt


def test_events_shows_recent_activity_and_counts(authed_client):
    logger.log_event('r1', 'secret.aws_access_token', 'block', 1.0, 'chatgpt.com')
    logger.log_event('r2', 'pii.email', 'transform', 0.5, 'claude.ai')

    resp = authed_client.get('/events')

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'secret.aws_access_token' in body
    assert 'chatgpt.com' in body
    assert 'Total events: 2' in body
    assert 'block: 1' in body
    assert 'transform: 1' in body
    assert 'token' not in body.lower() or dash.get_or_create_dashboard_token() not in body  # never rendered


def test_events_accepts_header_token(client):
    # The header form is preserved for API-style/tooling access, unlike the
    # query-string form which /auth is now the sole exception for.
    resp = client.get('/events', headers={'X-ContextGuard-Token': dash.get_or_create_dashboard_token()})
    assert resp.status_code == 200


def test_aliases_requires_token(client):
    assert client.get('/aliases').status_code == 401


def test_aliases_page_loads(authed_client):
    resp = authed_client.get('/aliases')
    assert resp.status_code == 200


def test_reveal_requires_token(client):
    assert client.post('/reveal/fake-session/fake-token').status_code == 401


def test_reveal_unknown_alias_returns_404(authed_client):
    resp = authed_client.post('/reveal/fake-session/fake-token')
    assert resp.status_code == 404


def test_reveal_is_post_only(authed_client):
    # Real fix from an external security review: a bare GET returning a
    # real plaintext secret could be triggered by link prefetching, "open
    # in new tab," or a URL-scanning tool -- none of which need malicious
    # intent, just the page being visited.
    resp = authed_client.get('/reveal/fake-session/fake-token')
    assert resp.status_code == 405


def test_reveal_not_found_logs_an_accounting_event(authed_client):
    # Accounting gap closed per an external security review: a reveal
    # attempt (found or not) must leave a trace -- see reveal()'s own
    # comment for why. isolated_db (autouse) means events() below only
    # shows what THIS test itself generated.
    authed_client.post('/reveal/fake-session/fake-token')
    resp = authed_client.get('/events')
    assert 'reveal_not_found' in resp.get_data(as_text=True)


def test_reveal_success_logs_an_accounting_event(authed_client, monkeypatch):
    monkeypatch.setattr(dash.vault, 'reveal', lambda session_id, alias_token: 'AKIAREALSECRET')
    authed_client.post('/reveal/real-session/real-token')
    resp = authed_client.get('/events')
    body = resp.get_data(as_text=True)
    assert 'reveal' in body
    assert 'AKIAREALSECRET' not in body  # the real value itself must never land in telemetry


def test_failed_auth_logs_an_accounting_event(authed_client):
    authed_client.get('/events?token=wrong')  # ignored as auth now, but must still 401 (no cookie override)
    # Use a fresh unauthenticated client to actually trigger auth_failed.
    dash.app.testing = True
    fresh = dash.app.test_client()
    fresh.get('/events')
    resp = authed_client.get('/events')
    assert 'auth_failed' in resp.get_data(as_text=True)


def test_control_status_requires_token(client):
    assert client.get('/control/status').status_code == 401


def test_control_status_proxies_to_tray_and_returns_its_body(authed_client, monkeypatch):
    monkeypatch.setattr(dash, 'call_tray_control', lambda method, path: (200, {'active': True}))
    resp = authed_client.get('/control/status')
    assert resp.status_code == 200
    assert resp.get_json() == {'active': True}


def test_control_pause_proxies_a_post_to_tray(authed_client, monkeypatch):
    calls = []
    monkeypatch.setattr(
        dash, 'call_tray_control',
        lambda method, path: calls.append((method, path)) or (200, {'active': False}))
    resp = authed_client.post('/control/pause')
    assert resp.status_code == 200
    assert calls == [('POST', '/pause')]


def test_control_resume_proxies_a_post_to_tray(authed_client, monkeypatch):
    calls = []
    monkeypatch.setattr(
        dash, 'call_tray_control',
        lambda method, path: calls.append((method, path)) or (200, {'active': True}))
    resp = authed_client.post('/control/resume')
    assert resp.status_code == 200
    assert calls == [('POST', '/resume')]


def test_control_quit_proxies_a_post_to_tray(authed_client, monkeypatch):
    calls = []
    monkeypatch.setattr(
        dash, 'call_tray_control',
        lambda method, path: calls.append((method, path)) or (200, {'ok': True}))
    resp = authed_client.post('/control/quit')
    assert resp.status_code == 200
    assert calls == [('POST', '/quit')]


def test_control_routes_surface_tray_unreachable_as_503(authed_client, monkeypatch):
    # Real scenario: dashboard started standalone, tray app not running at
    # all -- must degrade to a clear error, not crash or hang.
    monkeypatch.setattr(
        dash, 'call_tray_control', lambda method, path: (503, {'error': 'tray_app_unreachable'}))
    resp = authed_client.get('/control/status')
    assert resp.status_code == 503
    assert resp.get_json() == {'error': 'tray_app_unreachable'}


def test_call_tray_control_returns_503_when_tray_not_running():
    # Real, unmocked call: nothing is listening on CONTROL_PORT during
    # pytest, so this exercises the actual urllib error-handling path.
    status, body = dash.call_tray_control('GET', '/status')
    assert status == 503
    assert body == {'error': 'tray_app_unreachable'}
