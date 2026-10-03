"""The local web dashboard (127.0.0.1 only): events, counts, revealing masked
values, and Pause/Resume/Quit buttons. It is a separate process, so the
buttons call the app's control server over localhost (see proxy/control.py).

The token is used once, at /auth, and swapped for an HttpOnly cookie, so it
never sits in browser history or in page links. Scripts can send it in the
X-ContextGuard-Token header instead."""
import hmac
import json
import os
import sys
import urllib.error
import urllib.request
from functools import wraps

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, redirect, render_template_string, request

from engine.alias_vault import AliasVault
from proxy.control import CONTROL_PORT, get_or_create_control_token, get_or_create_dashboard_token
from telemetry.logger import event_counts, log_event, recent_events

app = Flask(__name__)
vault = AliasVault()

COOKIE_NAME = 'cg_token'

NAV = '<p><a href="/events">Events</a> | <a href="/aliases">Aliases</a></p>'

EVENTS_TEMPLATE = '''
<!doctype html>
<title>ContextGuard Dashboard</title>
{{ nav|safe }}
<h1>ContextGuard</h1>
<p>Protection: <strong id="status">checking...</strong>
  <button onclick="controlAction('pause')">Pause</button>
  <button onclick="controlAction('resume')">Resume</button>
  <button onclick="controlAction('quit')" style="color:#a00">Quit</button>
</p>
<p id="control-error" style="color:#a00"></p>

<h2>Caught so far</h2>
<p>Total events: {{ counts.total }}</p>
<ul>
{% for action, n in counts.by_action.items() %}
<li>{{ action }}: {{ n }}</li>
{% endfor %}
</ul>

<h2>Recent events</h2>
<table border="1" cellpadding="4">
<tr><th>Time</th><th>Category</th><th>Action</th><th>Destination</th><th>Latency (ms)</th></tr>
{% for e in events %}
<tr><td>{{ e[1] }}</td><td>{{ e[3] }}</td><td>{{ e[4] }}</td><td>{{ e[5] }}</td><td>{{ '%.1f'|format(e[6]) }}</td></tr>
{% endfor %}
</table>

<script>
// No token embedded here anymore -- every fetch below relies on the browser
// auto-attaching the HttpOnly session cookie set by /auth, same-origin.
async function refreshStatus() {
    try {
        const r = await fetch('/control/status');
        if (!r.ok) throw new Error('unreachable');
        const data = await r.json();
        document.getElementById('status').textContent = data.active ? 'Active' : 'Paused';
    } catch (e) {
        document.getElementById('status').textContent = 'unknown (tray app not running?)';
    }
}

async function controlAction(action) {
    if (action === 'quit' &&
        !confirm('Quit ContextGuard entirely? This stops the proxy and closes the dashboard.')) {
        return;
    }
    const errEl = document.getElementById('control-error');
    errEl.textContent = '';
    try {
        const r = await fetch(`/control/${action}`, {method: 'POST'});
        if (!r.ok) {
            const body = await r.json().catch(() => ({}));
            errEl.textContent = body.error || `request failed (${r.status})`;
            return;
        }
        if (action === 'quit') {
            document.getElementById('status').textContent = 'stopped';
        } else {
            refreshStatus();
        }
    } catch (e) {
        errEl.textContent = 'tray app unreachable';
    }
}

refreshStatus();
</script>
'''

ALIASES_TEMPLATE = '''
<!doctype html>
<title>ContextGuard Dashboard</title>
{{ nav|safe }}
<h1>Recent aliases</h1>
<table border="1" cellpadding="4">
<tr><th>Created</th><th>Category</th><th>Alias token</th><th></th><th>Revealed value</th></tr>
{% for session_id, alias_token, category, created_at, ttl_hours in aliases %}
<tr>
  <td>{{ created_at }}</td><td>{{ category }}</td><td>{{ alias_token }}</td>
  <td><button onclick="reveal('{{ session_id }}', '{{ alias_token }}', this)">Reveal</button></td>
  <td class="reveal-value"></td>
</tr>
{% endfor %}
</table>

<script>
// A plaintext secret is the single most sensitive thing this dashboard can
// hand out -- unlike the old bare GET link (followable by prefetching, "open
// in new tab," or a screen-recording tool with zero malicious intent needed),
// this is now a POST behind an explicit confirmation, same pattern already
// used for Quit on the events page.
async function reveal(sessionId, aliasToken, button) {
    if (!confirm('Reveal the real plaintext value for this alias?')) return;
    const cell = button.parentElement.nextElementSibling;
    try {
        const r = await fetch(`/reveal/${sessionId}/${aliasToken}`, {method: 'POST'});
        const body = await r.json();
        cell.textContent = r.ok ? body.real_value : (body.error || 'error');
    } catch (e) {
        cell.textContent = 'request failed';
    }
}
</script>
'''


def require_token(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        supplied = request.headers.get('X-ContextGuard-Token') or request.cookies.get(COOKIE_NAME, '')
        # Compare as bytes: compare_digest() raises on non-ASCII text. Read the
        # token fresh so a rotated token works at once.
        if not hmac.compare_digest(supplied.encode('utf-8', 'surrogateescape'),
                                    get_or_create_dashboard_token().encode('utf-8')):
            # Log failed logins (never the attempted token), so guessing
            # attempts leave a trace.
            log_event(rule_id=None, category='contextguard.control', action='auth_failed',
                      latency_ms=0.0, destination_host=request.path)
            return jsonify({'error': 'unauthorized'}), 401
        return fn(*args, **kwargs)
    return wrapper


def call_tray_control(method: str, path: str) -> tuple[int, dict]:
    """Sends one request to the app's control server and returns (status,
    json). Returns a 503 if the app isn't running, so callers never see raw
    network errors. Uses the control token, not the dashboard token."""
    url = f'http://127.0.0.1:{CONTROL_PORT}{path}'
    req = urllib.request.Request(
        url, method=method, headers={'X-ContextGuard-Token': get_or_create_control_token()})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
        except (ValueError, UnicodeDecodeError):
            body = {'error': e.reason}
        return e.code, body
    except (urllib.error.URLError, OSError):
        return 503, {'error': 'tray_app_unreachable'}


@app.route('/auth')
def auth():
    """The only route that accepts the token in the URL. It swaps it for a
    session cookie right away and redirects, so the token appears in one
    short-lived link only."""
    supplied = request.args.get('token', '')
    if not hmac.compare_digest(supplied.encode('utf-8', 'surrogateescape'),
                                get_or_create_dashboard_token().encode('utf-8')):
        log_event(rule_id=None, category='contextguard.control', action='auth_failed',
                  latency_ms=0.0, destination_host=request.path)
        return jsonify({'error': 'unauthorized'}), 401
    response = redirect('/events')
    # Not secure=True: this is plain http on 127.0.0.1, and a Secure cookie
    # would never be sent back. HttpOnly + SameSite=Strict is the protection here.
    response.set_cookie(COOKIE_NAME, supplied, httponly=True, samesite='Strict')
    return response


@app.route('/events')
@require_token
def events():
    return render_template_string(
        EVENTS_TEMPLATE, events=recent_events(), counts=event_counts(), nav=NAV)


@app.route('/aliases')
@require_token
def aliases():
    return render_template_string(ALIASES_TEMPLATE, aliases=vault.list_recent(), nav=NAV)


@app.route('/reveal/<session_id>/<alias_token>', methods=['POST'])
@require_token
def reveal(session_id, alias_token):
    # POST, not GET: link previews, prefetching or extensions open GET links
    # by themselves, and that must never reveal a secret.
    value = vault.reveal(session_id, alias_token)
    # Revealing a secret is logged (never the value itself), so "was my vault
    # read, and when?" can be answered.
    log_event(rule_id=None, category='contextguard.control',
              action='reveal' if value is not None else 'reveal_not_found',
              latency_ms=0.0, destination_host='local')
    if value is None:
        return jsonify({'error': 'not_found_or_expired'}), 404
    return jsonify({'alias_token': alias_token, 'real_value': value})


@app.route('/control/status')
@require_token
def control_status():
    status, body = call_tray_control('GET', '/status')
    return jsonify(body), status


@app.route('/control/pause', methods=['POST'])
@require_token
def control_pause():
    status, body = call_tray_control('POST', '/pause')
    return jsonify(body), status


@app.route('/control/resume', methods=['POST'])
@require_token
def control_resume():
    status, body = call_tray_control('POST', '/resume')
    return jsonify(body), status


@app.route('/control/quit', methods=['POST'])
@require_token
def control_quit():
    status, body = call_tray_control('POST', '/quit')
    return jsonify(body), status


if __name__ == '__main__':
    print(f'[dashboard] open http://127.0.0.1:5050/auth?token={get_or_create_dashboard_token()} '
          'to sign in (or pass the X-ContextGuard-Token header directly for API-style access)')
    app.run(host='127.0.0.1', port=5050, debug=False)
