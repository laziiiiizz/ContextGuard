"""Port number and token helpers for the app's local control server, which
lets the web dashboard's Pause, Resume and Quit buttons work. Kept small so
the dashboard can import it without the window and tray code.

There are two separate tokens:
- DASHBOARD_TOKEN opens the dashboard (port 5050). It ends up in a browser
  cookie, since a person opens the dashboard from a link.
- CONTROL_TOKEN talks to the control server (port 5052) directly. It never
  leaves the app: no cookie, no URL, no web page.
So a leaked dashboard token can't be used to call port 5052 directly.

Tokens are read fresh from the keyring every time, so a rotated token
works at once without a restart."""
import secrets

import keyring
import keyring.errors

CONTROL_PORT = 5052
KEYRING_SERVICE = 'contextguard'
KEYRING_DASHBOARD_TOKEN_NAME = 'dashboard_token'
KEYRING_CONTROL_TOKEN_NAME = 'control_token'


def _get_or_create(name: str) -> str:
    token = keyring.get_password(KEYRING_SERVICE, name)
    if not token:
        token = secrets.token_hex(16)
        keyring.set_password(KEYRING_SERVICE, name, token)
    return token


def get_or_create_dashboard_token() -> str:
    return _get_or_create(KEYRING_DASHBOARD_TOKEN_NAME)


def get_or_create_control_token() -> str:
    return _get_or_create(KEYRING_CONTROL_TOKEN_NAME)


def rotate_dashboard_token() -> str:
    """Makes a new dashboard token. Any open dashboard tab stops working
    and must be opened again from the tray."""
    keyring.delete_password(KEYRING_SERVICE, KEYRING_DASHBOARD_TOKEN_NAME)
    return get_or_create_dashboard_token()


def rotate_control_token() -> str:
    keyring.delete_password(KEYRING_SERVICE, KEYRING_CONTROL_TOKEN_NAME)
    return get_or_create_control_token()
