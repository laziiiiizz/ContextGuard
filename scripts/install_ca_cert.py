"""Adds the CA certificate to your own Windows certificate store
(CurrentUser), so browsers trust ContextGuard. No admin rights needed, and
Chrome, Edge, Opera and Brave all use this store.

Firefox uses its own store: import ca_store/mitmproxy-ca-cert.cer there by
hand (Settings > Privacy & Security > Certificates > View Certificates >
Import).
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from proxy.ca_provisioning import STORE_DIR, ensure_provisioned

CERT_FILENAME = 'mitmproxy-ca-cert.cer'


def install() -> None:
    ensure_provisioned()  # guarantees the .cer file exists even on a first-ever run
    cert_path = STORE_DIR / CERT_FILENAME
    if not cert_path.exists():
        raise FileNotFoundError(f'{cert_path} not found even after provisioning -- something is wrong.')
    subprocess.run(
        ['certutil', '-user', '-addstore', '-f', 'Root', str(cert_path)],
        check=True, capture_output=True, text=True,
    )


def _local_cert_serial() -> str:
    """Serial number of ca_store's own current CA cert, in the same hex text
    form certutil prints it in a store listing -- lets is_installed() compare
    like-for-like without needing to parse the .cer file's DER/PEM encoding
    itself."""
    result = subprocess.run(
        ['certutil', '-dump', str(STORE_DIR / CERT_FILENAME)],
        capture_output=True, text=True, check=True,
    )
    for line in result.stdout.splitlines():
        if line.strip().startswith('Serial Number:'):
            return line.split(':', 1)[1].strip()
    raise ValueError(f'could not find a Serial Number in certutil -dump output for '
                      f'{STORE_DIR / CERT_FILENAME}')


def is_installed() -> bool:
    """True only if THIS install's current CA is trusted, matched by its
    serial number. Checking only for "a certificate named mitmproxy" would be
    fooled by an old one left behind, and the real one would never get
    trusted."""
    ensure_provisioned()  # guarantees ca_store's own cert exists so its serial can be read
    serial = _local_cert_serial()
    result = subprocess.run(
        ['certutil', '-user', '-store', 'Root'],
        capture_output=True, text=True,
    )
    return serial.lower() in result.stdout.lower()


def main() -> None:
    if is_installed():
        print('[ContextGuard] CA certificate already trusted (CurrentUser store) -- nothing to do.')
        return
    install()
    print('[ContextGuard] CA certificate installed into your CurrentUser Trusted Root store -- '
          'no admin rights needed. Works for Chrome/Edge/Opera/Brave immediately. '
          'Firefox users: it keeps its own certificate store -- import '
          f'{STORE_DIR / CERT_FILENAME} manually via about:preferences#privacy > '
          'Certificates > View Certificates > Import.')


if __name__ == '__main__':
    main()
