"""Encrypts mitmproxy's CA private key at rest; decrypts to a temp confdir only while running."""
import os
import shutil
import tempfile
from pathlib import Path

import keyring
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mitmproxy.certs import CertStore

from proxy.paths import get_writable_data_dir

KEYRING_SERVICE = 'contextguard'
KEYRING_KEY_NAME = 'mitmproxy_ca_key'
BASENAME = 'mitmproxy'  # must match mitmproxy.options.CONF_BASENAME
KEY_SIZE = 2048

REPO_ROOT = get_writable_data_dir()
STORE_DIR = REPO_ROOT / 'ca_store'

SENSITIVE_FILES = [f'{BASENAME}-ca.pem', f'{BASENAME}-ca.p12']
PUBLIC_FILES = [
    f'{BASENAME}-ca-cert.pem', f'{BASENAME}-ca-cert.cer',
    f'{BASENAME}-ca-cert.p12', f'{BASENAME}-dhparam.pem',
]


def _get_or_create_key() -> bytes:
    existing = keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_NAME)
    if existing:
        return bytes.fromhex(existing)
    key = AESGCM.generate_key(bit_length=128)
    keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_NAME, key.hex())
    return key


def ensure_provisioned(store_dir: Path = STORE_DIR) -> None:
    """Generates a fresh CA on first run only, encrypted at rest."""
    if (store_dir / f'{SENSITIVE_FILES[0]}.enc').exists():
        return

    tmp = tempfile.mkdtemp(prefix='contextguard_ca_gen_')
    try:
        CertStore.create_store(Path(tmp), BASENAME, KEY_SIZE)
        store_dir.mkdir(parents=True, exist_ok=True)
        aesgcm = AESGCM(_get_or_create_key())

        for name in SENSITIVE_FILES:
            data = (Path(tmp) / name).read_bytes()
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, data, None)
            (store_dir / f'{name}.enc').write_bytes(nonce + ciphertext)

        for name in PUBLIC_FILES:
            shutil.copy(Path(tmp) / name, store_dir / name)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def provision_runtime_confdir(store_dir: Path = STORE_DIR) -> str:
    """Decrypts the CA into a fresh temp confdir; caller cleans up via cleanup_runtime_confdir."""
    ensure_provisioned(store_dir)
    runtime_dir = tempfile.mkdtemp(prefix='contextguard_ca_run_')
    try:
        aesgcm = AESGCM(_get_or_create_key())

        for name in SENSITIVE_FILES:
            blob = (store_dir / f'{name}.enc').read_bytes()
            nonce, ciphertext = blob[:12], blob[12:]
            data = aesgcm.decrypt(nonce, ciphertext, None)
            (Path(runtime_dir) / name).write_bytes(data)

        for name in PUBLIC_FILES:
            shutil.copy(store_dir / name, Path(runtime_dir) / name)
    except Exception:
        shutil.rmtree(runtime_dir, ignore_errors=True)  # don't leak a partial plaintext key
        raise

    return runtime_dir


def cleanup_runtime_confdir(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)


def reset_ca(store_dir: Path = STORE_DIR) -> None:
    """Deletes the current CA so a fresh one is made next time. For when the
    browser and the proxy no longer agree on the certificate. It doesn't
    remove the old entry from Windows (an old, unused entry is harmless);
    the caller trusts the new CA afterwards."""
    for name in SENSITIVE_FILES:
        (store_dir / f'{name}.enc').unlink(missing_ok=True)
    for name in PUBLIC_FILES:
        (store_dir / name).unlink(missing_ok=True)
