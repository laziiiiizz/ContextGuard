"""AES-GCM-encrypted alias vault; key lives in the OS credential store, never on disk."""
import hashlib
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import keyring
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from proxy.paths import get_writable_data_dir

KEYRING_SERVICE = 'contextguard'
KEYRING_KEY_NAME = 'alias_vault_key'
DB_PATH = str(get_writable_data_dir() / 'alias_vault.db')
DEFAULT_TTL_HOURS = 24


def _get_or_create_key() -> bytes:
    existing = keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_NAME)
    if existing:
        return bytes.fromhex(existing)
    key = AESGCM.generate_key(bit_length=128)
    keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_NAME, key.hex())
    return key


class AliasVault:
    def __init__(self, db_path: str = DB_PATH):
        self._key = _get_or_create_key()
        self._aesgcm = AESGCM(self._key)
        # The dashboard uses this from several threads. check_same_thread=False
        # only turns off sqlite's check; self._lock makes sure only one thread
        # uses the connection at a time (otherwise one session could get
        # another session's secret back).
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute('''
            CREATE TABLE IF NOT EXISTS aliases (
                session_id TEXT NOT NULL,
                alias_token TEXT NOT NULL,
                value_hash TEXT NOT NULL,
                encrypted_value BLOB NOT NULL,
                nonce BLOB NOT NULL,
                category TEXT NOT NULL,
                created_at TEXT NOT NULL,
                ttl_hours INTEGER NOT NULL,
                PRIMARY KEY (session_id, alias_token)
            )
        ''')
        self._conn.commit()

    def _encrypt(self, value: str) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, value.encode('utf-8'), None)
        return ciphertext, nonce

    def _decrypt(self, ciphertext: bytes, nonce: bytes) -> str:
        return self._aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')

    def get_or_create(self, session_id: str, real_value: str, category: str) -> str:
        value_hash = hashlib.sha256(real_value.encode('utf-8')).hexdigest()
        with self._lock:
            row = self._conn.execute(
                'SELECT alias_token FROM aliases WHERE session_id = ? AND value_hash = ?',
                (session_id, value_hash),
            ).fetchone()
            if row:
                # Restart the expiry clock every time the value is seen again,
                # so a value still being resent in a conversation stays
                # revealable, and the same value keeps the same alias.
                self._conn.execute(
                    'UPDATE aliases SET created_at = ? WHERE session_id = ? AND alias_token = ?',
                    (datetime.now(timezone.utc).isoformat(), session_id, row[0]),
                )
                self._conn.commit()
                return row[0]

            count = self._conn.execute(
                'SELECT COUNT(*) FROM aliases WHERE session_id = ? AND category = ?',
                (session_id, category),
            ).fetchone()[0]
            alias_token = f'{category.split(".")[-1].upper()}_{count + 1}'

            ciphertext, nonce = self._encrypt(real_value)
            self._conn.execute(
                'INSERT INTO aliases (session_id, alias_token, value_hash, encrypted_value, '
                'nonce, category, created_at, ttl_hours) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (session_id, alias_token, value_hash, ciphertext, nonce, category,
                 datetime.now(timezone.utc).isoformat(), DEFAULT_TTL_HOURS),
            )
            self._conn.commit()
            return alias_token

    def reveal(self, session_id: str, alias_token: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                'SELECT encrypted_value, nonce, created_at, ttl_hours FROM aliases '
                'WHERE session_id = ? AND alias_token = ?',
                (session_id, alias_token),
            ).fetchone()
        if row is None:
            return None
        ciphertext, nonce, created_at, ttl_hours = row
        created = datetime.fromisoformat(created_at)
        if datetime.now(timezone.utc) > created + timedelta(hours=ttl_hours):
            return None  # expired
        return self._decrypt(ciphertext, nonce)

    def list_recent(self, limit: int = 50) -> list[tuple]:
        """Metadata only, no encrypted values -- for listing what can be revealed."""
        with self._lock:
            return self._conn.execute(
                'SELECT session_id, alias_token, category, created_at, ttl_hours '
                'FROM aliases ORDER BY created_at DESC LIMIT ?', (limit,)
            ).fetchall()
