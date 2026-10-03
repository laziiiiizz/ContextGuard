import threading
from datetime import datetime, timedelta, timezone

import pytest

from engine.alias_vault import AliasVault


@pytest.fixture
def vault(tmp_path, monkeypatch):
    fake_store = {}
    monkeypatch.setattr('engine.alias_vault.keyring.get_password',
                         lambda service, key: fake_store.get((service, key)))
    monkeypatch.setattr('engine.alias_vault.keyring.set_password',
                         lambda service, key, value: fake_store.__setitem__((service, key), value))
    return AliasVault(db_path=str(tmp_path / 'test_vault.db'))


def test_get_or_create_is_idempotent_for_same_value(vault):
    token1 = vault.get_or_create('sess_1', 'secret-value-123', 'secret.api_key')
    token2 = vault.get_or_create('sess_1', 'secret-value-123', 'secret.api_key')
    assert token1 == token2


def test_get_or_create_isolates_sessions(vault):
    token1 = vault.get_or_create('sess_1', 'secret-value-123', 'secret.api_key')
    token2 = vault.get_or_create('sess_2', 'secret-value-123', 'secret.api_key')
    assert vault.reveal('sess_1', token1) == 'secret-value-123'
    assert vault.reveal('sess_2', token2) == 'secret-value-123'


def test_reveal_roundtrips_real_value(vault):
    token = vault.get_or_create('sess_1', 'super-secret', 'secret.api_key')
    assert vault.reveal('sess_1', token) == 'super-secret'


def test_reveal_unknown_token_returns_none(vault):
    assert vault.reveal('sess_1', 'NOPE_99') is None


def test_reveal_wrong_session_returns_none(vault):
    token = vault.get_or_create('sess_1', 'super-secret', 'secret.api_key')
    assert vault.reveal('sess_2', token) is None


def test_encrypted_value_never_stored_as_plaintext(vault, tmp_path):
    vault.get_or_create('sess_1', 'super-secret-plaintext', 'secret.api_key')
    raw_db_bytes = (tmp_path / 'test_vault.db').read_bytes()
    assert b'super-secret-plaintext' not in raw_db_bytes


def test_usable_from_a_different_thread_than_it_was_created_in(vault):
    vault.get_or_create('sess_1', 'cross-thread-value', 'secret.api_key')
    results = {}

    def read_from_other_thread():
        try:
            results['recent'] = vault.list_recent()
            results['reveal'] = vault.reveal('sess_1', vault.list_recent()[0][1])
        except Exception as exc:
            results['error'] = exc

    t = threading.Thread(target=read_from_other_thread)
    t.start()
    t.join()

    assert 'error' not in results, f'cross-thread access failed: {results.get("error")}'
    assert results['reveal'] == 'cross-thread-value'


def test_concurrent_get_or_create_with_distinct_values_is_race_free(vault):
    """Regression test: stress-testing the pre-lock implementation with 40 concurrent
    threads found real corruption, not a theoretical race -- 27/40 calls raised raw
    sqlite3 exceptions (InterfaceError/SystemError/TypeError) and 10 of the 13 that
    "succeeded" returned a token that decrypted to a DIFFERENT thread's secret value
    (actual cross-request secret leakage). self._lock in AliasVault fixes this."""
    n = 60
    results, errors = {}, {}
    barrier = threading.Barrier(n)

    def worker(i):
        try:
            barrier.wait()
            results[i] = vault.get_or_create('sess_race', f'secret-value-{i}', 'secret.api_key')
        except Exception as exc:
            errors[i] = exc

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f'{len(errors)} threads raised: {list(errors.values())[:3]}'
    assert len(results) == n
    assert len(set(results.values())) == n, 'duplicate alias tokens issued for distinct values'
    for i, token in results.items():
        assert vault.reveal('sess_race', token) == f'secret-value-{i}', (
            f'worker {i} got token {token} which decrypts to a different value -- secret leakage')


def test_concurrent_get_or_create_with_same_value_is_idempotent(vault):
    """Same real value hit concurrently by many threads must collapse to exactly one
    row and one token -- not one row per thread, and not a duplicate-token collision."""
    n = 30
    results, errors = {}, {}
    barrier = threading.Barrier(n)

    def worker(i):
        try:
            barrier.wait()
            results[i] = vault.get_or_create('sess_dup', 'the-same-secret', 'secret.api_key')
        except Exception as exc:
            errors[i] = exc

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f'{len(errors)} threads raised: {list(errors.values())[:3]}'
    assert len(set(results.values())) == 1, 'same value produced more than one distinct token'
    row_count = vault._conn.execute(
        'SELECT COUNT(*) FROM aliases WHERE session_id = ?', ('sess_dup',)
    ).fetchone()[0]
    assert row_count == 1, f'expected exactly 1 row for {n} concurrent identical inserts, got {row_count}'


def test_reused_value_refreshes_ttl_so_reveal_keeps_working(vault):
    # Regression test for a real bug: a value that keeps reappearing (e.g.
    # sitting in a client's conversation history, resent on every request)
    # kept returning the SAME token from get_or_create() -- masking still
    # worked -- but reveal() permanently returned "expired" for it the
    # moment its ORIGINAL creation time crossed the TTL, even for an
    # occurrence that was just freshly masked moments earlier. Fixed with a
    # sliding-window TTL: reuse refreshes created_at, so reveal() keeps
    # working for as long as the value keeps reappearing, while preserving
    # the documented guarantee that the same real value always maps to the
    # same alias token in a session.
    token1 = vault.get_or_create('sess_1', 'john@acme.com', 'pii.email')

    vault._conn.execute(
        'UPDATE aliases SET created_at = ? WHERE session_id = ? AND alias_token = ?',
        ((datetime.now(timezone.utc) - timedelta(hours=25)).isoformat(), 'sess_1', token1),
    )
    vault._conn.commit()
    assert vault.reveal('sess_1', token1) is None  # aged past the 24h default TTL

    token2 = vault.get_or_create('sess_1', 'john@acme.com', 'pii.email')
    assert token2 == token1, 'reuse must not mint a new token for the same value'
    assert vault.reveal('sess_1', token2) == 'john@acme.com', 'reuse must refresh the TTL'


def test_value_that_stops_reappearing_still_genuinely_expires(vault):
    # The sliding-window fix must not accidentally keep every alias alive
    # forever -- it should still expire DEFAULT_TTL_HOURS after its LAST
    # use, once reuse actually stops.
    token = vault.get_or_create('sess_1', 'john@acme.com', 'pii.email')
    vault._conn.execute(
        'UPDATE aliases SET created_at = ? WHERE session_id = ? AND alias_token = ?',
        ((datetime.now(timezone.utc) - timedelta(hours=25)).isoformat(), 'sess_1', token),
    )
    vault._conn.commit()
    assert vault.reveal('sess_1', token) is None


def test_list_recent_never_exposes_encrypted_bytes(vault):
    vault.get_or_create('sess_1', 'secret-value', 'secret.api_key')
    rows = vault.list_recent()
    assert len(rows) == 1
    session_id, alias_token, category, created_at, ttl_hours = rows[0]
    assert session_id == 'sess_1'
    assert category == 'secret.api_key'
    assert alias_token.startswith('API_KEY_')
