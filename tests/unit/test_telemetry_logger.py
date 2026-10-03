import sqlite3

import pytest

from telemetry import logger


@pytest.fixture(autouse=True)
def isolated_db(monkeypatch, tmp_path):
    # Never let these tests touch the real telemetry.db.
    monkeypatch.setattr(logger, 'DB_PATH', str(tmp_path / 'test_telemetry.db'))


def test_log_event_then_recent_events_round_trips():
    logger.log_event('aws-akia', 'secret.aws_access_token', 'block', 1.2, 'chatgpt.com')
    rows = logger.recent_events()
    assert len(rows) == 1
    assert rows[0][3] == 'secret.aws_access_token'
    assert rows[0][4] == 'block'
    assert rows[0][5] == 'chatgpt.com'


def test_recent_events_orders_newest_first():
    logger.log_event('r1', 'pii.email', 'transform', 0.5, 'claude.ai')
    logger.log_event('r2', 'secret.aws_access_token', 'block', 0.8, 'claude.ai')
    rows = logger.recent_events()
    assert rows[0][4] == 'block'  # logged second, comes back first
    assert rows[1][4] == 'transform'


def test_recent_events_respects_limit():
    for i in range(5):
        logger.log_event(f'r{i}', 'pii.email', 'transform', 0.1, 'claude.ai')
    assert len(logger.recent_events(limit=3)) == 3


def test_event_counts_empty_db():
    counts = logger.event_counts()
    assert counts == {'total': 0, 'by_action': {}}


def test_event_counts_breaks_down_by_action():
    # Regression test for the dashboard's new "how many caught" summary --
    # must group real block/transform/allow actions correctly, not just
    # report a flat total.
    logger.log_event('r1', 'secret.aws_access_token', 'block', 1.0, 'chatgpt.com')
    logger.log_event('r2', 'secret.aws_access_token', 'block', 1.0, 'claude.ai')
    logger.log_event('r3', 'pii.email', 'transform', 0.5, 'claude.ai')

    counts = logger.event_counts()

    assert counts['total'] == 3
    assert counts['by_action'] == {'block': 2, 'transform': 1}


def test_get_conn_enables_wal_mode():
    conn = logger._get_conn()
    try:
        mode = conn.execute('PRAGMA journal_mode').fetchone()[0]
        assert mode.lower() == 'wal'
    finally:
        conn.close()


def test_log_event_never_raises_when_the_db_is_unreachable(monkeypatch, tmp_path):
    # Real finding from an external security review: log_event() is called
    # from inside proxy/addon.py's block/warn branches AFTER flow.response
    # is already set -- if a DB failure raised here, it would propagate up
    # past code that isn't expecting a telemetry write to fail, risking a
    # wedged connection instead of the clean block/warn already decided on.
    def boom(*a, **k):
        raise sqlite3.OperationalError('simulated: database is locked')
    monkeypatch.setattr(logger, '_get_conn', boom)
    monkeypatch.setattr(logger, 'get_writable_data_dir', lambda: tmp_path)

    logger.log_event('r1', 'secret.aws_access_token', 'block', 1.0, 'chatgpt.com')  # must not raise

    fallback = tmp_path / 'telemetry_fallback.log'
    assert fallback.exists()
    content = fallback.read_text(encoding='utf-8')
    assert 'secret.aws_access_token' in content
    assert 'block' in content


def test_log_event_fallback_write_failure_also_does_not_raise(monkeypatch, tmp_path):
    def boom(*a, **k):
        raise sqlite3.OperationalError('simulated: database is locked')
    monkeypatch.setattr(logger, '_get_conn', boom)

    def boom_path():
        raise OSError('simulated: cannot access data dir')
    monkeypatch.setattr(logger, 'get_writable_data_dir', boom_path)

    logger.log_event('r1', 'secret.aws_access_token', 'block', 1.0, 'chatgpt.com')  # must not raise
