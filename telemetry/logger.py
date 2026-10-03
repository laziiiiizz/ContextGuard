"""Content-free telemetry -- no parameter here can ever carry raw matched text."""
import sqlite3
import uuid
from datetime import datetime, timezone

from proxy.paths import get_writable_data_dir

DB_PATH = str(get_writable_data_dir() / 'telemetry.db')


def _get_conn() -> sqlite3.Connection:
    # The proxy writes and the dashboard reads at the same time. WAL mode lets
    # both happen at once, and the busy timeout waits for a lock instead of
    # failing right away.
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA busy_timeout=5000')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            rule_id TEXT,
            category TEXT NOT NULL,
            action TEXT NOT NULL,
            destination_host TEXT NOT NULL,
            latency_ms REAL NOT NULL,
            policy_version TEXT NOT NULL
        )
    ''')
    return conn


def log_event(rule_id: str, category: str, action: str, latency_ms: float,
              destination_host: str, policy_version: str = '1.0.0') -> None:
    """Never raises: it runs after a request was already blocked or allowed,
    and an error here could leave that connection stuck. If the database
    can't be written, it tries a plain text file, and if that fails too,
    it gives up quietly."""
    try:
        conn = _get_conn()
        try:
            conn.execute(
                'INSERT INTO events (event_id, timestamp, rule_id, category, action, '
                'destination_host, latency_ms, policy_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (str(uuid.uuid4()), datetime.now(timezone.utc).isoformat(), rule_id, category,
                 action, destination_host, latency_ms, policy_version),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        try:
            fallback_path = get_writable_data_dir() / 'telemetry_fallback.log'
            with open(fallback_path, 'a', encoding='utf-8') as f:
                f.write(f'{datetime.now(timezone.utc).isoformat()}\t{category}\t{action}\t'
                         f'{destination_host}\n')
        except Exception:
            pass


def recent_events(limit: int = 50) -> list[tuple]:
    conn = _get_conn()
    rows = conn.execute(
        'SELECT event_id, timestamp, rule_id, category, action, destination_host, latency_ms, '
        'policy_version FROM events ORDER BY timestamp DESC, rowid DESC LIMIT ?', (limit,)
    ).fetchall()
    conn.close()
    return rows


def activity_rows(limit: int | None = None) -> list[tuple]:
    """(timestamp, category, action, destination_host), newest first. The
    window groups these into one entry per message sent."""
    conn = _get_conn()
    sql = ('SELECT timestamp, category, action, destination_host FROM events '
           'ORDER BY timestamp DESC, rowid DESC')
    rows = conn.execute(sql + (' LIMIT ?' if limit else ''), (limit,) if limit else ()).fetchall()
    conn.close()
    return rows


def event_counts() -> dict:
    """Total events plus a per-action breakdown (e.g. block/transform/warn),
    for the dashboard's "how many caught" summary -- content-free, same as
    every other telemetry query here."""
    conn = _get_conn()
    rows = conn.execute('SELECT action, COUNT(*) FROM events GROUP BY action').fetchall()
    conn.close()
    by_action = dict(rows)
    return {'total': sum(by_action.values()), 'by_action': by_action}
