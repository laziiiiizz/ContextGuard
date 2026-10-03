import pytest

from engine import user_settings
from telemetry import logger as telemetry_logger


@pytest.fixture(autouse=True)
def isolated_user_settings(monkeypatch, tmp_path):
    # A developer's own settings.json (created by using the Settings window
    # while running from source) must never switch detections off in tests.
    monkeypatch.setattr(user_settings, 'settings_path', lambda: tmp_path / 'settings.json')
    monkeypatch.setattr(user_settings, '_cache', {'stamp': None, 'disabled': frozenset()})
    # Nor may tests write their fake events into the project's own telemetry.db.
    monkeypatch.setattr(telemetry_logger, 'DB_PATH', str(tmp_path / 'telemetry.db'))
