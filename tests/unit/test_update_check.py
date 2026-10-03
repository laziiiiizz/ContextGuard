import json
import urllib.error

import pytest

from notify import update_check


class FakeResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode('utf-8')

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_parse_version_handles_normal_semver():
    assert update_check._parse_version('1.2.0') == (1, 2, 0)


def test_parse_version_strips_leading_v():
    assert update_check._parse_version('v1.2.0') == (1, 2, 0)


def test_parse_version_non_numeric_part_does_not_crash():
    # A malformed tag must never crash the comparison -- it just should
    # never look newer than a well-formed current version.
    assert update_check._parse_version('v1.2.0-beta') < update_check._parse_version('1.2.0')


def test_check_for_update_returns_none_when_current_is_latest(monkeypatch):
    monkeypatch.setattr(
        update_check.urllib.request, 'urlopen',
        lambda *a, **k: FakeResponse({'tag_name': 'v1.1.0'}))
    assert update_check.check_for_update('1.1.0') is None


def test_check_for_update_returns_version_when_newer_is_available(monkeypatch):
    monkeypatch.setattr(
        update_check.urllib.request, 'urlopen',
        lambda *a, **k: FakeResponse({'tag_name': 'v1.2.0'}))
    assert update_check.check_for_update('1.1.0') == 'v1.2.0'


def test_check_for_update_returns_none_when_current_is_newer(monkeypatch):
    # e.g. testing a dev build ahead of the last published release.
    monkeypatch.setattr(
        update_check.urllib.request, 'urlopen',
        lambda *a, **k: FakeResponse({'tag_name': 'v1.0.0'}))
    assert update_check.check_for_update('1.1.0') is None


def test_check_for_update_returns_none_on_no_releases_yet(monkeypatch):
    # The real, current, expected state of this project right now -- no
    # GitHub Release has ever been published. Must never surface an error.
    def raise_404(*a, **k):
        raise urllib.error.HTTPError('url', 404, 'Not Found', {}, None)
    monkeypatch.setattr(update_check.urllib.request, 'urlopen', raise_404)
    assert update_check.check_for_update('1.1.0') is None


def test_check_for_update_returns_none_on_network_error(monkeypatch):
    def raise_url_error(*a, **k):
        raise urllib.error.URLError('no network')
    monkeypatch.setattr(update_check.urllib.request, 'urlopen', raise_url_error)
    assert update_check.check_for_update('1.1.0') is None


def test_check_for_update_returns_none_on_malformed_json(monkeypatch):
    class BadResponse:
        def read(self):
            return b'not json'
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
    monkeypatch.setattr(update_check.urllib.request, 'urlopen', lambda *a, **k: BadResponse())
    assert update_check.check_for_update('1.1.0') is None


def test_check_for_update_returns_none_when_tag_name_missing(monkeypatch):
    monkeypatch.setattr(
        update_check.urllib.request, 'urlopen',
        lambda *a, **k: FakeResponse({'some_other_field': 'x'}))
    assert update_check.check_for_update('1.1.0') is None
