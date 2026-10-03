"""Tests notify.confirm_dialog's coalescing logic directly, without ever
opening a real Tkinter window -- _show_dialog() (the actual GUI) is always
mocked here. Before this file existed, this module had ZERO direct unit
coverage: every other test in this project mocks ask_send_anyway() away
entirely (see tests/e2e/test_addon_pipeline.py's own `a` fixture), so the
real coalescing logic added to close a concurrency finding from an external
security review needed its own tests written from scratch."""
import threading
import time

import pytest

from notify import confirm_dialog


@pytest.fixture(autouse=True)
def reset_module_state():
    # This module's coalescing state is global (module-level dicts) --
    # without resetting between tests, a decision cached by one test would
    # leak into the next and make it pass or fail for the wrong reason.
    confirm_dialog._pending_events.clear()
    confirm_dialog._recent_results.clear()
    yield
    confirm_dialog._pending_events.clear()
    confirm_dialog._recent_results.clear()


def test_single_call_shows_the_dialog_and_returns_its_result(monkeypatch):
    monkeypatch.setattr(confirm_dialog, '_show_dialog', lambda category, host, timeout: True)
    assert confirm_dialog.ask_send_anyway('secret.aws_access_token', 'chatgpt.com') is True


def test_dialog_exception_fails_safe_to_false(monkeypatch):
    def boom(category, host, timeout):
        raise RuntimeError('simulated Tkinter failure')
    monkeypatch.setattr(confirm_dialog, '_show_dialog', boom)
    assert confirm_dialog.ask_send_anyway('secret.aws_access_token', 'chatgpt.com') is False


def test_concurrent_calls_for_the_same_key_coalesce_into_one_dialog(monkeypatch):
    # Real finding from an external security review: before coalescing, N
    # simultaneous blocks of the exact same finding each queued behind the
    # dialog lock and then showed their OWN fresh 60-second dialog in turn.
    call_count = []

    def slow_dialog(category, host, timeout):
        call_count.append(1)
        time.sleep(0.2)  # long enough that a second caller would arrive while this is "showing"
        return True

    monkeypatch.setattr(confirm_dialog, '_show_dialog', slow_dialog)

    results = []

    def worker():
        results.append(confirm_dialog.ask_send_anyway('secret.aws_access_token', 'chatgpt.com'))

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert len(call_count) == 1  # only ONE real dialog shown for 5 concurrent identical requests
    assert results == [True] * 5  # every caller got the same (correct) result


def test_concurrent_calls_for_different_keys_each_get_their_own_dialog(monkeypatch):
    call_args = []

    def recording_dialog(category, host, timeout):
        call_args.append((category, host))
        return False

    monkeypatch.setattr(confirm_dialog, '_show_dialog', recording_dialog)

    results = {}

    def worker(category, host):
        results[(category, host)] = confirm_dialog.ask_send_anyway(category, host)

    threads = [
        threading.Thread(target=worker, args=('secret.aws_access_token', 'chatgpt.com')),
        threading.Thread(target=worker, args=('secret.github_pat', 'claude.ai')),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert len(call_args) == 2  # each distinct (category, host) got its own real dialog
    assert set(call_args) == {('secret.aws_access_token', 'chatgpt.com'), ('secret.github_pat', 'claude.ai')}


def test_a_recent_decision_is_reused_without_reprompting(monkeypatch):
    call_count = []
    monkeypatch.setattr(confirm_dialog, '_show_dialog',
                         lambda category, host, timeout: call_count.append(1) or True)

    first = confirm_dialog.ask_send_anyway('secret.aws_access_token', 'chatgpt.com')
    second = confirm_dialog.ask_send_anyway('secret.aws_access_token', 'chatgpt.com')

    assert first is True
    assert second is True
    assert len(call_count) == 1  # the second call reused the first's decision, no new dialog


def test_a_stale_decision_past_the_ttl_prompts_again(monkeypatch):
    monkeypatch.setattr(confirm_dialog, '_RECENT_DECISION_TTL_SECONDS', 0.05)
    call_count = []
    monkeypatch.setattr(confirm_dialog, '_show_dialog',
                         lambda category, host, timeout: call_count.append(1) or True)

    confirm_dialog.ask_send_anyway('secret.aws_access_token', 'chatgpt.com')
    time.sleep(0.1)  # past the (monkeypatched, short) TTL
    confirm_dialog.ask_send_anyway('secret.aws_access_token', 'chatgpt.com')

    assert len(call_count) == 2  # the second call was stale enough to re-prompt


def test_a_different_host_is_not_treated_as_the_same_key(monkeypatch):
    call_count = []
    monkeypatch.setattr(confirm_dialog, '_show_dialog',
                         lambda category, host, timeout: call_count.append(1) or True)

    confirm_dialog.ask_send_anyway('secret.aws_access_token', 'chatgpt.com')
    confirm_dialog.ask_send_anyway('secret.aws_access_token', 'claude.ai')

    assert len(call_count) == 2


def test_stale_recent_results_are_actually_evicted_not_just_ignored(monkeypatch):
    # Real finding from an independent review: _recent_results only ever
    # grew (entries added, never pruned) -- a long-running tray process
    # could accumulate one entry per distinct (category, host) pair for its
    # entire lifetime, an unbounded slow memory leak. This confirms the
    # dict entry is actually DELETED once stale, not merely treated as
    # expired at lookup time while still occupying memory forever.
    monkeypatch.setattr(confirm_dialog, '_RECENT_DECISION_TTL_SECONDS', 0.05)
    monkeypatch.setattr(confirm_dialog, '_show_dialog', lambda category, host, timeout: True)

    confirm_dialog.ask_send_anyway('secret.aws_access_token', 'chatgpt.com')
    assert ('secret.aws_access_token', 'chatgpt.com') in confirm_dialog._recent_results

    time.sleep(0.1)  # past the (monkeypatched, short) TTL
    # A call for a DIFFERENT key triggers the opportunistic sweep that
    # should evict the first key's now-stale entry.
    confirm_dialog.ask_send_anyway('secret.github_pat', 'claude.ai')

    assert ('secret.aws_access_token', 'chatgpt.com') not in confirm_dialog._recent_results
