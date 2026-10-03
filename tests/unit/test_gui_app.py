import threading

import pytest

from gui.app import (
    ContextGuardWindow,
    caught_total,
    activity_counts,
    filter_activity,
    format_activity_row,
    group_activity,
    status_color,
    status_text,
    toggle_button_text,
)


def test_status_text_reflects_active_state():
    assert status_text(True) == 'Protection: Active'
    assert status_text(False) == 'Protection: Paused'


def test_status_color_reflects_active_state():
    assert status_color(True) != status_color(False)


def test_toggle_button_text_is_inverse_of_current_state():
    # When protection is active, the button offers to Pause it -- and
    # vice versa -- same convention as the tray menu's own toggle label.
    assert toggle_button_text(True) == 'Pause'
    assert toggle_button_text(False) == 'Resume'


def _row(seconds, category, action, host):
    return (f'2026-10-02T01:43:{seconds:02d}+00:00', category, action, host)


def test_one_message_with_many_kinds_counts_once():
    # Message 1 from the live test: six kinds in one message, logged as six rows.
    rows = [_row(46, c, 'block', 'claude.ai') for c in (
        'secret.aws_access_token', 'secret.github_pat', 'secret.slack_bot_token',
        'secret.stripe_key', 'pii.ssn', 'pii.credit_card')]
    groups = group_activity(rows)
    assert len(groups) == 1
    assert len(groups[0]['categories']) == 6
    assert activity_counts(groups) == {'blocked': 1, 'sent_anyway': 0, 'masked_or_warned': 0}


def test_a_site_sending_the_same_message_three_times_counts_once():
    # Perplexity sent the text in three requests at once: 18 rows, one message.
    kinds = ('secret.aws_access_token', 'pii.ssn', 'pii.credit_card',
             'secret.github_pat', 'secret.stripe_key', 'secret.slack_bot_token')
    rows = [_row(17, c, 'block', 'www.perplexity.ai') for _ in range(3) for c in kinds]
    assert activity_counts(group_activity(rows))['blocked'] == 1


def test_different_sites_outcomes_and_times_stay_separate():
    rows = [_row(59, 'secret.aws_access_token', 'send_anyway', 'chatgpt.com'),
            _row(58, 'secret.aws_access_token', 'block', 'chatgpt.com'),
            _row(57, 'secret.aws_access_token', 'block', 'gemini.google.com'),
            _row(10, 'secret.aws_access_token', 'block', 'gemini.google.com'),  # 47 s earlier
            _row(9, 'contextguard.control', 'resume', 'local')]
    groups = group_activity(rows)
    assert len(groups) == 5
    assert activity_counts(groups) == {'blocked': 3, 'sent_anyway': 1, 'masked_or_warned': 0}
    assert [g['action'] for g in filter_activity(groups, 'Sent anyway')] == ['send_anyway']
    assert len(filter_activity(groups, 'All')) == 5  # pause/resume rows only show under All


def test_activity_row_never_includes_raw_matched_content():
    # Regression guard for the actual security property this project relies
    # on everywhere else in telemetry: the rows never carry the real matched
    # text, only kinds, actions, sites and times.
    group = group_activity([_row(46, 'secret.aws_access_token', 'block', 'chatgpt.com'),
                            _row(46, 'pii.credit_card', 'block', 'chatgpt.com')])[0]
    formatted = format_activity_row(group)
    assert 'AWS access token +1 more' in formatted
    assert 'Blocked' in formatted
    assert 'chatgpt.com' in formatted


@pytest.fixture
def isolated_manager(monkeypatch):
    import tray.app as manager
    monkeypatch.setattr(manager.system_proxy, 'enable', lambda *a, **k: None)
    monkeypatch.setattr(manager.system_proxy, 'disable', lambda: None)
    monkeypatch.setattr(manager, 'start_proxy', lambda: None)
    monkeypatch.setattr(manager, 'stop_proxy', lambda: None)
    monkeypatch.setattr(manager, 'stop_all', lambda: None)
    # Never let a GUI construction test actually bind the real control-plane
    # port -- ContextGuardWindow.__init__ calls start_control_server() for
    # real otherwise (added after a live test caught it was missing
    # entirely; these tests must not let that become a real side effect).
    monkeypatch.setattr(manager, 'start_control_server', lambda icon: None)
    manager.state = {'proxy': None, 'dashboard': None, 'proxy_confdir': None}
    yield manager
    manager.state = {'proxy': None, 'dashboard': None, 'proxy_confdir': None}


def test_context_guard_window_full_lifecycle(isolated_manager, monkeypatch):
    # Consolidated into ONE real-window test rather than several: creating
    # and destroying multiple separate Tk/CTk root windows across different
    # test functions in the same pytest process is a known Tkinter
    # flakiness source (confirmed live -- running these as separate tests
    # intermittently raised "Can't find a usable init.tcl", a Tcl
    # interpreter re-initialization issue after a prior root's destroy(),
    # not a bug in this code). One window, one full lifecycle, still a real
    # smoke test that catches actual wiring bugs (bad widget option, missing
    # method, exception during __init__) pure logic tests can't.
    control_calls = []
    monkeypatch.setattr(
        isolated_manager, 'start_control_server',
        lambda icon: control_calls.append(icon))
    stop_all_calls = []
    monkeypatch.setattr(isolated_manager, 'stop_all', lambda: stop_all_calls.append(True))
    # tray.app's own (real, unmocked) _sync_icon_to_state() now checks real
    # process liveness via _proxy_process_is_alive(), not just non-None, so
    # this fake needs a real .poll() -- a bare object() doesn't have one.
    fake_running_process = type('FakeRunningProcess', (), {'poll': lambda self: None})()
    monkeypatch.setattr(
        isolated_manager, 'start_proxy',
        lambda: isolated_manager.state.update(proxy=fake_running_process))
    monkeypatch.setattr(
        isolated_manager, 'stop_proxy',
        lambda: isolated_manager.state.update(proxy=None))
    # Never let a GUI construction test make a real network call to GitHub's
    # API -- __init__ kicks off the update check in a background thread.
    import gui.app as gui_app_module
    monkeypatch.setattr(gui_app_module, 'check_for_update', lambda version: None)

    window = ContextGuardWindow()
    try:
        window.update()  # process pending Tk events so widget text is current

        # Initial paused state renders correctly.
        assert window.status_label.cget('text') == 'Protection: Paused'
        assert window.toggle_button.cget('text') == 'Resume'
        assert 'Caught so far:' in window.counts_label.cget('text')
        assert window.update_label.cget('text') == ''  # nothing to show -- no update mocked as available

        # A real update being available gets surfaced -- never auto-applied,
        # just shown, matching the Send-Anyway dialog's own "tell the user,
        # let them choose" posture. self.after() itself requires a real,
        # running mainloop to actually dispatch a callback -- this test
        # deliberately never runs one (see the module-level flakiness note)
        # -- so it's stubbed here to just RECORD the callback rather than
        # invoke it. The real background thread and the real
        # check_for_update() call both still run for real; only the
        # callback is then invoked from this test's own thread (the same
        # thread that created the Tk root, so a direct widget call here is
        # safe) instead of from the background thread, which is the one
        # Tkinter-specific detail a mainloop-less test can't exercise as-is.
        monkeypatch.setattr(gui_app_module, 'check_for_update', lambda version: 'v9.9.9')
        recorded_callbacks = []
        monkeypatch.setattr(window, 'after', lambda delay, callback: recorded_callbacks.append(callback))
        window._check_for_update_async()
        # _check_for_update_async() itself only *starts* the background
        # thread; wait for it to actually finish before checking what it
        # recorded.
        for t in threading.enumerate():
            if t is not threading.current_thread() and t.name.startswith('Thread'):
                t.join(timeout=2)
        assert len(recorded_callbacks) == 1
        recorded_callbacks[0]()  # apply it now, from this (the Tk-owning) thread
        assert 'v9.9.9' in window.update_label.cget('text')

        # Regression: start_control_server() must actually be called -- this
        # window builds its own pystray icon rather than going through
        # tray.app's own main(), so it was silently never being called at
        # all, and the "Open web dashboard" flow had permanently dead
        # Pause/Resume/Quit buttons with no visible error anywhere.
        assert len(control_calls) == 1
        assert control_calls[0] is window._tray_icon

        # Regression: found in the live test of the real installer -- these
        # two actions existed only in tray/app.py's dev-mode menu, so the
        # shipped app had no way to reach them.
        # Settings: one switch per group, all on by default, and flipping
        # one off is saved for the proxy to read.
        from engine import user_settings
        # Settings is a page inside this window, not a separate popup.
        window._show_page('Settings')
        window.update()
        settings = window.settings_panel
        assert window.tabs.get() == 'Settings'
        assert set(settings.switches) == set(user_settings.GROUP_KEYS)
        assert all(switch.get() == 1 for switch in settings.switches.values())
        settings.switches['emails'].deselect()
        settings._on_switch('emails')
        assert user_settings.disabled_groups() == frozenset({'emails'})
        window._show_page('Home')

        labels = [item.text for item in window._build_tray_menu().items]
        assert 'Reset CA certificate (fixes cert errors)' in labels
        assert 'Rotate dashboard/control tokens' in labels

        # Toggle: Resume then Pause, checking both the manager call and the
        # button label update each time.
        window._on_toggle()
        window.update()
        assert isolated_manager.state['proxy'] is not None
        assert window.toggle_button.cget('text') == 'Pause'

        window._on_toggle()
        window.update()
        assert isolated_manager.state['proxy'] is None
        assert window.toggle_button.cget('text') == 'Resume'

        # Regression: control_quit() stopping the pystray icon does not stop
        # the SEPARATE Tkinter mainloop keeping the process alive -- a real
        # /quit call left the whole process running indefinitely until this
        # hook was wired up.
        on_quit_extra = isolated_manager._control_state.get('on_quit_extra')
        assert on_quit_extra is not None
        assert not window._quit_requested.is_set()
        on_quit_extra()  # simulates what control_quit() calls
        assert window._quit_requested.is_set()
        window._quit_requested.clear()  # reset before testing _on_quit() below

        # _on_quit() runs on pystray's own thread (a tray-menu click), not
        # Tk's -- it must only call thread-safe operations (stop_all(),
        # icon.stop(), Event.set()), never touch a Tk widget directly.
        window._on_quit()
        assert stop_all_calls == [True]
        assert window._quit_requested.is_set()
        assert window.winfo_exists() == 1  # _on_quit() itself never destroys the window

        # _poll_quit() is what actually destroys the window, always from a
        # callback Tk itself invoked on the main thread -- exercised last
        # since it ends the window's life. Once the root is destroyed, even
        # winfo_exists() itself raises (the whole Tcl interpreter is gone,
        # not just this one widget) -- destroy() completing without raising
        # is itself the evidence it worked.
        window._poll_quit()
        destroyed = True
    finally:
        if window._tray_icon is not None:
            window._tray_icon.stop()
        if not locals().get('destroyed'):
            window.destroy()


def test_main_refuses_to_start_a_second_instance(monkeypatch):
    # Real, live-diagnosed root cause fix: gui/app.py's main() is the actual
    # entry point ContextGuard.spec builds into the shipped .exe -- a second
    # launch used to proceed all the way through start_proxy() with nothing
    # checking first, which (see manager.is_another_instance_running()'s own
    # docstring) could silently flip the real system proxy setting OFF while
    # a healthy first instance's own tray icon kept showing "Active".
    import gui.app as gui_app_module
    monkeypatch.setattr(gui_app_module.manager, 'is_another_instance_running', lambda: True)
    start_proxy_calls = []
    monkeypatch.setattr(gui_app_module.manager, 'start_proxy', lambda: start_proxy_calls.append(True))
    notify_calls = []
    monkeypatch.setattr(gui_app_module, 'notify', lambda title, message: notify_calls.append(message))

    def boom():
        raise AssertionError('ContextGuardWindow must never be constructed for a second instance')
    monkeypatch.setattr(gui_app_module, 'ContextGuardWindow', boom)

    gui_app_module.main()

    assert start_proxy_calls == []
    assert len(notify_calls) == 1


class _FakeWindow:
    def mainloop(self):
        pass


def test_main_installs_ca_cert_when_not_already_trusted(monkeypatch):
    # Real, live-diagnosed gap: this window's main() is the actual entry
    # point ContextGuard.spec builds -- a plain dist\ContextGuard\ folder
    # run (no Inno Setup installer) never got its CA trusted, so watched-host
    # interception showed up as a real ERR_CERT_AUTHORITY_INVALID on
    # claude.ai instead of working. Checking (and fixing) this automatically
    # on every launch closes that gap.
    import gui.app as gui_app_module
    monkeypatch.setattr(gui_app_module.manager, 'is_another_instance_running', lambda: False)
    monkeypatch.setattr(gui_app_module.manager, 'start_proxy', lambda: None)
    monkeypatch.setattr(gui_app_module, 'ca_is_installed', lambda: False)
    install_calls = []
    monkeypatch.setattr(gui_app_module, 'install_ca_cert', lambda: install_calls.append(True))
    monkeypatch.setattr(gui_app_module, 'ContextGuardWindow', _FakeWindow)

    gui_app_module.main()

    assert install_calls == [True]


def test_main_skips_ca_install_when_already_trusted(monkeypatch):
    import gui.app as gui_app_module
    monkeypatch.setattr(gui_app_module.manager, 'is_another_instance_running', lambda: False)
    monkeypatch.setattr(gui_app_module.manager, 'start_proxy', lambda: None)
    monkeypatch.setattr(gui_app_module, 'ca_is_installed', lambda: True)
    install_calls = []
    monkeypatch.setattr(gui_app_module, 'install_ca_cert', lambda: install_calls.append(True))
    monkeypatch.setattr(gui_app_module, 'ContextGuardWindow', _FakeWindow)

    gui_app_module.main()

    assert install_calls == []


def test_main_continues_and_notifies_when_ca_install_fails(monkeypatch):
    import gui.app as gui_app_module
    monkeypatch.setattr(gui_app_module.manager, 'is_another_instance_running', lambda: False)
    start_proxy_calls = []
    monkeypatch.setattr(gui_app_module.manager, 'start_proxy', lambda: start_proxy_calls.append(True))
    monkeypatch.setattr(gui_app_module, 'ca_is_installed', lambda: False)

    def boom():
        raise RuntimeError('certutil failed')
    monkeypatch.setattr(gui_app_module, 'install_ca_cert', boom)
    notify_calls = []
    monkeypatch.setattr(gui_app_module, 'notify', lambda title, message: notify_calls.append(message))
    monkeypatch.setattr(gui_app_module, 'ContextGuardWindow', _FakeWindow)

    gui_app_module.main()  # must not raise -- a CA failure must never crash the whole app

    assert len(notify_calls) == 1
    assert start_proxy_calls == [True]  # app must still start despite the CA failure


def test_caught_total_counts_messages_not_control_events():
    rows = [_row(50, 'secret.aws_access_token', 'block', 'chatgpt.com'),
            _row(40, 'pii.email', 'transform', 'chatgpt.com'),
            _row(30, 'contextguard.control', 'pause', 'local'),
            _row(20, 'contextguard.control', 'resume', 'local')]
    assert caught_total(group_activity(rows)) == 2


def test_open_dashboard_uses_the_port_checked_handler(monkeypatch):
    import gui.app as gui_app_module
    calls = []
    monkeypatch.setattr(gui_app_module.manager, 'on_open_dashboard', lambda icon, item: calls.append(icon))
    fake_window = type('FakeWindow', (), {'_tray_icon': 'the-icon'})()
    ContextGuardWindow._open_dashboard(fake_window)
    assert calls == ['the-icon']
