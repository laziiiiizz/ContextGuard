"""The Don't Send / Send Anyway popup. The user decides, since a match can
be a test value; with no answer, the safe choice (Don't Send) wins.

Must run on a worker thread, never the proxy's main loop: it waits up to
`timeout` seconds for a click, which would freeze every other request.
"""
import os
import threading
import time

import customtkinter as ctk

from engine.labels import friendly_category, friendly_host, not_scanned_reason

_DEBUG = os.environ.get('CONTEXTGUARD_DEBUG_LOG_RAW') == '1'


def _debug_log(msg: str) -> None:
    if not _DEBUG:
        return
    try:
        from proxy.paths import get_writable_data_dir
        path = get_writable_data_dir() / 'dialog_debug.log'
        with open(path, 'a', encoding='utf-8') as f:
            f.write(f'{time.time():.3f} {msg}\n')
    except Exception:
        pass

# One popup at a time; different findings wait in line.
_LOCK = threading.Lock()

# Several requests with the SAME finding and site (chat apps resend the whole
# conversation, or two tabs send the same thing) share one popup instead of
# showing one each, one after another. An answer is also reused for a few
# seconds, so the user isn't asked again for something just answered.
_coalesce_lock = threading.Lock()
_pending_events: dict[tuple[str, str], threading.Event] = {}
_recent_results: dict[tuple[str, str], tuple[bool, float]] = {}
_RECENT_DECISION_TTL_SECONDS = 5.0

TIMEOUT_SECONDS = 60.0
SEND_ANYWAY_COLOR = '#8B2020'
SEND_ANYWAY_HOVER = '#6B1818'


def ask_send_anyway(category: str, host: str, timeout: float = TIMEOUT_SECONDS) -> bool:
    """True only after a real "Send Anyway" click. Timeout, closing the
    window or any error count as Don't Send.

    Calls for the same (category, host) share one popup (see above);
    different ones each get their own, one at a time."""
    key = (category, host)
    with _coalesce_lock:
        # Drop old answers so this dictionary doesn't keep growing.
        now = time.monotonic()
        expired = [k for k, (_, ts) in _recent_results.items() if now - ts >= _RECENT_DECISION_TTL_SECONDS]
        for k in expired:
            del _recent_results[k]

        cached = _recent_results.get(key)
        if cached is not None:
            _debug_log(f'ask_send_anyway reusing a recent decision for {key}: {cached[0]}')
            return cached[0]

        existing_event = _pending_events.get(key)
        if existing_event is None:
            event = threading.Event()
            _pending_events[key] = event
            is_leader = True
        else:
            is_leader = False

    if not is_leader:
        _debug_log(f'ask_send_anyway following an existing dialog for {key}')
        # Bounded by the same timeout as the real dialog so a leader that
        # somehow never resolves (a crash, a hang) can't wedge a follower
        # forever either.
        existing_event.wait(timeout=timeout)
        with _coalesce_lock:
            cached = _recent_results.get(key)
        result = cached[0] if cached is not None else False  # leader never resolved in time -- fail safe
        _debug_log(f'ask_send_anyway (follower) returning {result} for {key}')
        return result

    _debug_log(f'ask_send_anyway called, waiting for lock, thread={threading.current_thread().name}')
    try:
        with _LOCK:
            _debug_log('lock acquired')
            try:
                result = _show_dialog(category, host, timeout)
            except Exception as e:
                _debug_log(f'ask_send_anyway EXCEPTION: {type(e).__name__}: {e}')
                result = False  # the dialog itself failing must never turn into an accidental send
    finally:
        with _coalesce_lock:
            _recent_results[key] = (result, time.monotonic())
            event = _pending_events.pop(key)
        event.set()
    _debug_log(f'ask_send_anyway returning {result}')
    return result


def dialog_text(category: str, host: str) -> tuple[str, str, str]:
    """(title, body, hint) for the popup."""
    host = friendly_host(host)
    reason = not_scanned_reason(category)
    if reason:
        return ('This PDF was not checked',
                f'A PDF you are sending to {host} {reason[1]},\n'
                'so ContextGuard could not check it for secrets or personal data.',
                'Double-check it yourself before sending.')
    return ('Possible secret detected',
            f'ContextGuard found what looks like a real {friendly_category(category)}\n'
            f'about to be sent to {host}.',
            "If this is real, sending it could expose it publicly.\n"
            "If it's a false positive, you can send it anyway.")


def _show_dialog(category: str, host: str, timeout: float) -> bool:
    _debug_log(f'_show_dialog START category={category} host={host} timeout={timeout} '
               f'thread={threading.current_thread().name}')
    ctk.set_appearance_mode('system')
    ctk.set_default_color_theme('green')

    root = ctk.CTk()
    root.title('ContextGuard')
    root.resizable(False, False)
    root.attributes('-topmost', True)
    _debug_log('root created')

    def _apply_icon() -> None:
        try:
            from proxy.paths import get_app_root
            root.iconbitmap(str(get_app_root() / 'assets' / 'icon.ico'))
        except Exception:
            pass  # a missing icon must never stop the dialog from showing

    # customtkinter sets its own title-bar icon about 200 ms after the window
    # is created, so ours has to be applied after that.
    root.after(250, _apply_icon)

    result = {'send': False}

    def choose(send: bool, reason: str = 'unknown') -> None:
        _debug_log(f'choose({send}) reason={reason}')
        result['send'] = send
        root.destroy()

    title, body, hint = dialog_text(category, host)
    ctk.CTkLabel(root, text=title, font=('Segoe UI', 16, 'bold')).pack(padx=24, pady=(20, 6))
    ctk.CTkLabel(root, text=body, font=('Segoe UI', 12), justify='center').pack(padx=24, pady=(0, 6))
    ctk.CTkLabel(root, text=hint, font=('Segoe UI', 11), text_color='gray', justify='center').pack(
        padx=24, pady=(0, 16))

    button_row = ctk.CTkFrame(root, fg_color='transparent')
    button_row.pack(pady=(0, 20))
    dont_send_button = ctk.CTkButton(
        button_row, text="Don't Send", width=140,
        command=lambda: choose(False, 'dont_send_button'))
    dont_send_button.pack(side='left', padx=6)
    send_anyway_button = ctk.CTkButton(
        button_row, text='Send Anyway', width=140,
        fg_color=SEND_ANYWAY_COLOR, hover_color=SEND_ANYWAY_HOVER,
        command=lambda: choose(True, 'send_anyway_button'))
    send_anyway_button.pack(side='left', padx=6)

    # Both buttons start disabled for a moment, so a click meant for the
    # site's send button can't land on this popup and count as a choice.
    dont_send_button.configure(state='disabled')
    send_anyway_button.configure(state='disabled')

    def _enable_buttons() -> None:
        dont_send_button.configure(state='normal')
        send_anyway_button.configure(state='normal')
        dont_send_button.focus_set()

    root.after(400, _enable_buttons)

    # Closing the window (the X button) is the same as "Don't Send" -- never
    # leave the underlying request hanging with no decision at all.
    root.protocol('WM_DELETE_WINDOW', lambda: choose(False, 'window_closed'))
    # A no-response timeout also fails safe to "Don't Send" rather than
    # blocking the real request indefinitely if the user is away.
    root.after(int(timeout * 1000), lambda: choose(False, 'timeout'))

    # Enter always means Don't Send, so a stray key press can never send.
    root.bind('<Return>', lambda event: choose(False, 'return_key'))

    root.update_idletasks()
    x = (root.winfo_screenwidth() - root.winfo_width()) // 2
    y = (root.winfo_screenheight() - root.winfo_height()) // 2
    root.geometry(f'+{x}+{y}')

    _debug_log('calling mainloop()')
    root.mainloop()
    _debug_log(f'mainloop() returned, result={result["send"]}')
    return result['send']
