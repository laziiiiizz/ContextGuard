"""The ContextGuard app: one window (Home, Activity, Settings) plus a tray
icon. This is what the installer runs.

Starting and stopping the proxy lives in tray/app.py; this file is only the
window on top of it. The web dashboard is still there as an optional
"advanced" view from the tray menu.
"""
import atexit
from datetime import datetime
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The installed app has no console, so sys.stdout/stderr are None. Some code
# (mitmproxy, Flask) writes to them at startup and would crash, so point them
# at "nowhere" instead.
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w')

# The installed app is one exe. To act as mitmdump, the dashboard and so on,
# it starts itself again with one of the flags below. These checks run before
# any window code is imported, so those helper processes stay small.
if len(sys.argv) > 1 and sys.argv[1] == '--run-mitmdump':
    from mitmproxy.tools.main import mitmdump
    sys.exit(mitmdump(sys.argv[2:]))

if len(sys.argv) > 1 and sys.argv[1] == '--run-dashboard':
    import dashboard.server as _dashboard
    _dashboard.app.run(host='127.0.0.1', port=5050, debug=False)
    sys.exit(0)

# Used by the installer (see ContextGuard.iss).
if len(sys.argv) > 1 and sys.argv[1] == '--install-ca-cert':
    from scripts.install_ca_cert import main as _install_ca_cert
    _install_ca_cert()
    sys.exit(0)

# Reads one uploaded PDF in its own process (see engine/pdf_scan.py).
if len(sys.argv) > 1 and sys.argv[1] == '--extract-pdf':
    from engine.pdf_scan import worker_main as _extract_pdf_main
    sys.exit(_extract_pdf_main(sys.argv[2:]))

# Called by the git hooks ContextGuard installs (see gitguard/install.py).
if len(sys.argv) > 1 and sys.argv[1] == '--git-hook':
    from gitguard.hook import main as _git_hook_main
    sys.exit(_git_hook_main(sys.argv[2:]))

# Used by the uninstaller: removes the git hooks setting if it is still ours.
if len(sys.argv) > 1 and sys.argv[1] == '--git-guard-off':
    from gitguard.install import main_off as _git_guard_off
    _git_guard_off()
    sys.exit(0)

if len(sys.argv) > 1 and sys.argv[1] == '--register-autostart':
    from scripts.autostart import main as _autostart_main
    sys.argv = [sys.argv[0], 'register']
    _autostart_main()
    sys.exit(0)

if len(sys.argv) > 1 and sys.argv[1] == '--unregister-autostart':
    from scripts.autostart import main as _autostart_main
    sys.argv = [sys.argv[0], 'unregister']
    _autostart_main()
    sys.exit(0)

if len(sys.argv) > 1 and sys.argv[1] == '--quit-if-running':
    # Used by the uninstaller: asks a running copy to quit the normal way, so
    # the Windows proxy setting is put back. Killing it would leave the
    # setting pointed at a dead proxy. Tries 3 times, since the app may have
    # only just started; gives up quietly if nothing is running.
    import time
    import urllib.error
    import urllib.request

    from proxy.control import CONTROL_PORT, get_or_create_control_token
    token = get_or_create_control_token()  # the control-plane's own token, not the dashboard's
    for attempt in range(3):
        try:
            req = urllib.request.Request(
                f'http://127.0.0.1:{CONTROL_PORT}/quit',
                method='POST', headers={'X-ContextGuard-Token': token})
            urllib.request.urlopen(req, timeout=3)
            break
        except (urllib.error.URLError, OSError):
            if attempt < 2:
                time.sleep(1)
    sys.exit(0)

import customtkinter as ctk
import pystray

import tray.app as manager
from engine import user_settings
from gitguard import install as git_guard
from engine.labels import describe_event, friendly_time
from notify.native import notify
from notify.update_check import check_for_update
from proxy.paths import get_app_root
from scripts.install_ca_cert import install as install_ca_cert, is_installed as ca_is_installed
from telemetry.logger import activity_rows, event_counts
from version import VERSION

ctk.set_appearance_mode('system')
ctk.set_default_color_theme('green')


def status_text(active: bool) -> str:
    return 'Protection: Active' if active else 'Protection: Paused'


def status_color(active: bool) -> str:
    return '#2ea043' if active else '#8c8c8c'  # green / gray, matches make_icon_image()'s palette


def toggle_button_text(active: bool) -> str:
    return 'Pause' if active else 'Resume'


CAUGHT_ACTIONS = ('block', 'send_anyway', 'transform', 'warn')

# One message can log many rows: one per kind of information found in it, and
# some sites (Perplexity) send the same text in several requests at once.
# Rows for the same site and outcome this close together are one message.
SAME_MESSAGE_SECONDS = 10


def group_activity(rows: list) -> list:
    """rows: telemetry.logger.activity_rows() tuples, newest first. Returns
    one dict per message (or per pause/resume/quit), newest first.
    Content-free: only categories, actions, sites and times go in."""
    groups = []
    for timestamp, category, action, host in rows:
        try:
            when = datetime.fromisoformat(timestamp)
        except ValueError:
            continue
        last = groups[-1] if groups else None
        if (last is not None and category != 'contextguard.control'
                and last['category_kind'] == 'detection' and last['action'] == action
                and last['host'] == host
                and (last['when'] - when).total_seconds() <= SAME_MESSAGE_SECONDS):
            if category not in last['categories']:
                last['categories'].append(category)
            continue
        groups.append({'timestamp': timestamp, 'when': when, 'action': action, 'host': host,
                       'categories': [category],
                       'category_kind': 'control' if category == 'contextguard.control' else 'detection'})
    return groups


def activity_counts(groups: list) -> dict:
    detections = [g for g in groups if g['category_kind'] == 'detection']
    return {'blocked': sum(g['action'] == 'block' for g in detections),
            'sent_anyway': sum(g['action'] == 'send_anyway' for g in detections),
            'masked_or_warned': sum(g['action'] in ('transform', 'warn') for g in detections)}


def caught_total(groups: list) -> int:
    """Messages caught. Pause/resume/quit and failed dashboard logins are
    not something the app "caught"."""
    return sum(activity_counts(groups).values())


def format_activity_row(group: dict, now=None) -> str:
    when = friendly_time(group['timestamp'], now)
    what, kind, where = describe_event(group['categories'][0], group['action'], group['host'])
    if not kind:
        return f'{when:<17}{what}'
    extra = len(group['categories']) - 1
    if extra:
        kind = f'{kind[:20]} +{extra} more'
    return f'{when:<17}{what:<13}{kind[:30]:<32}{where}'


ACTIVITY_FILTERS = {
    'All': None,
    'Blocked': ('block',),
    'Sent anyway': ('send_anyway',),
    'Masked or warned': ('transform', 'warn'),
}


def filter_activity(groups: list, name: str) -> list:
    actions = ACTIVITY_FILTERS[name]
    if actions is None:
        return groups
    return [g for g in groups if g['category_kind'] == 'detection' and g['action'] in actions]


# Colour of each row in the activity lists, by what happened.
EVENT_COLORS = {'block': '#e5534b', 'send_anyway': '#d29922', 'warn': '#d29922', 'transform': '#2ea043'}
PAGES = ('Home', 'Activity', 'Settings')
WATCHED_SITES = 'ChatGPT, Claude, Gemini, Perplexity and HuggingFace'


def status_detail(active: bool) -> str:
    if active:
        return f'Messages to {WATCHED_SITES} are checked before they leave this PC.'
    return 'Nothing is being checked right now. Normal browsing is not affected.'


GIT_STATUS_TEXT = {
    'on': 'On for every repository on this PC. Skip it once with --no-verify.',
    'off': 'Off.',
    'conflict': 'Unavailable: another tool already manages git hooks on this PC.',
    'no_git': 'Git is not installed on this PC.',
}


class SettingsPanel(ctk.CTkScrollableFrame):
    """One switch per kind of detection. A change is saved the moment the
    switch is flipped; the proxy picks it up on the next request."""

    def __init__(self, parent):
        super().__init__(parent, fg_color='transparent')
        ctk.CTkLabel(self, text='What to catch', font=('Segoe UI', 16, 'bold'), anchor='w').pack(
            fill='x', padx=8, pady=(4, 0))
        ctk.CTkLabel(self, text='Turn off anything you do not want ContextGuard to check for.',
                     font=('Segoe UI', 11), text_color='gray', anchor='w').pack(fill='x', padx=8, pady=(0, 8))

        self.switches = {}
        disabled = user_settings.disabled_groups()
        for group in user_settings.GROUPS:
            card = ctk.CTkFrame(self)
            card.pack(fill='x', padx=4, pady=4)
            switch = ctk.CTkSwitch(card, text='', width=44,
                                   command=lambda key=group.key: self._on_switch(key))
            switch.pack(side='right', padx=(8, 12))
            if group.key not in disabled:
                switch.select()
            ctk.CTkLabel(card, text=group.label, font=('Segoe UI', 13, 'bold'), anchor='w').pack(
                fill='x', padx=14, pady=(8, 0))
            ctk.CTkLabel(card, text=group.description, font=('Segoe UI', 11), text_color='gray',
                         anchor='w', justify='left', wraplength=360).pack(fill='x', padx=14, pady=(0, 8))
            self.switches[group.key] = switch

        ctk.CTkLabel(self, text='Changes apply to the next message you send.',
                     font=('Segoe UI', 11), text_color='gray', anchor='w').pack(fill='x', padx=8, pady=(8, 4))

        ctk.CTkLabel(self, text='Git protection', font=('Segoe UI', 16, 'bold'), anchor='w').pack(
            fill='x', padx=8, pady=(18, 0))
        card = ctk.CTkFrame(self)
        card.pack(fill='x', padx=4, pady=4)
        self.git_switch = ctk.CTkSwitch(card, text='', width=44, command=self._on_git_switch)
        self.git_switch.pack(side='right', padx=(8, 12))
        ctk.CTkLabel(card, text='Check commits and pushes', font=('Segoe UI', 13, 'bold'), anchor='w').pack(
            fill='x', padx=14, pady=(8, 0))
        ctk.CTkLabel(card, text='Stops a commit or push that adds a .env file, a private key or a known '
                                'secret, from VS Code, IntelliJ, GitHub Desktop or the terminal. Turning '
                                'this on changes your global git settings.',
                     font=('Segoe UI', 11), text_color='gray', anchor='w', justify='left',
                     wraplength=360).pack(fill='x', padx=14)
        self.git_status_label = ctk.CTkLabel(card, text='', font=('Segoe UI', 11), anchor='w', justify='left',
                                             wraplength=360)
        self.git_status_label.pack(fill='x', padx=14, pady=(2, 8))
        self._sync_git_switch()

    def _on_switch(self, key: str) -> None:
        user_settings.set_group_enabled(key, bool(self.switches[key].get()))

    def _sync_git_switch(self, message: str | None = None) -> None:
        state = git_guard.status()
        self.git_switch.configure(state='normal' if state in ('on', 'off') else 'disabled')
        if state == 'on':
            self.git_switch.select()
        else:
            self.git_switch.deselect()
        self.git_status_label.configure(text=message or GIT_STATUS_TEXT[state])

    def _on_git_switch(self) -> None:
        # git runs off the window's thread so the window never freezes on it.
        turn_on = bool(self.git_switch.get())
        self.git_switch.configure(state='disabled')
        self.git_status_label.configure(text='Turning on...' if turn_on else 'Turning off...')

        def work():
            message = None
            try:
                git_guard.enable() if turn_on else git_guard.disable()
            except git_guard.GitGuardError as error:
                message = str(error)
            self.after(0, lambda: self._sync_git_switch(message))
        threading.Thread(target=work, daemon=True).start()


class ContextGuardWindow(ctk.CTk):
    REFRESH_MS = 2000

    def __init__(self):
        super().__init__()
        self.title('ContextGuard')
        self.geometry('560x600')
        self.minsize(500, 520)
        self.protocol('WM_DELETE_WINDOW', self._on_close)
        # customtkinter sets its own title-bar icon about 200 ms after the
        # window is created, so ours has to be applied after that.
        self.after(300, self._apply_window_icon)

        header = ctk.CTkFrame(self, fg_color='transparent')
        header.pack(fill='x', padx=20, pady=(16, 8))
        mark = manager.draw_logo_mark(manager.ICON_GREEN, 96)
        self._logo = ctk.CTkImage(light_image=mark, dark_image=mark, size=(28, 28))
        ctk.CTkLabel(header, text='  ContextGuard', image=self._logo, compound='left',
                     font=('Segoe UI', 17, 'bold')).pack(side='left')
        ctk.CTkLabel(header, text=f'v{VERSION}', font=('Segoe UI', 11), text_color='gray').pack(side='right')

        self.tabs = ctk.CTkSegmentedButton(self, values=list(PAGES), command=self._show_page)
        self.tabs.pack(fill='x', padx=20, pady=(0, 10))

        # Shown at the bottom only when a newer version exists.
        self.update_label = ctk.CTkLabel(self, text='', font=('Segoe UI', 11), text_color='#4A90D9')
        self.update_label.pack(side='bottom', pady=(0, 8))

        body = ctk.CTkFrame(self, fg_color='transparent')
        body.pack(fill='both', expand=True, padx=20, pady=(0, 4))
        self.pages = {name: ctk.CTkFrame(body, fg_color='transparent') for name in PAGES[:2]}

        # --- Home ---------------------------------------------------------
        home = self.pages['Home']
        status_card = ctk.CTkFrame(home)
        status_card.pack(fill='x')
        self.status_label = ctk.CTkLabel(status_card, text='Starting...', font=('Segoe UI', 22, 'bold'))
        self.status_label.pack(pady=(20, 2))
        self.status_detail_label = ctk.CTkLabel(status_card, text='', font=('Segoe UI', 12),
                                                text_color='gray', wraplength=440)
        self.status_detail_label.pack(padx=16)
        self.toggle_button = ctk.CTkButton(status_card, text='...', width=180, height=36,
                                           font=('Segoe UI', 13, 'bold'), command=self._on_toggle)
        self.toggle_button.pack(pady=(14, 20))

        tiles = ctk.CTkFrame(home, fg_color='transparent')
        tiles.pack(fill='x', pady=(10, 0))
        tiles.grid_columnconfigure((0, 1, 2), weight=1, uniform='tile')
        self.stat_labels = {}
        for column, (key, caption) in enumerate((('blocked', 'Blocked'), ('sent_anyway', 'Sent anyway'),
                                                 ('masked_or_warned', 'Masked or warned'))):
            tile = ctk.CTkFrame(tiles)
            tile.grid(row=0, column=column, sticky='nsew',
                      padx=(0 if column == 0 else 5, 0 if column == 2 else 5))
            number = ctk.CTkLabel(tile, text='0', font=('Segoe UI', 24, 'bold'))
            number.pack(pady=(12, 0))
            ctk.CTkLabel(tile, text=caption, font=('Segoe UI', 11), text_color='gray').pack(pady=(0, 12))
            self.stat_labels[key] = number

        latest_header = ctk.CTkFrame(home, fg_color='transparent')
        latest_header.pack(fill='x', pady=(14, 2))
        ctk.CTkLabel(latest_header, text='Latest', font=('Segoe UI', 13, 'bold')).pack(side='left')
        self.counts_label = ctk.CTkLabel(latest_header, text='Caught so far: 0', font=('Segoe UI', 11),
                                         text_color='gray')
        self.counts_label.pack(side='right')
        self.latest_box = ctk.CTkTextbox(home, height=110, font=('Consolas', 11), wrap='none')
        self.latest_box.pack(fill='both', expand=True)

        # --- Activity -----------------------------------------------------
        activity = self.pages['Activity']
        ctk.CTkLabel(activity, text='Everything ContextGuard has caught', font=('Segoe UI', 16, 'bold'),
                     anchor='w').pack(fill='x')
        ctk.CTkLabel(activity, text='Only the kind of information, the site and the time are kept. '
                                    'The text itself is never stored.',
                     font=('Segoe UI', 11), text_color='gray', anchor='w', justify='left',
                     wraplength=500).pack(fill='x', pady=(0, 8))
        filter_row = ctk.CTkFrame(activity, fg_color='transparent')
        filter_row.pack(fill='x', pady=(0, 6))
        self.activity_filter = ctk.CTkSegmentedButton(
            filter_row, values=list(ACTIVITY_FILTERS), command=lambda _value: self._refresh_activity_list())
        self.activity_filter.set('All')
        self.activity_filter.pack(side='left')
        self.activity_summary = ctk.CTkLabel(activity, text='', font=('Segoe UI', 12), anchor='w')
        self.activity_summary.pack(fill='x', pady=(0, 6))
        self.events_box = ctk.CTkTextbox(activity, font=('Consolas', 11), wrap='none')
        self.events_box.pack(fill='both', expand=True)

        for box in (self.latest_box, self.events_box):
            for action, color in EVENT_COLORS.items():
                box.tag_config(action, foreground=color)
            box.tag_config('control', foreground='gray')
            box.configure(state='disabled')
        self._rendered = {}
        self._groups = []
        self._seen_event_total = None

        # --- Settings -----------------------------------------------------
        self.settings_panel = SettingsPanel(body)
        self.pages['Settings'] = self.settings_panel

        self._current_page = None
        self._show_page('Home')

        self._tray_icon = None
        # Quit can come from other threads (tray menu, dashboard). Only the
        # window's own thread may close the window, so they set this flag and
        # _poll_quit() closes it.
        self._quit_requested = threading.Event()
        self._start_tray_icon()
        self._refresh_loop()
        self._poll_quit()
        self._check_for_update_async()

    def _apply_window_icon(self) -> None:
        try:
            self.iconbitmap(str(get_app_root() / 'assets' / 'icon.ico'))
        except Exception:
            pass  # a missing icon must never stop the window from opening

    def _show_page(self, name: str) -> None:
        if self._current_page is not None:
            self.pages[self._current_page].pack_forget()
        self.pages[name].pack(fill='both', expand=True)
        self._current_page = name
        self.tabs.set(name)

    def _check_for_update_async(self) -> None:
        # Checks GitHub in the background; only the window thread touches the label.
        def worker():
            latest = check_for_update(VERSION)
            if latest:
                self.after(0, lambda: self.update_label.configure(
                    text=f'Update available: {latest} (you have {VERSION}) — see the GitHub Releases page'))
        threading.Thread(target=worker, daemon=True).start()

    def _sync_status(self) -> None:
        # Whether the proxy process is actually running, not just whether one
        # was started: after a crash the window must not keep showing Active.
        active = manager._proxy_process_is_alive()
        self.status_label.configure(text=status_text(active), text_color=status_color(active))
        self.status_detail_label.configure(text=status_detail(active))
        self.toggle_button.configure(text=toggle_button_text(active))
        if self._tray_icon is not None:
            manager._sync_icon_to_state(self._tray_icon)

    def _on_toggle(self) -> None:
        # Shared with the tray: after a crash, one click restarts protection
        # instead of "stopping" a dead process.
        manager.on_toggle(self._tray_icon, None)
        self._sync_status()

    def _render_events(self, box, groups: list) -> None:
        # Redrawn only when the list changed, so reading or scrolling it is
        # not interrupted by the 2-second refresh.
        lines = [(format_activity_row(g), 'control' if g['category_kind'] == 'control' else g['action'])
                 for g in groups]
        if self._rendered.get(box) == lines:
            return
        self._rendered[box] = lines
        box.configure(state='normal')
        box.delete('1.0', 'end')
        if not lines:
            box.insert('end', 'Nothing here yet.', 'control')
        for text, tag in lines:
            box.insert('end', text + '\n', tag)
        box.configure(state='disabled')

    def _refresh_activity_list(self) -> None:
        self._render_events(self.events_box, filter_activity(self._groups, self.activity_filter.get())[:300])

    def _refresh_counts_and_events(self) -> None:
        # Re-read and regroup the log only when something new was logged.
        total = event_counts()['total']
        if total != self._seen_event_total:
            self._seen_event_total = total
            self._groups = group_activity(activity_rows())
        counts = activity_counts(self._groups)
        self.counts_label.configure(text=f'Caught so far: {caught_total(self._groups)}')
        for key, value in counts.items():
            self.stat_labels[key].configure(text=str(value))
        self.activity_summary.configure(
            text=f"{counts['blocked']} blocked  \u00b7  {counts['sent_anyway']} sent anyway  \u00b7  "
                 f"{counts['masked_or_warned']} masked or warned   (each message counts once)")
        self._render_events(self.latest_box, self._groups[:5])
        self._refresh_activity_list()

    def _refresh_loop(self) -> None:
        self._sync_status()
        self._refresh_counts_and_events()
        self.after(self.REFRESH_MS, self._refresh_loop)

    def _poll_quit(self) -> None:
        if self._quit_requested.is_set():
            self.destroy()
            return
        self.after(200, self._poll_quit)

    def _open_dashboard(self) -> None:
        # Checks that our own dashboard is the one on port 5050 before sending
        # it the token.
        manager.on_open_dashboard(self._tray_icon, None)

    def _build_tray_menu(self) -> pystray.Menu:
        return pystray.Menu(
            pystray.MenuItem('Open ContextGuard', lambda: self.after(0, self._show_window), default=True),
            pystray.MenuItem('Open web dashboard (advanced)', lambda: self.after(0, self._open_dashboard)),
            # These two never touch the window, so they can run on the tray's thread.
            pystray.MenuItem('Rotate dashboard/control tokens', manager.on_rotate_tokens),
            pystray.MenuItem('Reset CA certificate (fixes cert errors)', manager.on_reset_ca_certificate),
            # _on_quit() only sets a flag, so it is safe on the tray's thread too.
            pystray.MenuItem('Quit', lambda: self._on_quit()),
        )

    def _start_tray_icon(self) -> None:
        image = manager.make_icon_image(True)
        menu = self._build_tray_menu()
        self._tray_icon = pystray.Icon('contextguard', image, 'ContextGuard', menu)
        threading.Thread(target=self._tray_icon.run, daemon=True).start()
        # Lets the web dashboard's Pause/Resume/Quit buttons reach this app.
        manager.start_control_server(self._tray_icon)
        # A Quit from the dashboard closes this window too.
        manager._control_state['on_quit_extra'] = self._quit_requested.set

    def _show_window(self) -> None:
        self.deiconify()
        self.lift()

    def _on_close(self) -> None:
        # The X button hides the window instead of quitting, so protection keeps running.
        self.withdraw()

    def _on_quit(self) -> None:
        # Runs on the tray's thread: stop everything, then let the window close itself.
        manager.stop_all()
        if self._tray_icon is not None:
            self._tray_icon.stop()
        self._quit_requested.set()


def main() -> None:
    # A second copy must stop before touching the proxy (see is_another_instance_running).
    if manager.is_another_instance_running():
        notify('ContextGuard', 'ContextGuard is already running -- check your system tray icon.')
        return
    # Make sure Windows trusts our CA certificate, on every start (it may have
    # been removed since). If that fails the app still runs, and the message
    # below says watched sites may show certificate errors.
    try:
        if not ca_is_installed():
            install_ca_cert()
            # Chrome remembers certificate decisions until it fully restarts.
            notify('ContextGuard', 'CA certificate installed and trusted. If a watched site (ChatGPT, '
                                    'Claude, etc.) is already open, fully restart your browser for it '
                                    'to work.')
    except Exception:
        notify('ContextGuard', "Couldn't set up the CA certificate automatically -- watched sites "
                                '(ChatGPT, Claude, etc.) may show a certificate warning until this is '
                                'resolved. Try running scripts\\install_ca_cert.py, or reinstall.')
    atexit.register(manager.restore_system_proxy_if_still_enabled)
    git_guard.repair()  # before the window reads the git protection state (~0.1 s)
    manager.start_proxy()
    # Turns the proxy setting back off if the proxy dies on its own.
    threading.Thread(target=manager._proxy_watchdog_loop, daemon=True).start()
    app = ContextGuardWindow()
    app.mainloop()


if __name__ == '__main__':
    main()
