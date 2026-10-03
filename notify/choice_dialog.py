"""A two-button "stop / go ahead anyway" window for prompts raised outside
the proxy (the git hook). Same safety rules as the Don't Send popup: the
safe choice is the default, Enter and closing the window pick it, both
buttons are briefly disabled so a stray click can't choose, and no answer
within the timeout counts as the safe choice.
"""
import customtkinter as ctk

RISKY_COLOR = '#8B2020'
RISKY_HOVER = '#6B1818'


def ask(title: str, message: str, safe_label: str, risky_label: str, timeout: float = 120.0) -> bool:
    """Returns True only if the user clicked the risky button."""
    ctk.set_appearance_mode('system')
    ctk.set_default_color_theme('green')
    root = ctk.CTk()
    root.title('ContextGuard')
    root.resizable(False, False)
    root.attributes('-topmost', True)

    def apply_icon() -> None:
        try:
            from proxy.paths import get_app_root
            root.iconbitmap(str(get_app_root() / 'assets' / 'icon.ico'))
        except Exception:
            pass

    root.after(250, apply_icon)  # customtkinter sets its own icon at ~200 ms
    result = {'proceed': False}

    def choose(proceed: bool) -> None:
        result['proceed'] = proceed
        root.destroy()

    ctk.CTkLabel(root, text=title, font=('Segoe UI', 16, 'bold')).pack(padx=24, pady=(20, 6))
    ctk.CTkLabel(root, text=message, font=('Segoe UI', 12), justify='left', wraplength=460).pack(
        padx=24, pady=(0, 16))
    row = ctk.CTkFrame(root, fg_color='transparent')
    row.pack(pady=(0, 20))
    safe = ctk.CTkButton(row, text=safe_label, width=150, command=lambda: choose(False))
    safe.pack(side='left', padx=6)
    risky = ctk.CTkButton(row, text=risky_label, width=150, fg_color=RISKY_COLOR, hover_color=RISKY_HOVER,
                          command=lambda: choose(True))
    risky.pack(side='left', padx=6)
    safe.configure(state='disabled')
    risky.configure(state='disabled')

    def enable() -> None:
        safe.configure(state='normal')
        risky.configure(state='normal')
        safe.focus_set()

    root.after(400, enable)
    root.protocol('WM_DELETE_WINDOW', lambda: choose(False))
    root.after(int(timeout * 1000), lambda: choose(False))
    root.bind('<Return>', lambda event: choose(False))
    root.update_idletasks()
    x = (root.winfo_screenwidth() - root.winfo_width()) // 2
    y = (root.winfo_screenheight() - root.winfo_height()) // 2
    root.geometry(f'+{x}+{y}')
    root.mainloop()
    return result['proceed']
