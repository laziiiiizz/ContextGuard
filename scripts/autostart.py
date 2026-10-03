"""Makes ContextGuard start by itself when you sign in to Windows, by putting
a tiny VBScript in your Startup folder. No admin rights needed.

Task Scheduler is not used because locked-down accounts often aren't allowed
to create tasks; every account can write to its own Startup folder. VBScript
instead of a .bat file, because a .bat flashes a black window at sign-in.

Running register() again just overwrites the old file.
"""
import os
import sys

STARTUP_DIR = os.path.join(
    os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
LAUNCHER_NAME = 'ContextGuard.vbs'
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _pythonw_exe() -> str:
    return os.path.join(os.path.dirname(sys.executable), 'pythonw.exe')


def _gui_app_path() -> str:
    return os.path.join(REPO_ROOT, 'gui', 'app.py')


def _launcher_path() -> str:
    return os.path.join(STARTUP_DIR, LAUNCHER_NAME)


def _launch_command() -> str:
    """The full command line the VBScript launcher runs. A packaged/frozen
    build IS a standalone, already-windowless (console=False) executable --
    it launches itself directly, with no pythonw.exe/venv layer at all.
    Running from source still needs pythonw.exe (hidden) + gui/app.py."""
    if getattr(sys, 'frozen', False):
        return f'"{sys.executable}"'
    pythonw = _pythonw_exe()
    if not os.path.exists(pythonw):
        raise FileNotFoundError(
            f'{pythonw} not found -- venv may have been created without pythonw.exe. '
            'Recreate the venv with a standard CPython install (not a stripped-down one).')
    return f'"{pythonw}" "{_gui_app_path()}"'


def register() -> None:
    command = _launch_command()
    # A literal `"` inside a VBScript string literal is written as `""` --
    # this is VBScript's own escaping rule, not Python's.
    escaped = command.replace('"', '""')
    script = (
        'Set objShell = CreateObject("WScript.Shell")\r\n'
        f'objShell.Run "{escaped}", 0, False\r\n'
    )
    os.makedirs(STARTUP_DIR, exist_ok=True)
    with open(_launcher_path(), 'w', encoding='utf-8') as f:
        f.write(script)


def unregister() -> None:
    path = _launcher_path()
    if os.path.exists(path):
        os.remove(path)


def is_registered() -> bool:
    return os.path.exists(_launcher_path())


def main() -> None:
    action = sys.argv[1] if len(sys.argv) > 1 else ''
    if action == 'register':
        register()
        print(f'[ContextGuard] auto-launch registered -- the ContextGuard window will '
              f'now start silently at every logon ({_launcher_path()}). '
              'Use its Pause/Resume button (or the tray icon) to control it per-session; '
              'run `python scripts/autostart.py unregister` to stop it auto-launching entirely.')
    elif action == 'unregister':
        unregister()
        print('[ContextGuard] auto-launch removed -- it will no longer start automatically at logon.')
    elif action == 'status':
        print('registered' if is_registered() else 'not registered')
    else:
        print('Usage: python scripts/autostart.py [register|unregister|status]')
        sys.exit(1)


if __name__ == '__main__':
    main()
