"""Turns the git protection on and off by pointing git's global
core.hooksPath at ContextGuard's own hooks folder.

Git allows only one hooks folder, so this refuses to replace one the user
already set, and the installed hooks run each repository's own
.git/hooks/<name> after their check. A repository that sets its own
core.hooksPath (Husky does) is not covered: git uses that instead.
"""
import os
import shutil
import subprocess
import sys

from proxy.paths import get_app_root, get_writable_data_dir

HOOK_NAMES = ('pre-commit', 'pre-push')
# The installed app has no console; without this every git call it makes
# opens and closes a console window.
NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


class GitGuardError(Exception):
    pass


def hooks_dir():
    return get_writable_data_dir() / 'git-hooks'


def _posix(path) -> str:
    return str(path).replace('\\', '/')


def hook_command() -> str:
    if getattr(sys, 'frozen', False):
        return f'"{_posix(sys.executable)}" --git-hook'
    return f'"{_posix(sys.executable)}" "{_posix(get_app_root() / "gui" / "app.py")}" --git-hook'


def hook_script(name: str) -> str:
    folder = _posix(hooks_dir())
    return f'''#!/bin/sh
# Installed by ContextGuard: checks this {name.split('-')[1]} for secret files and
# secrets, then runs the repository's own {name} hook if it has one.
input="$(cat)"
work="{folder}/run-$$"
printf '%s\\n' "$input" > "$work.in"
{hook_command()} {name} "$work.out" "$work.in" "$@"
status=$?
[ -s "$work.out" ] && cat "$work.out" >&2
rm -f "$work.in" "$work.out"
[ $status -ne 0 ] && exit $status
own="$(git rev-parse --git-dir)/hooks/{name}"
if [ -x "$own" ]; then
  printf '%s\\n' "$input" | "$own" "$@"
  exit $?
fi
exit 0
'''


def _git_config(*args: str) -> subprocess.CompletedProcess:
    if shutil.which('git') is None:
        raise GitGuardError('Git is not installed (or not on PATH), so there is nothing to protect.')
    return subprocess.run(['git', 'config', '--global', *args], capture_output=True, text=True,
                          creationflags=NO_WINDOW)


def _same_path(a: str, b) -> bool:
    norm = lambda p: os.path.normcase(os.path.abspath(os.path.expanduser(str(p))))
    return norm(a) == norm(b)


def current_hooks_path() -> str | None:
    result = _git_config('--get', 'core.hooksPath')
    value = result.stdout.strip()
    return value or None


def status() -> str:
    """'on', 'off', 'conflict' (another tool owns the global hooks folder) or 'no_git'."""
    try:
        current = current_hooks_path()
    except GitGuardError:
        return 'no_git'
    if current is None:
        return 'off'
    if not _same_path(current, hooks_dir()):
        return 'conflict'
    return 'on' if _scripts_present() else 'off'


def _write_scripts() -> None:
    folder = hooks_dir()
    folder.mkdir(parents=True, exist_ok=True)
    for name in HOOK_NAMES:
        (folder / name).write_text(hook_script(name), encoding='utf-8', newline='\n')


def _scripts_present() -> bool:
    return all((hooks_dir() / name).is_file() for name in HOOK_NAMES)


def repair() -> None:
    """Run at startup. If git still points at this app's hooks folder (the
    user turned protection on) but the scripts are gone or stale, for
    example after a reinstall, write them again. Never raises."""
    try:
        current = current_hooks_path()
        if current is not None and _same_path(current, hooks_dir()):
            _write_scripts()
    except Exception:
        pass


def enable() -> None:
    current = current_hooks_path()
    if current is not None and not _same_path(current, hooks_dir()):
        raise GitGuardError(f'Git already uses another hooks folder ({current}). ContextGuard will not '
                            'replace it. Remove that setting first if you want ContextGuard to check commits.')
    _write_scripts()
    result = _git_config('core.hooksPath', _posix(hooks_dir()))
    if result.returncode != 0:
        raise GitGuardError(f'Could not update git settings: {result.stderr.strip()}')


def disable() -> None:
    """Only ever removes the setting if it still points at our folder."""
    current = current_hooks_path()
    if current is not None and _same_path(current, hooks_dir()):
        _git_config('--unset', 'core.hooksPath')


def main_off() -> None:
    """Uninstaller entry point; never raises."""
    try:
        disable()
    except Exception:
        pass
