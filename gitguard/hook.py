"""Entry point the installed git hooks call:

    ContextGuard.exe --git-hook <pre-commit|pre-push> <report-file> <input-file> [git's hook args]

The exe is a windowed app with no usable stdin/stdout, so the hook script
passes git's input in a file and prints the report file this writes.
Exit 0 lets git continue; exit 1 stops the commit or push.

If the check itself fails (git missing, a damaged install) this lets git
continue with a warning: a broken checker must not stop every commit on the
machine.
"""
import os
import sys
import traceback
from pathlib import Path

from engine.labels import friendly_category

_VERBS = {'pre-commit': ('commit', 'Commit'), 'pre-push': ('push', 'Push')}


def format_report(report, hook: str) -> str:
    verb = _VERBS[hook][0]
    lines = [f'ContextGuard stopped this {verb}.', '']
    for path in report.secret_files:
        lines.append(f'  {path}  (secret file: keep it out of git)')
    for path, categories in report.secrets.items():
        lines.append(f'  {path}  contains: {", ".join(friendly_category(c) for c in categories)}')
    lines.append('')
    if report.secret_files:
        names = ' '.join(report.secret_files)
        if hook == 'pre-commit':
            lines.append(f'Unstage it and ignore it:  git rm --cached {names}  then add it to .gitignore')
        else:
            lines.append('It is in a commit you are about to push. Remove it from that commit '
                         '(git rm --cached, then git commit --amend), add it to .gitignore, and push again.')
    if report.secrets:
        lines.append('Move the secrets out of the code (for example into an ignored .env file).')
    lines.append(f'Sure it is safe? {verb} anyway with:  git {verb} --no-verify')
    return '\n'.join(lines) + '\n'


def _popup_message(report) -> str:
    items = list(report.secret_files)
    items += [f'{path} ({", ".join(friendly_category(c) for c in cats)})' for path, cats in report.secrets.items()]
    shown = '\n'.join(f'• {item}' for item in items[:6])
    more = f'\nand {len(items) - 6} more' if len(items) > 6 else ''
    return f'{shown}{more}\n\nOnce this reaches GitHub it stays in the history, even if you delete it later.'


def main(argv: list[str]) -> int:
    hook, report_path, input_path = argv[0], Path(argv[1]), Path(argv[2])
    try:
        from engine.scan_text import Scanner
        from gitguard.scan import push_report, staged_report
        scanner = Scanner()
        if hook == 'pre-push':
            report = push_report(input_path.read_text(encoding='utf-8', errors='replace'), scanner)
        else:
            report = staged_report(scanner)
    except Exception:
        report_path.write_text('ContextGuard could not check this change, so it was not checked:\n'
                               + traceback.format_exc(limit=1), encoding='utf-8')
        return 0
    if report.clean:
        return 0

    text = format_report(report, hook)
    verb, title_verb = _VERBS[hook]
    proceed = False
    if os.environ.get('CONTEXTGUARD_GIT_NO_POPUP') != '1':
        try:
            from notify.choice_dialog import ask
            proceed = ask(f'Secrets in this {verb}', _popup_message(report),
                          safe_label=f"Don't {title_verb}", risky_label=f'{title_verb} Anyway')
        except Exception:
            proceed = False  # no screen to ask on: the terminal message below still explains
    if proceed:
        report_path.write_text(f'ContextGuard: {verb} allowed by you despite the warning.\n', encoding='utf-8')
        return 0
    report_path.write_text(text, encoding='utf-8')
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
