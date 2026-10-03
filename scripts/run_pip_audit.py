"""Runs pip-audit with the shared ignore list in .github/pip-audit-ignore.txt.

Extra arguments are passed through, e.g. `--format cyclonedx-json -o sbom.json`.
"""
import subprocess
import sys
from pathlib import Path

IGNORE_FILE = Path(__file__).resolve().parent.parent / '.github' / 'pip-audit-ignore.txt'


def load_ignored_ids(path: Path = IGNORE_FILE) -> list[str]:
    ids = []
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            ids.append(line)
    return ids


def build_command(extra_args: list[str], ignored_ids: list[str]) -> list[str]:
    cmd = [sys.executable, '-m', 'pip_audit']
    for vuln_id in ignored_ids:
        cmd += ['--ignore-vuln', vuln_id]
    return cmd + extra_args


if __name__ == '__main__':
    sys.exit(subprocess.call(build_command(sys.argv[1:], load_ignored_ids())))
