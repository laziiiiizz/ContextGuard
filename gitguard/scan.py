"""Finds secrets about to enter git history: secret files by name (.env and
private keys) and known secret formats in the lines being added.

Used by the commit and push hooks. Only file names and the kinds of secret
found are reported, never the secret text itself.
"""
import fnmatch
import subprocess
from dataclasses import dataclass, field
from pathlib import PurePosixPath

ZERO_SHA = '0' * 40

# Committed templates that by convention hold no real values.
_TEMPLATE_SUFFIXES = ('.example', '.sample', '.template', '.dist', '.defaults')
_SECRET_FILE_PATTERNS = ('id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', '*.pem', '*.p12', '*.pfx', '*.keystore',
                         'credentials.json', 'service-account*.json')
# Enough for any real diff; a huge generated diff is cut off rather than slowing every push.
MAX_SCANNED_CHARS = 2_000_000


@dataclass
class Report:
    secret_files: list[str] = field(default_factory=list)
    secrets: dict[str, list[str]] = field(default_factory=dict)  # file -> categories
    truncated: bool = False

    @property
    def clean(self) -> bool:
        return not self.secret_files and not self.secrets


def is_secret_file(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    if name.endswith(_TEMPLATE_SUFFIXES):
        return False
    if name == '.env' or name.startswith('.env.') or name.endswith('.env'):
        return True
    return any(fnmatch.fnmatch(name, pattern) for pattern in _SECRET_FILE_PATTERNS)


def _git(args: list[str], cwd=None) -> str:
    result = subprocess.run(['git', *args], cwd=cwd, capture_output=True, check=True,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    return result.stdout.decode('utf-8', errors='replace')


def _have_commit(sha: str, cwd=None) -> bool:
    result = subprocess.run(['git', 'cat-file', '-e', f'{sha}^{{commit}}'], cwd=cwd, capture_output=True,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    return result.returncode == 0


def added_lines_by_file(patch: str) -> dict[str, str]:
    """Splits `git diff -U0` / `git log -p -U0` output into the added lines
    of each file."""
    files: dict[str, list[str]] = {}
    current = None
    for line in patch.splitlines():
        if line.startswith('+++ '):
            target = line[4:]
            current = target[2:] if target.startswith('b/') else None
            if current is not None:
                files.setdefault(current, [])
        elif line.startswith('+') and current is not None:
            files[current].append(line[1:])
    return {path: '\n'.join(lines) for path, lines in files.items()}


def build_report(paths: list[str], patch: str, scanner) -> Report:
    report = Report()
    for path in sorted(set(paths)):
        if is_secret_file(path):
            report.secret_files.append(path)
    budget = MAX_SCANNED_CHARS
    for path, text in added_lines_by_file(patch).items():
        if budget <= 0:
            report.truncated = True
            break
        text = text[:budget]
        budget -= len(text)
        categories = scanner.blocking_categories(text)
        if categories:
            report.secrets[path] = categories
    return report


def staged_report(scanner, cwd=None) -> Report:
    """What `git commit` is about to record."""
    paths = _git(['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'], cwd).split('\0')
    patch = _git(['diff', '--cached', '-U0', '--no-color', '--no-ext-diff', '--diff-filter=ACMR'], cwd)
    return build_report([p for p in paths if p], patch, scanner)


def push_report(stdin_text: str, scanner, cwd=None) -> Report:
    """What `git push` is about to send. stdin_text is the pre-push hook's
    input: `<local-ref> <local-sha> <remote-ref> <remote-sha>` per line."""
    paths, patches = [], []
    for line in stdin_text.splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        _local_ref, local_sha, _remote_ref, remote_sha = parts
        if local_sha == ZERO_SHA:
            continue  # deleting a remote branch sends no content
        # A new remote branch, or a remote commit we don't have yet (someone
        # pushed or edited on GitHub since our last pull): check everything
        # not already on a remote we know about.
        if remote_sha == ZERO_SHA or not _have_commit(remote_sha, cwd):
            rev_range = [local_sha, '--not', '--remotes']
        else:
            rev_range = [f'{remote_sha}..{local_sha}']
        names = _git(['log', '--name-only', '--diff-filter=ACMR', '--pretty=format:', '-z', *rev_range], cwd)
        paths.extend(p.strip('\n') for p in names.split('\0') if p.strip('\n'))
        patches.append(_git(['log', '-p', '-U0', '--no-color', '--no-ext-diff', '--diff-filter=ACMR',
                             '--pretty=format:', *rev_range], cwd))
    return build_report(paths, '\n'.join(patches), scanner)
