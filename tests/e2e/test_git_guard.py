"""Real git commits and pushes through the installed hooks, in a temp folder
with its own global git config, so the developer's real git settings are
never read or changed."""
import os
import shutil
import subprocess

import pytest

from gitguard import install
from gitguard.scan import added_lines_by_file, is_secret_file

pytestmark = pytest.mark.skipif(shutil.which('git') is None, reason='git is not installed')

FAKE_AWS = 'AKIAABCDEFGHIJKLMNOP'


@pytest.mark.parametrize('name, secret', [
    ('.env', True), ('config/.env.production', True), ('prod.env', True),
    ('.env.example', False), ('.env.sample', False), ('.env.template', False),
    ('id_rsa', True), ('certs/server.pem', True), ('service-account-prod.json', True),
    ('README.md', False), ('environment.py', False), ('src/.envrc', False),
])
def test_secret_file_names(name, secret):
    assert is_secret_file(name) is secret


def test_added_lines_are_split_per_file():
    patch = ('diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -0,0 +1 @@\n+key = 1\n'
             'diff --git a/b.py b/b.py\n--- /dev/null\n+++ b/b.py\n@@ -0,0 +1,2 @@\n+x\n+y\n')
    assert added_lines_by_file(patch) == {'a.py': 'key = 1', 'b.py': 'x\ny'}


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    env = dict(os.environ)
    env.update(GIT_CONFIG_GLOBAL=str(tmp_path / 'global.gitconfig'), GIT_CONFIG_NOSYSTEM='1',
               CONTEXTGUARD_GIT_NO_POPUP='1')
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(install, 'hooks_dir', lambda: tmp_path / 'hooks')

    def git(*args, cwd=None, check=True):
        result = subprocess.run(['git', *args], cwd=cwd, capture_output=True, text=True, env=env)
        if check and result.returncode != 0:
            raise AssertionError(result.stderr)
        return result

    git('config', '--global', 'user.email', 'test@example.com')
    git('config', '--global', 'user.name', 'Test')
    git('config', '--global', 'init.defaultBranch', 'main')
    git('init', '-q', '--bare', str(tmp_path / 'remote.git'))
    repo = tmp_path / 'repo'
    git('init', '-q', str(repo))
    git('remote', 'add', 'origin', str(tmp_path / 'remote.git'), cwd=repo)
    (repo / 'README.md').write_text('hello\n')
    git('add', '.', cwd=repo)
    git('commit', '-q', '-m', 'first', cwd=repo)
    git('push', '-q', 'origin', 'main', cwd=repo)
    return git, repo, tmp_path


def test_enable_points_git_at_our_hooks_and_disable_removes_it(sandbox):
    git, _repo, tmp_path = sandbox
    assert install.status() == 'off'
    install.enable()
    assert install.status() == 'on'
    assert (tmp_path / 'hooks' / 'pre-commit').exists() and (tmp_path / 'hooks' / 'pre-push').exists()
    install.disable()
    assert install.status() == 'off'


def test_enable_refuses_to_replace_another_tools_hooks_folder(sandbox):
    git, _repo, tmp_path = sandbox
    git('config', '--global', 'core.hooksPath', str(tmp_path / 'someone-elses-hooks'))
    assert install.status() == 'conflict'
    with pytest.raises(install.GitGuardError):
        install.enable()
    install.disable()  # must not remove a setting that is not ours
    assert git('config', '--global', '--get', 'core.hooksPath').stdout.strip()


def test_commit_of_env_file_is_stopped_and_no_verify_overrides(sandbox):
    git, repo, _tmp = sandbox
    install.enable()
    (repo / '.env').write_text('DATABASE_PASSWORD=hunter2\n')
    git('add', '.env', cwd=repo)
    result = git('commit', '-m', 'add env', cwd=repo, check=False)
    assert result.returncode != 0
    assert 'ContextGuard stopped this commit' in result.stderr
    assert '.env' in result.stderr
    assert 'hunter2' not in result.stderr  # never echoes the secret itself

    assert git('commit', '-q', '--no-verify', '-m', 'add env', cwd=repo, check=False).returncode == 0


def test_commit_with_a_key_in_code_is_stopped(sandbox):
    git, repo, _tmp = sandbox
    install.enable()
    (repo / 'settings.py').write_text(f'AWS_KEY = "{FAKE_AWS}"\n')
    git('add', 'settings.py', cwd=repo)
    result = git('commit', '-m', 'settings', cwd=repo, check=False)
    assert result.returncode != 0
    assert 'settings.py  contains: AWS access token' in result.stderr
    assert FAKE_AWS not in result.stderr


def test_clean_commit_and_push_go_through(sandbox):
    git, repo, _tmp = sandbox
    install.enable()
    (repo / 'app.py').write_text('print("hello")\n')
    git('add', 'app.py', cwd=repo)
    git('commit', '-q', '-m', 'app', cwd=repo)
    git('push', '-q', 'origin', 'main', cwd=repo)


def test_push_of_an_env_committed_before_protection_is_stopped(sandbox):
    git, repo, _tmp = sandbox
    (repo / '.env').write_text('TOKEN=abc\n')
    git('add', '.env', cwd=repo)
    git('commit', '-q', '-m', 'env before the guard existed', cwd=repo)
    install.enable()
    result = git('push', 'origin', 'main', cwd=repo, check=False)
    assert result.returncode != 0
    assert 'ContextGuard stopped this push' in result.stderr


def test_the_repositorys_own_hook_still_runs(sandbox):
    git, repo, _tmp = sandbox
    install.enable()
    own = repo / '.git' / 'hooks' / 'pre-commit'
    own.write_text('#!/bin/sh\necho "repo hook ran" >&2\nexit 0\n', newline='\n')
    own.chmod(0o755)
    (repo / 'app.py').write_text('x = 1\n')
    git('add', 'app.py', cwd=repo)
    result = git('commit', '-m', 'app', cwd=repo)
    assert 'repo hook ran' in result.stderr


def test_switch_shows_off_when_the_hook_scripts_are_missing_and_repair_restores_them(sandbox):
    # Seen on a real machine: git still pointed at the hooks folder after a
    # reinstall, but the scripts were gone, so nothing was actually checked.
    git, _repo, tmp_path = sandbox
    install.enable()
    for name in install.HOOK_NAMES:
        (tmp_path / 'hooks' / name).unlink()
    assert install.status() == 'off'
    install.repair()
    assert install.status() == 'on'


def test_repair_leaves_other_tools_hooks_alone(sandbox):
    git, _repo, tmp_path = sandbox
    git('config', '--global', 'core.hooksPath', str(tmp_path / 'someone-elses-hooks'))
    install.repair()
    assert not (tmp_path / 'hooks').exists()


def test_push_still_checked_when_github_has_a_commit_we_dont_have(sandbox, tmp_path):
    # Seen live: the README was edited on the GitHub website, so the remote's
    # newest commit was missing locally and the check crashed instead of running.
    git, repo, _tmp = sandbox
    other = tmp_path / 'other'
    git('clone', '-q', str(tmp_path / 'remote.git'), str(other))
    (other / 'notes.md').write_text('edited elsewhere\n')
    git('add', 'notes.md', cwd=other)
    git('commit', '-q', '-m', 'edit on GitHub', cwd=other)
    git('push', '-q', 'origin', 'main', cwd=other)

    install.enable()
    (repo / '.env').write_text('TOKEN=abc\n')
    git('add', '.env', cwd=repo)
    git('commit', '-q', '--no-verify', '-m', 'env', cwd=repo)
    # Make the pre-push hook see the remote's newer commit without fetching it.
    result = git('push', 'origin', 'main', '--force-with-lease=main:' + git('ls-remote', 'origin', 'main', cwd=repo).stdout.split()[0],
                 cwd=repo, check=False)
    assert 'ContextGuard stopped this push' in result.stderr
    assert 'could not check' not in result.stderr
