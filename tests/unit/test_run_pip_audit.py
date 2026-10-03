import sys

from scripts.run_pip_audit import IGNORE_FILE, build_command, load_ignored_ids


def test_shared_ignore_file_loads_ids_and_skips_comments():
    ids = load_ignored_ids()
    assert ids, f'{IGNORE_FILE} is empty'
    assert all(not i.startswith('#') and ' ' not in i for i in ids)
    assert len(ids) == len(set(ids))


def test_comment_and_blank_lines_are_ignored(tmp_path):
    f = tmp_path / 'ignore.txt'
    f.write_text('# header\n\nPYSEC-1\n  GHSA-x  \n# trailing\n', encoding='utf-8')
    assert load_ignored_ids(f) == ['PYSEC-1', 'GHSA-x']


def test_build_command_adds_each_ignore_then_passthrough_args():
    cmd = build_command(['--format', 'cyclonedx-json'], ['A', 'B'])
    assert cmd == [sys.executable, '-m', 'pip_audit',
                   '--ignore-vuln', 'A', '--ignore-vuln', 'B', '--format', 'cyclonedx-json']
