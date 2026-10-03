from pathlib import Path

import pytest

from engine import pdf_scan
from engine.scan_text import Scanner
from notify.confirm_dialog import dialog_text

FIXTURES = Path(__file__).resolve().parent.parent / 'fixtures' / 'pdf'


def _read(name):
    return pdf_scan.read_pdf((FIXTURES / name).read_bytes())


def _blocked(text):
    scanner = Scanner()
    found = set()
    for chunk in pdf_scan.texts_to_scan(text):
        found.update(scanner.blocking_categories(chunk))
    return found


def test_a_key_on_one_line_is_extracted_and_caught():
    result = _read('key_on_one_line.pdf')
    assert result['pages'] == 1
    assert 'secret.aws_access_token' in _blocked(result['text'])


def test_a_key_wrapped_across_lines_is_caught_by_the_joined_copy():
    # Measured in the bake-off: the layout splits the token over two lines,
    # and only the copy with line breaks removed still matches its format.
    text = _read('key_wrapped_across_lines.pdf')['text']
    assert 'secret.github_pat' not in Scanner().blocking_categories(text)
    assert 'secret.github_pat' in _blocked(text)


def test_a_clean_pdf_has_nothing_to_block():
    assert _blocked(_read('clean.pdf')['text']) == set()


@pytest.mark.parametrize('name, reason', [
    ('fifty_one_pages.pdf', 'too_many_pages'),
    ('password_protected.pdf', 'locked'),
    ('image_only.pdf', 'no_text'),
])
def test_pdfs_that_cannot_be_checked_say_why(name, reason):
    assert _read(name)['reason'] == reason


def test_garbage_is_unreadable_not_a_crash():
    assert pdf_scan.read_pdf(b'%PDF-1.7 this is not really a pdf')['reason'] == 'unreadable'


def test_oversized_pdfs_are_not_even_opened(monkeypatch):
    monkeypatch.setattr(pdf_scan, 'MAX_BYTES', 10)
    assert pdf_scan.extract(b'%PDF-' + b'x' * 100) == {'reason': 'too_large'}


def test_extract_reads_the_pdf_in_a_separate_process():
    result = pdf_scan.extract((FIXTURES / 'key_on_one_line.pdf').read_bytes())
    assert 'AKIAABCDEFGHIJKLMNOP' in result['text']


def test_not_scanned_popup_says_why_and_asks_to_double_check():
    title, body, hint = dialog_text('file.not_scanned.too_many_pages', 'chatgpt.com')
    assert title == 'This PDF was not checked'
    assert 'more than 50 pages' in body and 'chatgpt.com' in body
    assert 'Double-check' in hint
