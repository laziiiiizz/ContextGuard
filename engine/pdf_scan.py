"""Reads the text of an uploaded PDF so the normal detectors can check it.

PDFium (the engine inside pypdfium2) is not thread-safe, and a malformed
file can crash it, so the reading happens in a short-lived separate process
(this same app started with --extract-pdf) with a time limit. A crash or
hang there can only fail that one check, never the proxy.

A PDF that can't be fully read (too big, too many pages, password, images
only, damaged, too slow) is reported with a reason instead of text, so the
user can be told it was NOT checked rather than letting it pass silently.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_PAGES = 50
MAX_BYTES = 25 * 1024 * 1024
EXTRACT_TIMEOUT_SECONDS = 10

NOT_SCANNED = 'file.not_scanned'
REASONS = ('too_large', 'too_many_pages', 'locked', 'no_text', 'unreadable', 'timeout')


def is_pdf(data: bytes) -> bool:
    # The PDF spec lets the %PDF- marker sit anywhere in the first 1024 bytes.
    return b'%PDF-' in data[:1024]


def read_pdf(data: bytes) -> dict:
    """{'pages': n, 'text': ...} or {'reason': one of REASONS}. Runs PDFium
    in the calling process: only call this from the worker."""
    import pypdfium2 as pdfium
    try:
        pdf = pdfium.PdfDocument(data)
    except pdfium.PdfiumError as error:
        return {'reason': 'locked' if 'password' in str(error).lower() else 'unreadable'}
    try:
        pages = len(pdf)
        if pages > MAX_PAGES:
            return {'reason': 'too_many_pages', 'pages': pages}
        chunks = []
        for index in range(pages):
            page = pdf[index]
            textpage = page.get_textpage()
            chunks.append(textpage.get_text_bounded())
            textpage.close()
            page.close()
    except pdfium.PdfiumError:
        return {'reason': 'unreadable'}
    finally:
        pdf.close()
    text = '\n'.join(chunks)
    if not text.strip():
        return {'reason': 'no_text', 'pages': pages}
    return {'pages': pages, 'text': text}


def worker_main(argv: list[str]) -> int:
    """`--extract-pdf <in-file> <out-file>`: reads the PDF, writes JSON."""
    in_path, out_path = Path(argv[0]), Path(argv[1])
    out_path.write_text(json.dumps(read_pdf(in_path.read_bytes())), encoding='utf-8')
    return 0


def _worker_command() -> list[str]:
    if getattr(sys, 'frozen', False):
        return [sys.executable, '--extract-pdf']
    from proxy.paths import get_app_root
    return [sys.executable, str(get_app_root() / 'gui' / 'app.py'), '--extract-pdf']


def extract(data: bytes) -> dict:
    """Same result shape as read_pdf(), produced in a separate process."""
    if len(data) > MAX_BYTES:
        return {'reason': 'too_large'}
    folder = tempfile.mkdtemp(prefix='contextguard-pdf-')
    in_path, out_path = os.path.join(folder, 'in.pdf'), os.path.join(folder, 'out.json')
    try:
        with open(in_path, 'wb') as f:
            f.write(data)
        try:
            subprocess.run(_worker_command() + [in_path, out_path], timeout=EXTRACT_TIMEOUT_SECONDS,
                           capture_output=True, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except subprocess.TimeoutExpired:
            return {'reason': 'timeout'}
        try:
            with open(out_path, encoding='utf-8') as f:
                return json.load(f)
        except (OSError, ValueError):
            return {'reason': 'unreadable'}  # the worker crashed before writing a result
    finally:
        for path in (in_path, out_path):
            try:
                os.remove(path)
            except OSError:
                pass
        try:
            os.rmdir(folder)
        except OSError:
            pass


def texts_to_scan(text: str) -> list[str]:
    """The text as extracted, plus a copy with line breaks removed: a key
    that the page layout wrapped onto two lines comes out split in two, and
    only the joined copy still matches its format."""
    return [text, re.sub(r'\s*\n\s*', '', text)]
