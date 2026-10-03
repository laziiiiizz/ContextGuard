# mitmproxy addon: checks outgoing requests to watched AI sites and blocks,
# masks or warns about secrets and personal data before they leave this PC.
import asyncio
import json
import os
import sys
import time
import traceback
import urllib.parse
import zlib
from email.parser import BytesParser
from email.policy import HTTP as HTTP_POLICY
from pathlib import Path

import yaml
from mitmproxy import http, tls

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import pdf_scan
from engine.alias_vault import AliasVault
from engine.context_score import adjust_confidence
from engine.detectors import allowlist, context_rules, entropy, regex_rules
from engine.normalize import fold_confusables, normalize
from engine.policy import evaluate, load_policy
from engine.policy_signing import verify_policy_signature
from engine.transform import generalize, mask, remove, tokenize
from engine.user_settings import is_category_enabled
from notify.confirm_dialog import ask_send_anyway
from notify.native import notify
from proxy.paths import get_writable_data_dir
from telemetry.logger import log_event

# Never log raw content by default -- opt in only for local debugging.
DEBUG_LOG_RAW_CONTENT = os.environ.get('CONTEXTGUARD_DEBUG_LOG_RAW') == '1'


def _safe_print(message: str) -> None:
    """print() that can never fail. On Windows some text can't be printed in
    the console's encoding; that must not look like a failed check."""
    try:
        print(message)
    except UnicodeEncodeError:
        try:
            print(message.encode('ascii', 'backslashreplace').decode('ascii'))
        except Exception:
            pass  # diagnostics must never themselves become a new failure mode


def _log_crash(where: str) -> None:
    """Saves the last error to last_addon_error.log, since the installed app
    has no console. Only the error is written, never the request, so no
    secret ends up in the file."""
    try:
        path = get_writable_data_dir() / 'last_addon_error.log'
        path.write_text(f'[{where}]\n{traceback.format_exc()}', encoding='utf-8')
    except Exception:
        pass  # diagnostics must never themselves become a new failure mode


def _log_unrecognized_shape(flow: 'http.HTTPFlow', where: str, body_text: str) -> None:
    """Debug only (CONTEXTGUARD_DEBUG_LOG_RAW=1): records requests whose
    format we don't recognize, to help add support for them. Off by default
    because the body can contain private text."""
    if not DEBUG_LOG_RAW_CONTENT or flow.request.method != 'POST':
        return
    try:
        host = flow.request.pretty_host
        path = get_writable_data_dir() / 'unrecognized_shapes.log'
        headers = {k: v for k, v in flow.request.headers.items()
                   if k.lower() in ('content-type', 'content-length', 'transfer-encoding')}
        entry = (f'[{where}] host={host} method={flow.request.method} '
                 f'path={flow.request.path} headers={headers}\n'
                 f'{body_text[:2000]}\n{"=" * 60}\n')
        existing = path.read_text(encoding='utf-8') if path.exists() else ''
        # Keep only the last 20 entries.
        entries = (existing + entry).split('=' * 60 + '\n')[-20:]
        path.write_text(('=' * 60 + '\n').join(entries), encoding='utf-8')
    except Exception:
        pass

# If anything below fails to load (a bad signature, a lost key), mitmproxy
# would otherwise run with no checks at all while the app still shows Active.
# So every risky step is wrapped: on failure, _FailClosedAddon (at the bottom
# of this file) is used instead and blocks all AI sites until it is fixed.
_INIT_ERROR = None
try:
    # The list of watched sites is signed too, so nobody can quietly remove a site.
    verify_policy_signature(Path('proxy/domains.yaml'))  # raises PolicyIntegrityError, fail-safe
    with open('proxy/domains.yaml', encoding='utf-8') as f:
        # Lowercase here and when matching: host names ignore case.
        _domain_rows = [row for row in yaml.safe_load(f) if row['enabled']]
        WATCHLIST = {row['hostname'].lower() for row in _domain_rows}
        # Shared upload servers: only PDF uploads there are checked.
        UPLOAD_ONLY_HOSTS = {row['hostname'].lower() for row in _domain_rows
                             if row.get('category') == 'file-upload'}

    POLICY_RULES = load_policy()
    ALLOWLIST = allowlist.load_allowlist()
except Exception:
    _INIT_ERROR = traceback.format_exc()


def is_watched_host(host: str) -> bool:
    """True for a watched site or any subdomain of it (for example
    www.perplexity.ai when perplexity.ai is listed)."""
    host = host.lower()
    return host in WATCHLIST or any(host.endswith('.' + w) for w in WATCHLIST)


def is_upload_only_host(host: str) -> bool:
    """Same subdomain matching as is_watched_host(): OpenAI's file storage
    has a different subdomain per region (sdmntpr<region>.oaiusercontent.com)."""
    host = host.lower()
    return host in UPLOAD_ONLY_HOSTS or any(host.endswith('.' + h) for h in UPLOAD_ONLY_HOSTS)


def _log_every_matched_request(flow: 'http.HTTPFlow', host: str) -> None:
    """Debug only: logs every request to a watched site, to see when a
    site sends one message in several requests."""
    if not DEBUG_LOG_RAW_CONTENT:
        return
    try:
        import time as _time
        path = get_writable_data_dir() / 'all_matched_requests.log'
        entry = (f'{_time.time():.3f} host={host} method={flow.request.method} '
                 f'path={flow.request.path}\n')
        existing = path.read_text(encoding='utf-8') if path.exists() else ''
        lines = (existing + entry).splitlines(keepends=True)[-100:]
        path.write_text(''.join(lines), encoding='utf-8')
    except Exception:
        pass


# Same safety net as above: opening the vault can fail if its key was lost.
if _INIT_ERROR is None:
    try:
        VAULT = AliasVault()
    except Exception:
        _INIT_ERROR = traceback.format_exc()


def run_pipeline(content: str) -> list:
    findings = regex_rules.run(content) + entropy.run(content) + context_rules.run(content)
    findings = allowlist.filter_findings(findings, ALLOWLIST)
    findings = [adjust_confidence(f, 'public-ai') for f in findings]
    # Detection kinds the user switched off in Settings are dropped here, so
    # they are neither acted on nor logged.
    findings = [f for f in findings if is_category_enabled(f.category)]
    return evaluate(findings, POLICY_RULES, destination_class='public-ai')


def drop_overlapping_spans(decisions: list) -> list:
    """Drops overlapping transform spans so substitution can't corrupt text."""
    kept = []
    last_end = -1
    for d in sorted(decisions, key=lambda d: d.finding.span_start):
        if d.finding.span_start >= last_end:
            kept.append(d)
            last_end = d.finding.span_end
    return kept


def extract_text(content) -> str:
    """Gets the text out of a message's `content`, which can be:
    - a plain string
    - a list of text blocks (OpenAI and Anthropic APIs)
    - Anthropic tool_result blocks: data a tool sent back, which can hold
      secrets too
    - ChatGPT's website format: {"content_type": "text", "parts": [...]}
    Images and the model's own tool calls are skipped. Anything else raises,
    so the caller blocks instead of guessing."""
    if isinstance(content, str):
        return content
    if isinstance(content, dict) and isinstance(content.get('parts'), list):
        return ' '.join(p for p in content['parts'] if isinstance(p, str))
    if isinstance(content, list):
        parts = []
        for block in content:
            if not isinstance(block, dict):
                continue
            # 'input_text' is the OpenAI Responses API's name for user text.
            if block.get('type') in ('text', 'input_text'):
                parts.append(block.get('text', ''))
            elif block.get('type') == 'tool_result':
                nested = block.get('content')
                if isinstance(nested, str):
                    parts.append(nested)
                elif isinstance(nested, list):
                    parts.append(extract_text(nested))
        return ' '.join(parts)
    raise TypeError(f'unsupported content shape: {type(content).__name__}')


# Message roles whose text is checked. System and developer prompts are
# often built by apps and can hold config values or keys; tool and function
# results are data sent back from tools. The model's own replies ('assistant')
# are skipped: the site already has them.
SCANNABLE_ROLES = {'user', 'system', 'developer', 'tool', 'function'}


def _body_has_a_known_shape_key(body: dict) -> bool:
    """True if the body has at least one field we know how to read, with a
    real value in it. Tells "we know this format, it just has nothing to
    check" apart from "we don't know this format" (which gets the fallback
    scan). An empty field doesn't count, so a secret hidden under some other
    field name can't slip past by sitting next to an empty known field.
    Keep in step with extract_all_user_turns()."""
    messages = body.get('messages')
    if isinstance(messages, list) and messages:
        return True
    contents = body.get('contents')
    if isinstance(contents, list) and contents:
        return True
    if 'system' in body and body['system'] not in (None, ''):
        return True
    system_instruction = body.get('systemInstruction')
    if isinstance(system_instruction, dict) and isinstance(system_instruction.get('parts'), list):
        return True
    input_field = body.get('input')
    if isinstance(input_field, str) and input_field:
        return True
    if isinstance(input_field, list) and input_field:
        return True
    instructions = body.get('instructions')
    if isinstance(instructions, str) and instructions:
        return True
    prompt = body.get('prompt')
    if isinstance(prompt, str) and prompt:
        return True
    query_str = body.get('query_str')
    if isinstance(query_str, str) and query_str:
        return True
    inputs = body.get('inputs')
    if isinstance(inputs, str) and inputs:
        return True
    return False


def extract_all_user_turns(body: dict) -> list[tuple[str, object, object]]:
    """Finds every piece of text to check in a request, not just the newest
    message. Chat apps resend the whole conversation every time, so a secret
    in an old message goes out again with every new one.
    Returns (field name, index or None, content) for each piece. Covers the
    OpenAI, Anthropic and Gemini APIs, ChatGPT's and Claude's websites,
    Perplexity, HuggingChat, and system prompts."""
    turns = []

    messages = body.get('messages')
    if isinstance(messages, list):
        for i, m in enumerate(messages):
            if not isinstance(m, dict):
                continue
            # ChatGPT's website puts the role under `author` instead.
            role = m.get('role')
            if role is None and isinstance(m.get('author'), dict):
                role = m['author'].get('role')
            if role in SCANNABLE_ROLES:
                turns.append(('messages', i, m.get('content', '')))

    contents = body.get('contents')
    if isinstance(contents, list):
        for i, c in enumerate(contents):
            if not isinstance(c, dict):
                continue
            parts = c.get('parts')
            if not isinstance(parts, list):
                continue
            if c.get('role') == 'user':
                # Gemini keeps its system prompt in systemInstruction, below.
                turns.append(('contents', i, [
                    {'type': 'text', 'text': p['text']}
                    for p in parts if isinstance(p, dict) and 'text' in p
                ]))
            elif c.get('role') == 'function':
                # Data a function sent back to Gemini. It can be any JSON,
                # so it is turned into text to check.
                fn_texts = [
                    json.dumps(p['functionResponse'].get('response', ''))
                    for p in parts
                    if isinstance(p, dict) and isinstance(p.get('functionResponse'), dict)
                ]
                if fn_texts:
                    turns.append(('contents_function_response', i,
                                   [{'type': 'text', 'text': t} for t in fn_texts]))

    # Anthropic's system prompt: a string or a list of text blocks.
    if 'system' in body and body['system'] not in (None, ''):
        turns.append(('system', None, body['system']))

    # Gemini's system prompt.
    system_instruction = body.get('systemInstruction')
    if isinstance(system_instruction, dict):
        parts = system_instruction.get('parts')
        if isinstance(parts, list):
            turns.append(('systemInstruction', None, [
                {'type': 'text', 'text': p['text']}
                for p in parts if isinstance(p, dict) and 'text' in p
            ]))

    # OpenAI's Responses API uses `input` and `instructions`. The Embeddings
    # and Moderations APIs use `input` as a list of strings.
    input_field = body.get('input')
    if isinstance(input_field, str) and input_field:
        turns.append(('input', None, input_field))
    elif isinstance(input_field, list):
        for i, item in enumerate(input_field):
            if isinstance(item, str) and item:
                turns.append(('input_items', i, item))
                continue
            if not isinstance(item, dict):
                continue
            item_type = item.get('type')
            if item_type == 'function_call_output':
                # Data a tool sent back.
                turns.append(('input_items', i, item.get('output', '')))
            elif item.get('role') in SCANNABLE_ROLES and item_type in (None, 'message'):
                turns.append(('input_items', i, item.get('content', '')))

    instructions = body.get('instructions')
    if isinstance(instructions, str) and instructions:
        turns.append(('instructions', None, instructions))

    # Claude's website: the typed message is in `prompt`.
    prompt = body.get('prompt')
    if isinstance(prompt, str) and prompt:
        turns.append(('prompt', None, prompt))

    # Perplexity's website: the typed message is in `query_str`.
    query_str = body.get('query_str')
    if isinstance(query_str, str) and query_str:
        turns.append(('query_str', None, query_str))

    # HuggingChat: the typed message is in `inputs`, inside a multipart field.
    inputs = body.get('inputs')
    if isinstance(inputs, str) and inputs:
        turns.append(('inputs', None, inputs))

    return turns


def extract_batchexecute_text(body_text: str) -> list[str]:
    """Gets the typed message out of Gemini's website format ("batchexecute"):
    a form field holding JSON inside JSON. Returns [] if it doesn't match."""
    try:
        params = urllib.parse.parse_qs(body_text)
        freq_values = params.get('f.req')
        if not freq_values:
            return []
        outer = json.loads(freq_values[0])
        if not isinstance(outer, list) or len(outer) < 2 or not isinstance(outer[1], str):
            return []
        inner = json.loads(outer[1])
        if not isinstance(inner, list) or not inner:
            return []
        first = inner[0]
        if not isinstance(first, list) or not first:
            return []
        text = first[0]
        return [text] if isinstance(text, str) and text else []
    except (ValueError, TypeError, IndexError, KeyError):
        return []


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Reads one protobuf number at `pos`. Returns (value, new position).
    Raises ValueError on broken input instead of reading past the end."""
    shift = 0
    value = 0
    while True:
        if pos >= len(data):
            raise ValueError('truncated varint')
        if shift > 63:
            raise ValueError('varint too long')
        byte = data[pos]
        value |= (byte & 0x7F) << shift
        pos += 1
        if not (byte & 0x80):
            return value, pos
        shift += 7


class ConnectProtoParseError(Exception):
    """The body looks like Claude Design's binary format but can't be read to
    the end. Unlike a body in some other format, this is blocked: we can't
    tell whether it is clean."""


# Limit for unzipping a request. A tiny "zip bomb" could otherwise grow to
# gigabytes and freeze the proxy.
MAX_DECOMPRESSED_CONNECT_BYTES = 20 * 1024 * 1024


def _bounded_gzip_decompress(data: bytes, max_size: int) -> bytes:
    """Unzips in steps and stops as soon as the result passes `max_size`,
    so a zip bomb never fills memory."""
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)  # 16+ selects gzip framing
    out = bytearray(decompressor.decompress(data, max_size + 1))
    while decompressor.unconsumed_tail and len(out) <= max_size:
        out.extend(decompressor.decompress(decompressor.unconsumed_tail, max_size + 1 - len(out)))
    if len(out) > max_size:
        raise ConnectProtoParseError('decompressed content exceeds safety cap')
    return bytes(out)


def _skip_group(message: bytes, pos: int, field_number: int) -> int:
    """Skips an old-style protobuf "group" field. Claude Design still sends
    them. Raises if the group is broken, so the request is blocked."""
    while True:
        if pos >= len(message):
            raise ConnectProtoParseError('unterminated group')
        tag, pos = _read_varint(message, pos)
        inner_field_number = tag >> 3
        wire_type = tag & 0x7
        if wire_type == 4:  # EGROUP
            if inner_field_number != field_number:
                raise ConnectProtoParseError('mismatched EGROUP field number')
            return pos
        elif wire_type == 0:  # varint
            _, pos = _read_varint(message, pos)
        elif wire_type == 1:  # 64-bit fixed
            if pos + 8 > len(message):
                raise ConnectProtoParseError('64-bit field overruns message')
            pos += 8
        elif wire_type == 2:  # length-delimited
            length, pos = _read_varint(message, pos)
            if length < 0 or pos + length > len(message):
                raise ConnectProtoParseError('length-delimited field overruns message')
            pos += length
        elif wire_type == 3:  # nested SGROUP
            pos = _skip_group(message, pos, inner_field_number)
        elif wire_type == 5:  # 32-bit fixed
            if pos + 4 > len(message):
                raise ConnectProtoParseError('32-bit field overruns message')
            pos += 4
        else:
            raise ConnectProtoParseError(f'unsupported wire type {wire_type} inside group')


def extract_connect_proto_json(body: bytes) -> dict | None:
    """Gets the JSON request out of Claude Design's binary format
    (Connect-RPC: 1 flag byte, 4 length bytes, then protobuf). There is no
    published schema, so it walks the fields and returns the first one that
    is JSON with a `messages` list.
    Returns None if the body isn't this format at all. Raises
    ConnectProtoParseError if it is this format but can't be read (blocked).
    It is never rewritten, only checked."""
    if len(body) < 5:
        return None
    flag = body[0]
    frame_len = int.from_bytes(body[1:5], 'big')
    if frame_len != len(body) - 5:
        return None  # not a single well-formed unary frame -- not this format
    message = body[5:5 + frame_len]
    try:
        if flag & 0x01:
            message = _bounded_gzip_decompress(message, MAX_DECOMPRESSED_CONNECT_BYTES)
        pos = 0
        while pos < len(message):
            tag, pos = _read_varint(message, pos)
            field_number = tag >> 3
            wire_type = tag & 0x7
            if wire_type == 0:  # varint
                _, pos = _read_varint(message, pos)
            elif wire_type == 1:  # 64-bit fixed
                if pos + 8 > len(message):
                    raise ConnectProtoParseError('64-bit field overruns message')
                pos += 8
            elif wire_type == 2:  # length-delimited
                length, pos = _read_varint(message, pos)
                if length < 0 or pos + length > len(message):
                    raise ConnectProtoParseError('length-delimited field overruns message')
                value = message[pos:pos + length]
                pos += length
                try:
                    candidate = json.loads(value)
                except (ValueError, TypeError):
                    continue
                if isinstance(candidate, dict) and isinstance(candidate.get('messages'), list):
                    return candidate
            elif wire_type == 3:  # SGROUP -- deprecated but legal, skip via its matching EGROUP
                pos = _skip_group(message, pos, field_number)
            elif wire_type == 5:  # 32-bit fixed
                if pos + 4 > len(message):
                    raise ConnectProtoParseError('32-bit field overruns message')
                pos += 4
            else:
                # A field we can't skip safely: block rather than guess.
                raise ConnectProtoParseError(f'unsupported wire type {wire_type}')
        return None  # well-formed envelope, no recognizable JSON field in it
    except ConnectProtoParseError:
        raise
    except (ValueError, TypeError, IndexError, EOFError, OSError, zlib.error) as e:
        raise ConnectProtoParseError(str(e)) from e


# Bodies in a format we don't recognize get a plain-text scan, up to this
# size. Bigger ones are skipped so the scan can't slow the proxy down.
_FALLBACK_SCAN_MAX_BYTES = 200_000


def extract_multipart_json(body: bytes, content_type: str) -> dict | None:
    """Returns the first non-file field of a multipart/form-data body whose
    value is a JSON object, else None. HuggingChat sends its message JSON
    this way, in a field named `data`. File parts are skipped here; PDF files
    are checked separately by find_pdfs()."""
    if not content_type or 'multipart/form-data' not in content_type.lower():
        return None
    try:
        header = f'Content-Type: {content_type}\r\n\r\n'.encode('latin-1')
        message = BytesParser(policy=HTTP_POLICY).parsebytes(header + body)
    except (UnicodeEncodeError, ValueError):
        return None
    if not message.is_multipart():
        return None
    for part in message.iter_parts():
        if part.get_filename():
            continue
        try:
            value = json.loads(part.get_payload(decode=True) or b'')
        except (ValueError, TypeError):
            continue
        if isinstance(value, dict):
            return value
    return None


def find_pdfs(body: bytes, content_type: str) -> list[bytes]:
    """PDF files in a request: the whole body (a direct file upload) or the
    file parts of a multipart/form-data body."""
    if pdf_scan.is_pdf(body):
        return [body]
    if not content_type or 'multipart/form-data' not in content_type.lower() or b'%PDF-' not in body:
        return []
    try:
        header = f'Content-Type: {content_type}\r\n\r\n'.encode('latin-1')
        message = BytesParser(policy=HTTP_POLICY).parsebytes(header + body)
    except (UnicodeEncodeError, ValueError):
        return []
    if not message.is_multipart():
        return []
    found = []
    for part in message.iter_parts():
        payload = part.get_payload(decode=True) or b''
        if pdf_scan.is_pdf(payload):
            found.append(payload)
    return found


# PDFs are read in separate worker processes; this caps how many run at once.
_PDF_WORKERS = asyncio.Semaphore(2)


async def _check_pdf_uploads(flow: http.HTTPFlow, host: str, pdfs: list[bytes]) -> None:
    """Blocks (after the usual Don't Send / Send Anyway choice) a PDF that
    contains a blockable secret, or one that could not be checked at all.
    Mask and warn findings are not acted on: a PDF can't be edited in place."""
    loop = asyncio.get_running_loop()
    for data in pdfs:
        start = time.perf_counter()
        async with _PDF_WORKERS:
            result = await loop.run_in_executor(None, pdf_scan.extract, data)
        if 'reason' in result:
            category = f"{pdf_scan.NOT_SCANNED}.{result['reason']}"
            latency_ms = (time.perf_counter() - start) * 1000
            sent_anyway = await _confirm_or_block(flow, host, category)
            log_event(rule_id=category, category=category, action='send_anyway' if sent_anyway else 'block',
                      latency_ms=latency_ms, destination_host=host)
            if not sent_anyway:
                return
            continue
        blocking, seen = [], set()
        for text in pdf_scan.texts_to_scan(result['text']):
            for decision in run_pipeline(text):
                if decision.action == 'block' and decision.finding.category not in seen:
                    seen.add(decision.finding.category)
                    blocking.append(decision)
        latency_ms = (time.perf_counter() - start) * 1000
        if not blocking:
            continue
        sent_anyway = await _confirm_or_block(flow, host, blocking[0].finding.category)
        for d in blocking:
            log_event(rule_id=d.finding.category, category=d.finding.category,
                      action='send_anyway' if sent_anyway else 'block', latency_ms=latency_ms,
                      destination_host=host)
        if not sent_anyway:
            return


async def _scan_unrecognized_body_as_fallback(flow: http.HTTPFlow, host: str, body_text: str) -> None:
    """For a body in a format we don't recognize: scan its raw text anyway.
    Sites change their formats often; finding a secret doesn't need to know
    the format, only rewriting it does. So these bodies can be blocked, just
    not masked. Skips non-POST requests and bodies over the size limit."""
    if flow.request.method != 'POST' or len(body_text) > _FALLBACK_SCAN_MAX_BYTES:
        return
    start = time.perf_counter()
    decisions = run_pipeline(fold_confusables(normalize(body_text)))
    latency_ms = (time.perf_counter() - start) * 1000
    # Block-tier findings only. A body no parser recognized is mostly the
    # site's own background traffic (analytics, session and telemetry
    # payloads full of random-looking tokens), so warn-tier findings here
    # were thousands of meaningless warnings per browsing session.
    blocking = [d for d in decisions if d.action == 'block']
    await _block_or_warn_only(flow, host, blocking, latency_ms)


# One "Heads up" toast per category and host per this many seconds. Chat
# clients resend the whole conversation on every request, so one flagged
# line would otherwise raise the same toast again on every later message.
_WARN_TOAST_COOLDOWN_SECONDS = 60.0
_last_warn_toast: dict[tuple[str, str], float] = {}


def _notify_warning(category: str, host: str) -> None:
    now = time.monotonic()
    last = _last_warn_toast.get((category, host))
    if last is not None and now - last < _WARN_TOAST_COOLDOWN_SECONDS:
        return
    _last_warn_toast[(category, host)] = now
    notify('ContextGuard', f'Heads up: possible {category} sent to {host}')


async def _block_or_warn_only(flow: http.HTTPFlow, host: str, decisions: list, latency_ms: float) -> None:
    """Block or warn for formats we can't safely rewrite (Gemini, Claude
    Design, HuggingChat): anything that would be masked becomes a warning."""
    blocking = [d for d in decisions if d.action == 'block']
    if blocking:
        first = blocking[0]
        sent_anyway = await _confirm_or_block(flow, host, first.finding.category)
        for d in blocking:
            log_event(rule_id=d.finding.category, category=d.finding.category,
                      action='send_anyway' if sent_anyway else 'block',
                      latency_ms=latency_ms, destination_host=host)
        return
    for d in [d for d in decisions if d.action in ('warn', 'transform')]:
        log_event(rule_id=d.finding.category, category=d.finding.category,
                  action='warn', latency_ms=latency_ms, destination_host=host)
        _notify_warning(d.finding.category, host)


def _replace_text_blocks(blocks: list, text: str, text_key: str) -> list:
    """Puts the new text into the first text block and drops the other text
    blocks (their text is already included). Images and other blocks stay."""
    rewritten = []
    replaced = False
    for block in blocks:
        is_text = isinstance(block, dict) and text_key in block
        if is_text:
            if not replaced:
                rewritten.append({**block, text_key: text})
                replaced = True
            continue
        rewritten.append(block)
    if not replaced:
        rewritten.append({text_key: text})
    return rewritten


def _write_message_content_blocks(blocks: list, text: str) -> list:
    """Like _replace_text_blocks, but can also write into an Anthropic
    tool_result block, whose text sits under block['content']. A normal
    text block is used first if there is one."""
    has_top_level_text = any(isinstance(b, dict) and 'text' in b for b in blocks)
    has_tool_result = any(isinstance(b, dict) and b.get('type') == 'tool_result' for b in blocks)
    if has_top_level_text or not has_tool_result:
        return _replace_text_blocks(blocks, text, 'text')

    rewritten = []
    replaced = False
    for block in blocks:
        if not replaced and isinstance(block, dict) and block.get('type') == 'tool_result':
            nested = block.get('content')
            new_block = dict(block)
            new_block['content'] = (
                _replace_text_blocks(nested, text, 'text') if isinstance(nested, list) else text
            )
            rewritten.append(new_block)
            replaced = True
        else:
            rewritten.append(block)
    return rewritten


def write_user_turn(body: dict, list_key: str, index: object, text: str) -> None:
    """Writes the masked text back into the same place it was read from
    (see extract_all_user_turns). Images and other blocks are kept."""
    if list_key == 'messages':
        message = body['messages'][index]
        original = message.get('content')
        if isinstance(original, dict) and isinstance(original.get('parts'), list):
            # ChatGPT's website: change only `parts`, keep the rest as is.
            original['parts'] = [text]
        elif isinstance(original, list):
            message['content'] = _write_message_content_blocks(original, text)
        else:
            message['content'] = text
        return

    if list_key == 'contents':
        turn = body['contents'][index]
        parts = turn.get('parts')
        if isinstance(parts, list):
            turn['parts'] = _replace_text_blocks(parts, text, 'text')
        else:
            turn['parts'] = [{'text': text}]
        return

    if list_key == 'contents_function_response':
        # Masking text inside arbitrary JSON could break it, so this raises
        # and the caller blocks the request instead. Only affects mask-level
        # findings; secrets are blocked before this point anyway.
        raise RuntimeError(
            'functionResponse transform write-back is not supported -- failing safe')

    if list_key == 'system':
        # A string or a list of text blocks, like messages[].content.
        original = body.get('system')
        if isinstance(original, list):
            body['system'] = _replace_text_blocks(original, text, 'text')
        else:
            body['system'] = text
        return

    if list_key == 'systemInstruction':
        system_instruction = body['systemInstruction']
        parts = system_instruction.get('parts')
        if isinstance(parts, list):
            system_instruction['parts'] = _replace_text_blocks(parts, text, 'text')
        else:
            system_instruction['parts'] = [{'text': text}]
        return

    if list_key == 'input':
        # OpenAI Responses API with plain-text `input`.
        body['input'] = text
        return

    if list_key == 'input_items':
        item = body['input'][index]
        if isinstance(item, str):
            # Embeddings/Moderations: a plain string in the list.
            body['input'][index] = text
            return
        if item.get('type') == 'function_call_output':
            item['output'] = text
            return
        original = item.get('content')
        if isinstance(original, list):
            item['content'] = _write_message_content_blocks(original, text)
        else:
            item['content'] = text
        return

    if list_key == 'instructions':
        body['instructions'] = text
        return

    if list_key == 'prompt':
        # Claude's website.
        body['prompt'] = text
        return

    if list_key == 'query_str':
        # Perplexity sends the same text twice; both copies must be changed
        # or the secret still goes out in the other one.
        body['query_str'] = text
        params = body.get('params')
        if isinstance(params, dict):
            params['dsl_query'] = text
        return

    if list_key == 'inputs':
        body['inputs'] = text


async def _confirm_or_block(flow: http.HTTPFlow, host: str, category: str) -> bool:
    """Shows the Don't Send / Send Anyway popup. On Don't Send (or no answer
    in time) it answers the request with a 403 and returns False. On Send
    Anyway it returns True and the request goes out unchanged.
    The popup runs on a separate thread so other requests keep moving
    while it waits."""
    from notify.confirm_dialog import _debug_log
    loop = asyncio.get_running_loop()
    _debug_log(f'_confirm_or_block: awaiting run_in_executor for category={category} host={host}')
    try:
        send_anyway = await loop.run_in_executor(None, ask_send_anyway, category, host)
    except asyncio.CancelledError:
        _debug_log('_confirm_or_block: AWAIT WAS CANCELLED by the event loop')
        raise
    _debug_log(f'_confirm_or_block: await returned send_anyway={send_anyway}')
    if send_anyway:
        notify('ContextGuard', f'Sent anyway: {category} to {host} (user override)')
        return True
    flow.response = http.Response.make(
        403,
        json.dumps({'error': 'blocked_by_contextguard', 'category': category}),
        {'Content-Type': 'application/json'},
    )
    notify('ContextGuard', f'Blocked: {category} heading to {host}')
    return False


class ContextGuardAddon:
    async def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        """Runs before any decryption. Connections to sites we don't watch
        (banking, email, everything else) pass through untouched and are
        never decrypted. If a connection names no site, it is decrypted to be
        safe, and request() checks it."""
        sni = data.client_hello.sni
        if sni and not is_watched_host(sni.lower()):
            data.ignore_connection = True

    async def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        # Check both the Host header and the real server we connected to: the
        # header can be faked to hide a watched site.
        if not (is_watched_host(host) or is_watched_host(flow.request.host)):
            return  # passthrough: do not touch, do not even fully decrypt
        _safe_print(f'[ContextGuard] matched host: {host}')
        _log_every_matched_request(flow, host)

        # An uploaded PDF is checked first. The same request can also carry
        # the chat message (HuggingChat sends both in one multipart body), so
        # unless the PDF check blocked it, the normal checks below still run.
        if flow.request.method in ('POST', 'PUT') and is_category_enabled(pdf_scan.NOT_SCANNED):
            pdfs = find_pdfs(flow.request.content or b'', flow.request.headers.get('content-type', ''))
            if pdfs:
                await _check_pdf_uploads(flow, host, pdfs)
                if flow.response is not None:
                    return
        if is_upload_only_host(host) or is_upload_only_host(flow.request.host):
            return

        try:
            body = json.loads(flow.request.get_text())
        except RecursionError:
            # JSON nested so deep it crashes the parser. We can't check it, so
            # block it (letting the error escape would send it through).
            flow.response = http.Response.make(
                502, b'ContextGuard: request body too deeply nested to safely inspect, blocked by default')
            notify('ContextGuard', 'Request body too deeply nested to inspect — blocked, not passed through.')
            return
        except (ValueError, TypeError):
            # Not JSON. Try the other formats we know, in order. These can be
            # blocked or warned about, never rewritten.
            try:
                body_text = flow.request.get_text()
                batch_texts = extract_batchexecute_text(body_text)
                if batch_texts:
                    start = time.perf_counter()
                    decisions = [d for text in batch_texts
                                 for d in run_pipeline(fold_confusables(normalize(text)))]
                    latency_ms = (time.perf_counter() - start) * 1000
                    await _block_or_warn_only(flow, host, decisions, latency_ms)
                    return

                # Claude Design's binary format. Needs the raw bytes, not text.
                connect_json = extract_connect_proto_json(flow.request.content)
                if connect_json is not None:
                    turns = extract_all_user_turns(connect_json)
                    if turns:
                        start = time.perf_counter()
                        decisions = [d for _, _, raw_content in turns
                                     for d in run_pipeline(fold_confusables(normalize(extract_text(raw_content))))]
                        latency_ms = (time.perf_counter() - start) * 1000
                        await _block_or_warn_only(flow, host, decisions, latency_ms)
                        return
                    # A known format with nothing to check: don't scan the
                    # binary bytes as text (that only causes false alarms).
                    if _body_has_a_known_shape_key(connect_json):
                        return

                # HuggingChat: JSON inside a multipart form. Block or warn only.
                multipart_json = extract_multipart_json(
                    flow.request.content, flow.request.headers.get('content-type', ''))
                if multipart_json is not None and _body_has_a_known_shape_key(multipart_json):
                    turns = extract_all_user_turns(multipart_json)
                    start = time.perf_counter()
                    decisions = [d for _, _, raw_content in turns
                                 for d in run_pipeline(fold_confusables(normalize(extract_text(raw_content))))]
                    latency_ms = (time.perf_counter() - start) * 1000
                    await _block_or_warn_only(flow, host, decisions, latency_ms)
                    return

                _log_unrecognized_shape(flow, 'non-JSON body, not batchexecute, not connect-proto, not multipart JSON', body_text)
                await _scan_unrecognized_body_as_fallback(flow, host, body_text)
                return
            except Exception:
                # If checking itself crashes, block instead of sending unchecked.
                _log_crash('batchexecute/connect-proto branch')
                flow.response = http.Response.make(
                    502, b'ContextGuard: inspection failed, blocked by default')
                notify('ContextGuard', 'Inspection failed — request blocked, not passed through.')
                return

        if not isinstance(body, dict):
            _log_unrecognized_shape(flow, 'JSON but not a dict', flow.request.get_text())
            await _scan_unrecognized_body_as_fallback(flow, host, flow.request.get_text())
            return  # not a chat-message payload

        turns = extract_all_user_turns(body)
        if not turns:
            _log_unrecognized_shape(flow, 'JSON dict, no recognized turn shape', flow.request.get_text())
            # Scan the raw text only if we don't know this format at all. A
            # known format with only the model's own replies has nothing to check.
            if not _body_has_a_known_shape_key(body):
                await _scan_unrecognized_body_as_fallback(flow, host, flow.request.get_text())
            return  # no user turn in a shape we recognize

        start = time.perf_counter()
        try:
            # Check every message, not just the newest (the whole chat is resent).
            per_turn = []  # (list_key, index, content, decisions)
            for list_key, index, raw_content in turns:
                content = normalize(extract_text(raw_content))
                # Check a copy where look-alike letters (Cyrillic, Greek) are
                # swapped for Latin ones, but send the original text on.
                # Positions stay the same, so masking still lines up.
                decisions = run_pipeline(fold_confusables(content))
                per_turn.append((list_key, index, content, decisions))
            if DEBUG_LOG_RAW_CONTENT:
                _safe_print(f'[ContextGuard] extracted content (DEBUG, unsafe for demo): '
                            f'{[c for _, _, c, _ in per_turn]!r}')
            else:
                total_chars = sum(len(c) for _, _, c, _ in per_turn)
                _safe_print(f'[ContextGuard] extracted content: {total_chars} chars '
                            f'across {len(per_turn)} scannable turn(s)')
        except Exception:
            # If checking crashes, block and save the error for debugging.
            _log_crash('plain-JSON per-turn scanning')
            flow.response = http.Response.make(
                502, b'ContextGuard: inspection failed, blocked by default')
            notify('ContextGuard', 'Inspection failed — request blocked, not passed through.')
            return
        latency_ms = (time.perf_counter() - start) * 1000
        session_id = str(flow.client_conn.id)

        blocking = [d for _, _, _, decisions in per_turn for d in decisions if d.action == 'block']
        if blocking:
            first = blocking[0]
            sent_anyway = await _confirm_or_block(flow, host, first.finding.category)
            for d in blocking:
                _safe_print(f'[ContextGuard] {"SEND ANYWAY (user override)" if sent_anyway else "BLOCK"} '
                            f'category={d.finding.category} confidence={d.finding.confidence:.2f} '
                            f'mandatory={d.mandatory}')
                log_event(rule_id=d.finding.category, category=d.finding.category,
                          action='send_anyway' if sent_anyway else 'block',
                          latency_ms=latency_ms, destination_host=host)
            return

        any_transformed = False
        try:
            TRANSFORMS = {'mask': mask, 'tokenize': tokenize, 'generalize': generalize, 'remove': remove}
            for list_key, index, content, decisions in per_turn:
                transforming = drop_overlapping_spans([d for d in decisions if d.action == 'transform'])
                if not transforming:
                    continue
                # Right-to-left so earlier span offsets don't shift as we edit.
                for d in sorted(transforming, key=lambda d: d.finding.span_start, reverse=True):
                    fn = TRANSFORMS[d.transform_type]
                    replacement = fn(d.finding, VAULT, session_id) if fn is tokenize else fn(d.finding)
                    _safe_print(f'[ContextGuard] TRANSFORM ({d.transform_type}) category={d.finding.category}')
                    log_event(rule_id=d.finding.category, category=d.finding.category,
                              action='transform', latency_ms=latency_ms, destination_host=host)
                    content = content[:d.finding.span_start] + replacement + content[d.finding.span_end:]

                write_user_turn(body, list_key, index, content)
                any_transformed = True

            if any_transformed:
                flow.request.text = json.dumps(body)
        except Exception:
            # Fail-safe: don't let the original unmasked content go out.
            _log_crash('transform')
            flow.response = http.Response.make(
                502, b'ContextGuard: transform failed, blocked by default')
            notify('ContextGuard', 'Transform failed — request blocked, not passed through.')
            return

        warning = [d for _, _, _, decisions in per_turn for d in decisions if d.action == 'warn']
        for d in warning:
            # Warn = pass through + quiet toast, no block.
            _safe_print(f'[ContextGuard] WARN category={d.finding.category} '
                        f'confidence={d.finding.confidence:.2f}')
            log_event(rule_id=d.finding.category, category=d.finding.category,
                      action='warn', latency_ms=latency_ms, destination_host=host)
            _notify_warning(d.finding.category, host)


# Written in the code on purpose: used when the signed files failed to load,
# so it can't come from those files.
_FALLBACK_WATCHLIST = frozenset({
    'chat.openai.com', 'chatgpt.com', 'api.openai.com',
    'claude.ai', 'api.anthropic.com',
    'gemini.google.com', 'generativelanguage.googleapis.com',
    'perplexity.ai', 'api.perplexity.ai',
    'huggingface.co', 'api-inference.huggingface.co', 'router.huggingface.co',
})


def _is_fallback_watched_host(host: str) -> bool:
    host = host.lower()
    return host in _FALLBACK_WATCHLIST or any(host.endswith('.' + w) for w in _FALLBACK_WATCHLIST)


class _FailClosedAddon:
    """Used instead of ContextGuardAddon when startup failed (see _INIT_ERROR
    at the top). It blocks every POST to known AI sites, with no popup,
    until the problem is fixed and the app restarts. It uses nothing that
    could have caused the failure, so it can't fail the same way."""

    def __init__(self, reason: str):
        try:
            (get_writable_data_dir() / 'last_addon_error.log').write_text(
                f'[module-level init failed -- ContextGuard is running in fail-closed mode]\n{reason}',
                encoding='utf-8')
        except Exception:
            pass  # diagnostics must never themselves become a new failure mode

    async def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        # Even when broken, don't decrypt sites we don't watch.
        sni = data.client_hello.sni
        if sni and not _is_fallback_watched_host(sni.lower()):
            data.ignore_connection = True

    async def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.method != 'POST':
            return
        if not (_is_fallback_watched_host(flow.request.pretty_host)
                or _is_fallback_watched_host(flow.request.host)):
            return
        flow.response = http.Response.make(
            503,
            b'ContextGuard failed to start correctly and is blocking all traffic to known AI '
            b'hosts as a precaution instead of running uninspected. Check last_addon_error.log '
            b'and restart the app.',
            {'Content-Type': 'text/plain'},
        )


addons = [_FailClosedAddon(_INIT_ERROR) if _INIT_ERROR is not None else ContextGuardAddon()]
