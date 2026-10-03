"""Tests ContextGuardAddon.request() against a fake mitmproxy flow."""
import asyncio
import gzip
import json

import pytest

from proxy import addon


class FakeRequest:
    def __init__(self, host, body, real_host=None):
        self.pretty_host = host
        # Mirrors real mitmproxy: pretty_host prefers the (spoofable) Host
        # header, .host is the actual dial target. Defaults to the same
        # value as pretty_host so every existing test (which only ever
        # passed one "host") is unaffected; real_host lets a test simulate
        # a spoofed Host header specifically (pretty_host != .host).
        self.host = real_host if real_host is not None else host
        # Accepts either str (every existing plain-JSON/text test) or bytes
        # (connect-proto tests, which need the exact raw bytes .content
        # exposes -- get_text() lossily decodes, matching mitmproxy's real
        # get_text() behavior on genuinely binary content).
        if isinstance(body, bytes):
            self._body_bytes = body
            self._body_text = body.decode('utf-8', errors='replace')
        else:
            self._body_text = body
            self._body_bytes = body.encode('utf-8')
        self.text = None
        # Every existing test represents a real chat send, i.e. a POST --
        # defaults here so the many tests written before .method existed
        # don't all need updating; a test can override it explicitly
        # (flow.request.method = 'GET') when it actually needs to.
        self.method = 'POST'
        self.headers = {}

    def get_text(self):
        return self._body_text

    @property
    def content(self):
        return self._body_bytes


class FakeClientConn:
    def __init__(self, conn_id):
        self.id = conn_id


class FakeFlow:
    def __init__(self, host, body, conn_id='test-session', real_host=None):
        self.request = FakeRequest(host, body, real_host=real_host)
        self.client_conn = FakeClientConn(conn_id)
        self.response = None


def make_flow(host, content, conn_id='test-session'):
    body = json.dumps({'messages': [{'role': 'user', 'content': content}]})
    return FakeFlow(host, body, conn_id)


def make_flow_raw(host, raw_body, conn_id='test-session'):
    return FakeFlow(host, json.dumps(raw_body), conn_id)


class _SyncAddon:
    """Wraps ContextGuardAddon so `a.request(flow)` stays a plain sync call
    in every existing test -- request() itself is async (it awaits the
    interactive Send-Anyway dialog off the event loop, see addon.py), but
    each test only ever exercises one flow in isolation, so running that
    one coroutine to completion via asyncio.run() per call is equivalent."""
    def __init__(self, inner):
        self._inner = inner

    def request(self, flow):
        return asyncio.run(self._inner.request(flow))


@pytest.fixture
def a(monkeypatch):
    # Default every test to the pre-existing "hard block" behavior: a real
    # Tkinter dialog popping up during `pytest` would hang the suite (and a
    # default of "send anyway" would silently defeat every block test
    # below). Tests that specifically exercise the override dialog replace
    # this mock themselves -- see test_send_anyway_override_* below.
    monkeypatch.setattr(addon, 'ask_send_anyway', lambda category, host: False)
    # The warning-toast cooldown is module state; start every test with none
    # recorded so one test's toast can't suppress the next test's.
    monkeypatch.setattr(addon, '_last_warn_toast', {})
    # This whole file uses 'localhost' as its mock/test host throughout --
    # but the SHIPPED, signed domains.yaml deliberately has it
    # `enabled: false` (a real finding: it was shipped enabled, which meant
    # a developer's own http://localhost:PORT traffic got intercepted and
    # possibly mask-rewritten or blocked in a real install -- corrupting a
    # local request that never left the machine and was never a leak, with
    # nothing on the client side explaining why). Re-added here, in tests
    # only, rather than relying on the shipped file's default.
    monkeypatch.setattr(addon, 'WATCHLIST', addon.WATCHLIST | {'localhost'})
    return _SyncAddon(addon.ContextGuardAddon())


def test_passthrough_for_non_watchlisted_host(a):
    flow = make_flow('example.com', 'AKIAABCDEFGHIJKLMNOP')
    a.request(flow)
    assert flow.response is None
    assert flow.request.text is None


def test_subdomain_of_a_watched_apex_domain_is_also_watched(a):
    # Regression test for a real, confirmed-live gap: perplexity.ai's own
    # website actually serves from www.perplexity.ai, but domains.yaml only
    # listed the bare apex "perplexity.ai" -- a plain exact-string set
    # membership check meant every real request to the real site silently
    # matched nothing (no log line, no telemetry event, the message went
    # straight through unblocked, confirmed live by sending a real AWS key
    # and getting a real, unblocked response back).
    flow = make_flow('www.perplexity.ai', 'here is a key AKIAABCDEFGHIJKLMNOP')
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_lookalike_host_is_not_falsely_matched_as_a_subdomain(a):
    # A watchlisted "perplexity.ai" must not match a host that merely
    # contains it as a substring -- only an exact match or a genuine
    # dot-separated subdomain counts.
    flow = make_flow('evilperplexity.ai', 'AKIAABCDEFGHIJKLMNOP')
    a.request(flow)
    assert flow.response is None


def test_localhost_is_disabled_in_the_real_shipped_domains_yaml():
    # Regression guard for a real finding: this project's own test suite
    # needs 'localhost' watched (see the `a` fixture's own monkeypatch,
    # right above), but the REAL, SHIPPED, signed domains.yaml must never
    # ship it enabled -- a real install intercepting a developer's own
    # http://localhost:PORT traffic corrupts local-only requests that were
    # never a leak, with no explanation on the client side. Checks the raw
    # file directly (not addon.WATCHLIST, which the `a` fixture above
    # deliberately monkeypatches for every other test in this file).
    import yaml
    with open('proxy/domains.yaml', encoding='utf-8') as f:
        rows = yaml.safe_load(f)
    localhost_row = next(row for row in rows if row['hostname'] == 'localhost')
    assert localhost_row['enabled'] is False


def test_spoofed_host_header_cannot_hide_the_real_watched_destination(a):
    # Real, code-grounded security finding (external review): mitmproxy's
    # own docs warn that pretty_host (which prefers the Host/authority
    # header) "may not reflect the actual destination as the Host header
    # could be spoofed." A local app or page can CONNECT to a real watched
    # host and then send a different Host header inside the tunnel -- before
    # this fix, is_watched_host() only ever looked at pretty_host, so a
    # spoofed header made the whole request invisible to this addon
    # regardless of where it actually went. request.host (the real dial
    # target, not attacker-controlled the same way) is now checked too.
    body = json.dumps({'messages': [{'role': 'user', 'content': 'here is a key AKIAABCDEFGHIJKLMNOP'}]})
    flow = FakeFlow('not-a-real-host.example', body, real_host='api.openai.com')
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_block_branch_sets_403_and_never_rewrites_body(a):
    flow = make_flow('localhost', 'here is a key AKIAABCDEFGHIJKLMNOP')
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_transform_branch_rewrites_body_without_blocking(a):
    flow = make_flow('localhost', 'contact me at john@acme.com thanks')
    a.request(flow)
    assert flow.response is None
    rewritten = json.loads(flow.request.text)
    assert rewritten['messages'][0]['content'] == 'contact me at [EMAIL] thanks'


def test_send_anyway_override_lets_the_original_request_through(a, monkeypatch):
    # When the user picks "Send Anyway" in the interactive dialog, the
    # ORIGINAL request must go out completely unmodified -- no response set
    # (mitmproxy forwards it as-is), no body rewrite.
    monkeypatch.setattr(addon, 'ask_send_anyway', lambda category, host: True)
    flow = make_flow('localhost', 'here is a key AKIAABCDEFGHIJKLMNOP')
    a.request(flow)
    assert flow.response is None
    assert flow.request.text is None


def test_send_anyway_override_logs_the_override_not_a_silent_pass(a, monkeypatch):
    logged = []
    monkeypatch.setattr(addon, 'ask_send_anyway', lambda category, host: True)
    monkeypatch.setattr(addon, 'log_event', lambda **kw: logged.append(kw))
    flow = make_flow('localhost', 'here is a key AKIAABCDEFGHIJKLMNOP')
    a.request(flow)
    assert any(entry['action'] == 'send_anyway' for entry in logged)


def test_declining_the_dialog_still_blocks_same_as_before(a, monkeypatch):
    # The default -- explicitly re-asserted here even though the `a` fixture
    # already mocks this to False, so this test still documents/verifies the
    # behavior directly rather than relying only on the fixture default.
    monkeypatch.setattr(addon, 'ask_send_anyway', lambda category, host: False)
    flow = make_flow('localhost', 'here is a key AKIAABCDEFGHIJKLMNOP')
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_gemini_batchexecute_send_anyway_override_lets_request_through(a, monkeypatch):
    monkeypatch.setattr(addon, 'ask_send_anyway', lambda category, host: True)
    body = make_batchexecute_body('here is my key AKIAABCDEFGHIJKLMNOP')
    flow = FakeFlow('localhost', body)
    a.request(flow)
    assert flow.response is None


def test_fail_safe_blocks_with_502_on_internal_error(a, monkeypatch):
    def boom(content):
        raise RuntimeError('simulated detector crash')

    monkeypatch.setattr(addon, 'run_pipeline', boom)
    flow = make_flow('localhost', 'anything at all')
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 502


def test_structured_content_array_is_actually_inspected(a):
    # content as a list of blocks (OpenAI/Anthropic shape), not a plain string
    flow = make_flow_raw('localhost', {'messages': [{'role': 'user', 'content': [
        {'type': 'text', 'text': 'key AKIAABCDEFGHIJKLMNOP'},
    ]}]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_unparseable_content_shape_fails_safe_not_open(a):
    flow = make_flow_raw('localhost', {'messages': [{'role': 'user', 'content': None}]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 502


def test_non_dict_json_body_passes_through_without_crashing(a):
    flow = make_flow_raw('localhost', [1, 2, 3])
    a.request(flow)
    assert flow.response is None


def test_gemini_shape_block_is_detected(a):
    flow = make_flow_raw('localhost', {'contents': [{'role': 'user', 'parts': [
        {'text': 'key AKIAABCDEFGHIJKLMNOP'},
    ]}]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_gemini_shape_transform_rewrites_parts(a):
    flow = make_flow_raw('localhost', {'contents': [{'role': 'user', 'parts': [
        {'text': 'contact me at john@acme.com'},
    ]}]})
    a.request(flow)
    assert flow.response is None
    rewritten = json.loads(flow.request.text)
    assert rewritten['contents'][0]['parts'] == [{'text': 'contact me at [EMAIL]'}]


def test_extract_text_handles_chatgpt_web_parts_dict():
    assert addon.extract_text({'content_type': 'text', 'parts': ['hello world']}) == 'hello world'


def test_extract_text_joins_multiple_parts():
    assert addon.extract_text({'content_type': 'text', 'parts': ['a', 'b']}) == 'a b'


def test_extract_text_skips_non_string_parts():
    assert addon.extract_text({'content_type': 'multimodal_text', 'parts': ['a', {'asset_pointer': 'x'}, 'b']}) == 'a b'


def test_chatgpt_web_shape_block_is_detected(a):
    # The real shape ChatGPT's own website sends to backend-api/conversation
    # -- materially different from the public API's plain-string content,
    # confirmed against a real reverse-engineered request body. Before this
    # was supported, extract_text() raised on the content dict for every
    # single web-UI message, which fail-safes to a 502 block -- meaning the
    # tool would have been unusable against its own flagship watchlisted
    # host, not just under-protective.
    flow = make_flow_raw('localhost', {'action': 'next', 'messages': [{
        'id': 'abc-123',
        'author': {'role': 'user'},
        'role': 'user',
        'content': {'content_type': 'text', 'parts': ['key AKIAABCDEFGHIJKLMNOP']},
    }], 'model': 'text-davinci-002-render-sha', 'parent_message_id': 'def-456'})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_chatgpt_web_shape_transform_rewrites_parts_not_whole_envelope(a):
    body = {'action': 'next', 'messages': [{
        'id': 'abc-123',
        'author': {'role': 'user'},
        'role': 'user',
        'content': {'content_type': 'text', 'parts': ['contact me at john@acme.com']},
    }], 'model': 'text-davinci-002-render-sha', 'parent_message_id': 'def-456'}
    flow = make_flow_raw('localhost', body)
    a.request(flow)
    assert flow.response is None
    rewritten = json.loads(flow.request.text)
    msg = rewritten['messages'][0]
    assert msg['content'] == {'content_type': 'text', 'parts': ['contact me at [EMAIL]']}
    # the rest of the real backend's expected envelope must survive untouched
    assert msg['id'] == 'abc-123'
    assert msg['author'] == {'role': 'user'}
    assert rewritten['action'] == 'next'
    assert rewritten['model'] == 'text-davinci-002-render-sha'


def test_transform_preserves_non_text_blocks_openai_shape(a):
    # Regression test: a real data-loss bug -- transforming a mixed text+image
    # message used to collapse the whole content array down to a bare string,
    # silently destroying the image.
    flow = make_flow_raw('localhost', {'messages': [{'role': 'user', 'content': [
        {'type': 'text', 'text': 'contact me at john@acme.com'},
        {'type': 'image_url', 'image_url': {'url': 'data:image/png;base64,xyz'}},
    ]}]})
    a.request(flow)
    assert flow.response is None
    rewritten = json.loads(flow.request.text)
    blocks = rewritten['messages'][0]['content']
    assert blocks[0] == {'type': 'text', 'text': 'contact me at [EMAIL]'}
    assert blocks[1] == {'type': 'image_url', 'image_url': {'url': 'data:image/png;base64,xyz'}}


def test_transform_preserves_non_text_parts_gemini_shape(a):
    flow = make_flow_raw('localhost', {'contents': [{'role': 'user', 'parts': [
        {'text': 'contact me at john@acme.com'},
        {'inline_data': {'mime_type': 'image/png', 'data': 'xyz'}},
    ]}]})
    a.request(flow)
    assert flow.response is None
    rewritten = json.loads(flow.request.text)
    parts = rewritten['contents'][0]['parts']
    assert parts[0] == {'text': 'contact me at [EMAIL]'}
    assert parts[1] == {'inline_data': {'mime_type': 'image/png', 'data': 'xyz'}}


def test_multiple_simultaneous_blocks_are_all_logged(a, monkeypatch):
    logged_categories = []
    monkeypatch.setattr(addon, 'log_event',
                         lambda **kwargs: logged_categories.append(kwargs['category']))
    flow = make_flow('localhost', 'key AKIAABCDEFGHIJKLMNOP and sk_live_abcdefghijklmnopqrstuvwx')
    a.request(flow)
    assert flow.response.status_code == 403
    assert set(logged_categories) == {'secret.aws_access_token', 'secret.stripe_key'}


def test_transform_failure_fails_safe_not_open(a, monkeypatch):
    def boom(finding):
        raise RuntimeError('simulated transform crash')

    monkeypatch.setattr(addon, 'mask', boom)
    flow = make_flow('localhost', 'contact me at john@acme.com')
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 502
    assert flow.request.text is None  # original content must never go out as-is


def test_transform_preserves_unrelated_cyrillic_text(a):
    # Regression test for a real bug caught during development: the
    # homoglyph-confusables fold (added to catch bx-012/bx-013) was first
    # implemented inside normalize() itself, which addon.py reuses as the
    # literal text it rewrites when ANY transform fires. That would have
    # silently mangled real Cyrillic prose elsewhere in the same message
    # (e.g. a Russian-speaking user's text) into Latin lookalikes the moment
    # an unrelated email/secret in the same message got masked. Fixed by
    # keeping the fold detection-only (engine/normalize.py's
    # fold_confusables()). This proves it end to end, not just at the
    # detector-unit level.
    flow = make_flow('localhost', 'Привет, как дела? Вот мой email: john@acme.com')
    a.request(flow)
    assert flow.response is None
    rewritten = json.loads(flow.request.text)
    text = rewritten['messages'][0]['content']
    assert 'Привет' in text and 'дела' in text  # untouched
    assert text == 'Привет, как дела? Вот мой email: [EMAIL]'


def test_warns_on_context_rule_value_split_across_a_line_break(a, monkeypatch):
    # Regression test for corpus.json bx-014: a keyword-context value wrapped
    # or split across a chat line break used to defeat detection entirely
    # (the value regex requires a contiguous run). Fixed via
    # engine.normalize.strip_line_breaks_for_detection() -- this proves it
    # end to end, including that the flagged span still lands on the real
    # secret (embedded newline and all) in the actual outgoing text, not
    # some other unrelated part of the message.
    notified = []
    monkeypatch.setattr(addon, 'notify', lambda title, msg: notified.append(msg))
    text = ('unrelated line one\nunrelated line two\n'
             'sentry token abc123abc123abc123abc123abc123abc123\nabc123abc123abc123abc123abc123abc'
             '\nunrelated line three')
    flow = make_flow('localhost', text)
    a.request(flow)
    assert flow.response is None  # warn = pass through, never blocked
    assert any('secret.sentry_access_token' in msg for msg in notified)
    # the message itself must reach the destination completely unmodified --
    # 'warn' is passthrough-only, no rewrite, so all the real line breaks
    # (including the one inside the flagged value) must survive untouched
    assert flow.request.text is None


def test_blocks_space_injected_aws_key(a):
    # Regression test for corpus.json bx-006, end to end through the real
    # addon: a single space injected mid-token used to defeat detection
    # entirely. Fixed via regex_rules.py's SPACE_TOLERANT_RULES.
    flow = make_flow('localhost', 'here is a key AKIA ABCDEFGHIJKLMNOP')
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_blocks_bidi_override_injected_aws_key(a):
    # Regression test for corpus.json bx-018, end to end: a Trojan-Source
    # style bidi-override character injected mid-token. Fixed via
    # engine/normalize.py stripping bidi control characters globally.
    flow = make_flow('localhost', 'here is a key AKIA‮ABCDEFGHIJKLMNOP')
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_batch3_prefix_rule_blocks(a):
    # Spot-checks that a newly-added prefix rule (not just the pre-existing
    # ones) is actually wired through policy.yaml to a real block -- this is
    # the exact gap a missing policy row would hide (see test_policy_coverage.py).
    flow = make_flow('localhost', 'here is a token sntryu_' + 'a' * 64)
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_context_rule_warns_without_blocking(a, monkeypatch):
    notified = []
    monkeypatch.setattr(addon, 'notify', lambda title, msg: notified.append(msg))
    flow = make_flow('localhost', 'here is my sentry token ' + 'a' * 64)
    a.request(flow)
    assert flow.response is None  # warn = pass through, never blocked
    assert any('secret.sentry_access_token' in msg for msg in notified)


def test_secret_resurfacing_in_history_is_blocked_not_just_the_first_turn(a):
    # Regression test for a real, severe gap found by live-testing this
    # scenario: real chat-completion APIs (OpenAI/Anthropic/Gemini) are
    # stateless and resend the client's own local FULL history on every
    # request -- the client's local state is what the user actually typed,
    # never anything this proxy rewrote on the wire. The original design only
    # scanned the LAST user turn, so a secret was inspected exactly once: the
    # moment it stopped being the last turn, it went out verbatim, unblocked,
    # on every subsequent request for the rest of the conversation. Confirmed
    # live before this fix: turn 1's AWS key got a real 403, then turn 2's
    # request (history + a new unrelated message) sailed through with the
    # SAME raw key still sitting in messages[0], completely unscanned.
    turn1 = a
    flow1 = make_flow('localhost', 'here is my key AKIAABCDEFGHIJKLMNOP')
    turn1.request(flow1)
    assert flow1.response.status_code == 403

    # Turn 2: client resends its own unmodified history (the real key, since
    # the proxy's block never reached the client's local state) plus a new,
    # unrelated last turn.
    flow2 = make_flow_raw('localhost', {'messages': [
        {'role': 'user', 'content': 'here is my key AKIAABCDEFGHIJKLMNOP'},
        {'role': 'assistant', 'content': 'Sorry, I cannot help with that.'},
        {'role': 'user', 'content': 'ok never mind, what is the weather today'},
    ]})
    a.request(flow2)
    assert flow2.response is not None
    assert flow2.response.status_code == 403
    assert flow2.response.content is not None  # never silently forwarded


def test_secret_resurfacing_in_history_gets_transformed_every_time(a):
    # Same gap class as above, for the transform (non-block) action: an
    # earlier turn's email must be re-masked on every request it reappears
    # in, not just the first, and a NEW email in the newest turn must also
    # be masked in the same pass.
    flow1 = make_flow('localhost', 'contact me at john@acme.com')
    a.request(flow1)
    assert flow1.response is None
    rewritten1 = json.loads(flow1.request.text)
    assert rewritten1['messages'][0]['content'] == 'contact me at [EMAIL]'

    flow2 = make_flow_raw('localhost', {'messages': [
        {'role': 'user', 'content': 'contact me at john@acme.com'},  # raw, per client's own history
        {'role': 'assistant', 'content': 'Sure, got it.'},
        {'role': 'user', 'content': 'and also jane@acme.com please'},
    ]})
    a.request(flow2)
    assert flow2.response is None
    rewritten2 = json.loads(flow2.request.text)
    assert rewritten2['messages'][0]['content'] == 'contact me at [EMAIL]'
    assert rewritten2['messages'][1]['content'] == 'Sure, got it.'  # non-user turn untouched
    assert rewritten2['messages'][2]['content'] == 'and also [EMAIL] please'


def test_gemini_shape_multi_turn_history_all_scanned(a):
    flow = make_flow_raw('localhost', {'contents': [
        {'role': 'user', 'parts': [{'text': 'here is my key AKIAABCDEFGHIJKLMNOP'}]},
        {'role': 'model', 'parts': [{'text': 'I cannot help with that.'}]},
        {'role': 'user', 'parts': [{'text': 'ok, unrelated follow-up'}]},
    ]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_conversation_with_no_secrets_anywhere_passes_through_untouched(a):
    # Multi-turn scanning must not introduce false positives or unnecessary
    # rewrites for an entirely benign conversation.
    flow = make_flow_raw('localhost', {'messages': [
        {'role': 'user', 'content': 'hello'},
        {'role': 'assistant', 'content': 'hi there'},
        {'role': 'user', 'content': 'what is 2 + 2'},
    ]})
    a.request(flow)
    assert flow.response is None
    assert flow.request.text is None  # nothing to rewrite, must not touch it


def test_anthropic_system_field_string_is_scanned(a):
    # Regression test for a real gap found right after the multi-turn-history
    # fix: only messages[].role=="user" was ever scanned, so Anthropic's
    # top-level `system` field -- a completely separate field from
    # `messages`, not inside it -- was never inspected at all, on any
    # request. System prompts are commonly built programmatically by the
    # calling app and are, if anything, a MORE likely place for a real
    # secret/config value to end up than an ad-hoc chat turn.
    flow = make_flow_raw('localhost', {
        'model': 'claude-opus-4',
        'system': 'Use this AWS key when needed: AKIAABCDEFGHIJKLMNOP',
        'messages': [{'role': 'user', 'content': 'deploy please'}],
    })
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_anthropic_system_field_block_list_shape_is_scanned(a):
    # Anthropic's prompt-caching shape: `system` as a list of content blocks
    # ({"type": "text", "text": ..., "cache_control": {...}}) rather than a
    # plain string -- same gap, different wire shape for the same field.
    flow = make_flow_raw('localhost', {
        'model': 'claude-opus-4',
        'system': [{'type': 'text', 'text': 'AWS key AKIAABCDEFGHIJKLMNOP',
                    'cache_control': {'type': 'ephemeral'}}],
        'messages': [{'role': 'user', 'content': 'deploy please'}],
    })
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_anthropic_system_field_transform_masks_and_preserves_envelope(a):
    flow = make_flow_raw('localhost', {
        'model': 'claude-opus-4',
        'system': 'contact support at john@acme.com for issues',
        'messages': [{'role': 'user', 'content': 'hi'}],
    })
    a.request(flow)
    assert flow.response is None
    rewritten = json.loads(flow.request.text)
    assert rewritten['system'] == 'contact support at [EMAIL] for issues'
    assert rewritten['model'] == 'claude-opus-4'  # rest of the envelope survives
    assert rewritten['messages'][0]['content'] == 'hi'  # untouched, no secret there


def test_openai_system_role_message_is_scanned(a):
    # Unlike Anthropic, OpenAI's system prompt lives INSIDE messages[] as
    # role=="system" -- also never scanned before, since only role=="user"
    # was checked.
    flow = make_flow_raw('localhost', {'messages': [
        {'role': 'system', 'content': 'Stripe key sk_live_abcdefghijklmnopqrstuvwx'},
        {'role': 'user', 'content': 'hello'},
    ]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_openai_developer_role_message_is_scanned(a):
    # 'developer' is the o-series/GPT-5 replacement for 'system' -- same gap.
    flow = make_flow_raw('localhost', {'messages': [
        {'role': 'developer', 'content': 'key AKIAABCDEFGHIJKLMNOP'},
        {'role': 'user', 'content': 'hi'},
    ]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_openai_assistant_role_is_never_scanned(a):
    # Assistant output is the AI provider's own generated text -- it already
    # saw it, so scanning it isn't a leak-prevention concern for this tool.
    # Confirms the role allowlist doesn't accidentally widen to 'assistant'.
    flow = make_flow_raw('localhost', {'messages': [
        {'role': 'assistant', 'content': 'here is a key AKIAABCDEFGHIJKLMNOP'},
        {'role': 'user', 'content': 'thanks'},
    ]})
    a.request(flow)
    assert flow.response is None
    assert flow.request.text is None


def test_gemini_system_instruction_is_scanned(a):
    flow = make_flow_raw('localhost', {
        'systemInstruction': {'parts': [{'text': 'key AKIAABCDEFGHIJKLMNOP'}]},
        'contents': [{'role': 'user', 'parts': [{'text': 'hi'}]}],
    })
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_gemini_system_instruction_transform_preserves_contents(a):
    flow = make_flow_raw('localhost', {
        'systemInstruction': {'parts': [{'text': 'contact john@acme.com for support'}]},
        'contents': [{'role': 'user', 'parts': [{'text': 'hi'}]}],
    })
    a.request(flow)
    assert flow.response is None
    rewritten = json.loads(flow.request.text)
    assert rewritten['systemInstruction']['parts'] == [{'text': 'contact [EMAIL] for support'}]
    assert rewritten['contents'][0]['parts'] == [{'text': 'hi'}]


def test_openai_tool_role_message_is_scanned(a):
    # Regression test for a real gap found right after the system-prompt
    # fix: OpenAI's tool/function-calling protocol sends the actual returned
    # data from a tool call back to the model as its own message with
    # role=="tool" -- never scanned before, since only user/system/developer
    # were checked. Real agentic/CLI workflows (this tool's explicit
    # universal-coverage goal) commonly route exactly this kind of content
    # (a DB query result, an API response, a file's contents) back in.
    flow = make_flow_raw('localhost', {'messages': [
        {'role': 'user', 'content': 'check the db config'},
        {'role': 'assistant', 'content': None, 'tool_calls': [
            {'id': 'call_1', 'type': 'function', 'function': {'name': 'get_config', 'arguments': '{}'}}]},
        {'role': 'tool', 'tool_call_id': 'call_1', 'content': 'DB_PASSWORD=AKIAABCDEFGHIJKLMNOP'},
    ]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_anthropic_tool_result_block_string_content_is_scanned(a):
    # Anthropic's tool-use protocol sends tool results as role=="user" with a
    # {"type": "tool_result", ...} content block -- role=="user" meant the
    # message WAS being "scanned" (counted), but extract_text() only matched
    # blocks with type=="text" before this fix, so a tool_result's real
    # content silently extracted as empty text: zero detection, no crash, no
    # fail-safe trip, nothing visibly wrong to notice.
    flow = make_flow_raw('localhost', {'messages': [
        {'role': 'user', 'content': [{'type': 'tool_result', 'tool_use_id': 'toolu_1',
                                       'content': 'DB_PASSWORD=AKIAABCDEFGHIJKLMNOP'}]},
    ]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_anthropic_tool_result_block_nested_text_blocks_is_scanned(a):
    # A tool_result's own `content` can itself be a nested list of
    # {"type": "text", ...} blocks rather than a plain string.
    flow = make_flow_raw('localhost', {'messages': [
        {'role': 'user', 'content': [{'type': 'tool_result', 'tool_use_id': 'toolu_2',
                                       'content': [{'type': 'text', 'text': 'AWS key AKIAABCDEFGHIJKLMNOP'}]}]},
    ]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_anthropic_tool_result_transform_rewrites_nested_content_correctly(a):
    # The write-back path matters here: a naive top-level-text-block rewrite
    # would append a stray extra block while leaving the real (still-
    # unmasked) nested tool_result content untouched. Confirms the actual
    # nested `content` field gets rewritten in place, and the rest of the
    # block's envelope (tool_use_id, type) survives.
    flow = make_flow_raw('localhost', {'messages': [
        {'role': 'user', 'content': [{'type': 'tool_result', 'tool_use_id': 'toolu_3',
                                       'content': 'query returned: contact john@acme.com for issues'}]},
    ]})
    a.request(flow)
    assert flow.response is None
    rewritten = json.loads(flow.request.text)
    block = rewritten['messages'][0]['content'][0]
    assert block == {
        'type': 'tool_result', 'tool_use_id': 'toolu_3',
        'content': 'query returned: contact [EMAIL] for issues',
    }


def test_assistant_tool_use_block_still_not_scanned(a):
    # tool_use blocks are the ASSISTANT's own generated tool-call arguments
    # (already seen by the provider) -- confirms this stays excluded even
    # though it lives in a content-block list alongside the now-scanned
    # tool_result type, i.e. the fix didn't accidentally widen scope here.
    flow = make_flow_raw('localhost', {'messages': [
        {'role': 'assistant', 'content': [
            {'type': 'tool_use', 'id': 'toolu_4', 'name': 'send_email',
             'input': {'key': 'AKIAABCDEFGHIJKLMNOP'}}]},
    ]})
    a.request(flow)
    assert flow.response is None
    assert flow.request.text is None


def test_responses_api_plain_string_input_is_scanned(a):
    # Regression test for a real gap found right after the tool-use fix:
    # OpenAI's newer Responses API (api.openai.com/v1/responses -- same
    # watchlisted host, but a materially different wire shape from Chat
    # Completions) uses 'input' instead of 'messages'. Increasingly the
    # default for agent frameworks/SDKs. None of it was scanned before this.
    flow = make_flow_raw('localhost', {'model': 'gpt-5', 'input': 'here is my key AKIAABCDEFGHIJKLMNOP'})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_responses_api_list_shaped_input_is_scanned(a):
    flow = make_flow_raw('localhost', {'model': 'gpt-5', 'input': [
        {'role': 'user', 'content': 'here is my key AKIAABCDEFGHIJKLMNOP'},
    ]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_responses_api_input_text_content_part_is_scanned(a):
    # Responses API content parts use 'input_text' as the type name, not
    # Chat Completions' 'text'.
    flow = make_flow_raw('localhost', {'model': 'gpt-5', 'input': [
        {'role': 'user', 'content': [{'type': 'input_text', 'text': 'key AKIAABCDEFGHIJKLMNOP'}]},
    ]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_responses_api_instructions_field_is_scanned(a):
    # 'instructions' is the Responses API's system-prompt equivalent -- a
    # separate top-level field, same blind spot as Anthropic's 'system' was.
    flow = make_flow_raw('localhost', {
        'model': 'gpt-5', 'instructions': 'Use this AWS key: AKIAABCDEFGHIJKLMNOP', 'input': 'hi',
    })
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_chatgpt_web_ui_author_role_message_is_scanned(a):
    # ChatGPT web-UI's real send endpoint (POST backend-api/f/conversation)
    # was confirmed live to carry messages with NO top-level `role` key at
    # all -- role lives ONLY nested under `author`: {'id', 'author':
    # {'role': 'user'}, 'create_time', 'content': {'content_type': 'text',
    # 'parts': [...]}, 'metadata'}. Before this fix, m.get('role') was
    # always None for this shape, so this endpoint's messages were never
    # scanned at all -- a real secret typed into the actual ChatGPT website
    # went out completely unblocked even though the exact same secret was
    # correctly blocked via the public OpenAI API shape.
    flow = make_flow_raw('localhost', {'action': 'next', 'messages': [
        {
            'id': 'abc-123',
            'author': {'role': 'user'},
            'create_time': 1700000000,
            'content': {'content_type': 'text', 'parts': ['here is my key AKIAABCDEFGHIJKLMNOP']},
            'metadata': {},
        },
    ]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_chatgpt_web_ui_author_role_transform_masks_and_preserves_envelope(a):
    flow = make_flow_raw('localhost', {'action': 'next', 'messages': [
        {
            'id': 'abc-123',
            'author': {'role': 'user'},
            'create_time': 1700000000,
            'content': {'content_type': 'text', 'parts': ['contact support at john@acme.com for issues']},
            'metadata': {},
        },
    ]})
    a.request(flow)
    assert flow.response is None
    rewritten = json.loads(flow.request.text)
    rewritten_msg = rewritten['messages'][0]
    assert rewritten_msg['content']['parts'] == ['contact support at [EMAIL] for issues']
    assert rewritten_msg['author'] == {'role': 'user'}  # rest of the envelope survives
    assert rewritten_msg['id'] == 'abc-123'


def test_claude_web_ui_prompt_field_is_scanned(a):
    # claude.ai's real web-UI send endpoint (POST .../chat_conversations/
    # {id}/completion) uses neither the public Anthropic API's `messages`
    # array nor `system` -- what the user actually typed is a flat top-level
    # `prompt` string. Confirmed live: this shape was never scanned at all
    # before this fix, letting a real secret through the web UI even though
    # the exact same secret was correctly blocked via the public API shape.
    flow = make_flow_raw('localhost', {
        'prompt': 'here is my key AKIAABCDEFGHIJKLMNOP',
        'parent_message_uuid': 'x', 'model': 'claude-opus-4',
    })
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_claude_web_ui_prompt_field_transform_masks_and_preserves_envelope(a):
    flow = make_flow_raw('localhost', {
        'prompt': 'contact support at john@acme.com for issues',
        'parent_message_uuid': 'x', 'model': 'claude-opus-4',
    })
    a.request(flow)
    assert flow.response is None
    rewritten = json.loads(flow.request.text)
    assert rewritten['prompt'] == 'contact support at [EMAIL] for issues'
    assert rewritten['parent_message_uuid'] == 'x'  # rest of the envelope survives


def test_perplexity_web_ui_query_str_field_is_scanned(a):
    # perplexity.ai's real web-UI send endpoint (POST .../rest/sse/
    # perplexity_ask) uses neither `messages` nor `prompt` -- what the user
    # actually typed is a flat top-level `query_str` string (duplicated at
    # params.dsl_query). Confirmed live: this shape was never scanned at
    # all before this fix -- combined with a separate www.perplexity.ai
    # domain-matching gap, real secrets went straight through unblocked.
    flow = make_flow_raw('localhost', {
        'query_str': 'here is my key AKIAABCDEFGHIJKLMNOP',
        'params': {'dsl_query': 'here is my key AKIAABCDEFGHIJKLMNOP', 'mode': 'copilot'},
    })
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_perplexity_web_ui_query_str_transform_rewrites_both_copies(a):
    flow = make_flow_raw('localhost', {
        'query_str': 'contact support at john@acme.com for issues',
        'params': {'dsl_query': 'contact support at john@acme.com for issues', 'mode': 'copilot'},
    })
    a.request(flow)
    assert flow.response is None
    rewritten = json.loads(flow.request.text)
    assert rewritten['query_str'] == 'contact support at [EMAIL] for issues'
    assert rewritten['params']['dsl_query'] == 'contact support at [EMAIL] for issues'
    assert rewritten['params']['mode'] == 'copilot'  # rest of the envelope survives


# The 3 tests below are regression guards for the "extra scoping field" class
# of gap, added while extending provider coverage to each already-watchlisted
# provider's Project/Custom-GPT/Space feature (ChatGPT Custom GPTs & Projects,
# claude.ai Projects, Perplexity Spaces). These features add an ID field
# scoping the conversation to a project/space/custom-GPT (`conversation_ref`
# in a ChatGPT project/custom-GPT chat via `conversation_template_id`/
# `gizmo_id`; a `project_uuid` in a claude.ai Project chat; a `collection_uuid`
# in a Perplexity Space) but were never captured live against the actual
# feature -- there is no reason to believe the send endpoint or its message
# shape changes at all (it's the same conversation endpoint each provider's
# ordinary web chat already uses, just pre-scoped to a project/space rather
# than the user's default workspace), but that belief is UNVERIFIED and must
# not be asserted as fact until confirmed with a real browser session against
# each real feature (blocked this round on the Chrome extension being
# disconnected -- see project memory ROUND 17). What IS verifiable right now
# without live capture is the one concrete way an extra field like this could
# silently defeat detection: if extract_all_user_turns() or write_user_turn()
# ever keyed off "the ONLY top-level string field" or similarly loose
# assumption rather than the exact field name, an unrecognized sibling field
# could confuse it. These tests pin down that an extra scoping field changes
# nothing: detection, blocking, and in-place transform all still work exactly
# as they do for the plain (non-project) shape, and the scoping field itself
# always survives a rewrite untouched.
def test_chatgpt_project_or_custom_gpt_chat_is_still_scanned_with_gizmo_id_present(a):
    flow = make_flow_raw('localhost', {'action': 'next', 'conversation_template_id': 'g-p-abc123',
        'messages': [
            {
                'id': 'abc-123',
                'author': {'role': 'user'},
                'create_time': 1700000000,
                'content': {'content_type': 'text', 'parts': ['here is my key AKIAABCDEFGHIJKLMNOP']},
                'metadata': {},
            },
        ]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_claude_project_chat_is_still_scanned_with_project_uuid_present(a):
    flow = make_flow_raw('localhost', {
        'prompt': 'here is my key AKIAABCDEFGHIJKLMNOP',
        'parent_message_uuid': 'x', 'model': 'claude-opus-4', 'project_uuid': 'proj-abc-123',
    })
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403
    rewritten_check = json.loads(flow.request.get_text())
    assert rewritten_check['project_uuid'] == 'proj-abc-123'  # untouched -- request was blocked, not rewritten


def test_perplexity_space_chat_transform_rewrites_query_and_preserves_space_id(a):
    flow = make_flow_raw('localhost', {
        'query_str': 'contact support at john@acme.com for issues',
        'params': {'dsl_query': 'contact support at john@acme.com for issues', 'mode': 'copilot'},
        'collection_uuid': 'space-abc-123',
    })
    a.request(flow)
    assert flow.response is None
    rewritten = json.loads(flow.request.text)
    assert rewritten['query_str'] == 'contact support at [EMAIL] for issues'
    assert rewritten['params']['dsl_query'] == 'contact support at [EMAIL] for issues'
    assert rewritten['collection_uuid'] == 'space-abc-123'  # scoping field survives untouched


def test_responses_api_function_call_output_is_scanned(a):
    # function_call_output is the Responses API's equivalent of a tool
    # result -- real, app/tool-supplied data coming back into the model.
    flow = make_flow_raw('localhost', {'model': 'gpt-5', 'input': [
        {'role': 'user', 'content': 'check config'},
        {'type': 'function_call', 'call_id': 'c1', 'name': 'get_config', 'arguments': '{}'},
        {'type': 'function_call_output', 'call_id': 'c1', 'output': 'DB_PASSWORD=AKIAABCDEFGHIJKLMNOP'},
    ]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_responses_api_transform_preserves_envelope(a):
    flow = make_flow_raw('localhost', {'model': 'gpt-5', 'input': 'contact john@acme.com for support'})
    a.request(flow)
    assert flow.response is None
    rewritten = json.loads(flow.request.text)
    assert rewritten['input'] == 'contact [EMAIL] for support'
    assert rewritten['model'] == 'gpt-5'


def test_responses_api_function_call_output_transform_write_back_is_correct(a):
    flow = make_flow_raw('localhost', {'model': 'gpt-5', 'input': [
        {'type': 'function_call_output', 'call_id': 'c2', 'output': 'contact john@acme.com for support'},
    ]})
    a.request(flow)
    assert flow.response is None
    rewritten = json.loads(flow.request.text)
    assert rewritten['input'][0] == {
        'type': 'function_call_output', 'call_id': 'c2', 'output': 'contact [EMAIL] for support',
    }


def test_responses_api_model_output_text_is_not_scanned(a):
    # output_text is the model's OWN generated output (Responses API's
    # assistant-role content-part type) -- must stay excluded, same
    # reasoning as tool_use/assistant content elsewhere.
    flow = make_flow_raw('localhost', {'model': 'gpt-5', 'input': [
        {'type': 'message', 'role': 'assistant',
         'content': [{'type': 'output_text', 'text': 'key AKIAABCDEFGHIJKLMNOP'}]},
    ]})
    a.request(flow)
    assert flow.response is None
    assert flow.request.text is None


def test_gemini_function_response_secret_is_blocked(a):
    # Regression test for the Gemini equivalent of the OpenAI/Anthropic
    # tool-result gaps: the app sends the actual returned data from a
    # function call back to the model as role=='function', parts containing
    # {'functionResponse': {'response': ...}} -- never scanned before this.
    flow = make_flow_raw('localhost', {'contents': [
        {'role': 'user', 'parts': [{'text': 'check the db config'}]},
        {'role': 'model', 'parts': [{'functionCall': {'name': 'get_config', 'args': {}}}]},
        {'role': 'function', 'parts': [{'functionResponse': {
            'name': 'get_config', 'response': {'result': 'DB_PASSWORD=AKIAABCDEFGHIJKLMNOP'}}}]},
    ]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_gemini_function_response_transform_only_fails_safe(a):
    # functionResponse.response is an arbitrary JSON value -- reliably
    # splicing a text-level mask back into it isn't safe in general, so a
    # transform (non-block)-tier finding here deliberately fails safe (502)
    # rather than risk forwarding corrupted JSON or a still-unmasked value.
    # A mandatory-block secret is unaffected (see the test above) since
    # blocking short-circuits before write-back is ever attempted.
    flow = make_flow_raw('localhost', {'contents': [
        {'role': 'function', 'parts': [{'functionResponse': {
            'name': 'lookup', 'response': {'contact': 'john@acme.com'}}}]},
    ]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 502
    assert flow.request.text is None  # never forwards unmasked or corrupted content


def test_gemini_function_response_with_no_secrets_passes_through(a):
    flow = make_flow_raw('localhost', {'contents': [
        {'role': 'user', 'parts': [{'text': 'check status'}]},
        {'role': 'function', 'parts': [{'functionResponse': {
            'name': 'status', 'response': {'ok': True, 'count': 5}}}]},
    ]})
    a.request(flow)
    assert flow.response is None
    assert flow.request.text is None


def test_embeddings_style_string_array_input_is_scanned(a):
    # OpenAI's Embeddings and Moderations APIs (api.openai.com/v1/embeddings,
    # /v1/moderations) reuse the top-level 'input' field name from the
    # Responses API fix, but as a plain array of strings, not role-shaped
    # items -- a real document/RAG chunk sent for embedding is exactly the
    # kind of content that can carry a secret.
    flow = make_flow_raw('localhost', {
        'model': 'text-embedding-3-small',
        'input': ['some benign text', 'here is my key AKIAABCDEFGHIJKLMNOP'],
    })
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_embeddings_style_string_array_transform_preserves_other_items(a):
    flow = make_flow_raw('localhost', {
        'model': 'text-embedding-3-small',
        'input': ['unrelated text', 'contact john@acme.com for support'],
    })
    a.request(flow)
    assert flow.response is None
    rewritten = json.loads(flow.request.text)
    assert rewritten['input'] == ['unrelated text', 'contact [EMAIL] for support']
    assert rewritten['model'] == 'text-embedding-3-small'


def test_watchlist_match_is_case_insensitive(a):
    # Regression test for a real, severe finding: DNS/HTTP hostnames are
    # case-insensitive, but the original watchlist check was a plain-string
    # set membership test. Confirmed live through a real mitmdump process +
    # curl: a request to 'API.OPENAI.COM' reached the real OpenAI server
    # with ZERO inspection -- no '[ContextGuard] matched host' log line at
    # all, a real AWS key went out in full, proven by a real response
    # actually coming back from the provider (not just a local mock).
    for host_variant in ('LOCALHOST', 'LocalHost', 'localhost'):
        flow = make_flow(host_variant, 'here is a key AKIAABCDEFGHIJKLMNOP')
        a.request(flow)
        assert flow.response is not None, f'{host_variant} bypassed the watchlist entirely'
        assert flow.response.status_code == 403


def test_deeply_nested_json_fails_safe_not_uncaught(a):
    # Regression test for a real, severe gap: a degenerate but syntactically
    # valid JSON body (extreme array-nesting depth) overflows json.loads()'s
    # parser stack with a RecursionError -- which is NOT a ValueError/
    # TypeError subclass, so it wasn't caught by the narrow except clause
    # around the initial parse. Confirmed live before this fix: the
    # exception propagated completely uncaught out of request(), which in
    # real mitmdump means mitmproxy's default addon-error handling logs an
    # error and forwards the request UNMODIFIED -- fail-OPEN, the opposite
    # of this tool's purpose, from a ~40KB payload, and a repeatable free
    # way to crash this hook on every request to a watchlisted host.
    depth = 20000
    nested = '{"messages":' + '[' * depth + '1' + ']' * depth + '}'
    flow = FakeFlow('localhost', nested)  # raw text, not json.dumps'd via make_flow_raw
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 502
    assert flow.request.text is None  # never forwarded, original or otherwise


def test_moderately_nested_json_is_unaffected(a):
    # The fix must not become a new false-positive source for ordinary
    # payloads that happen to contain some nested JSON-shaped text.
    body = {'messages': [{'role': 'user',
                           'content': 'hello, nested: ' + json.dumps({'a': {'b': {'c': [1, 2, 3]}}})}]}
    flow = make_flow_raw('localhost', body)
    a.request(flow)
    assert flow.response is None


@pytest.mark.parametrize('role', ['user', 'system', 'developer', 'tool'])
def test_content_none_fails_safe_for_every_scannable_role(a, role):
    # The original fail-safe for content:null (a real shape failure, not "no
    # user turn") was only ever proven for role=='user'. Locks in that the
    # same protection holds for every role that was added to SCANNABLE_ROLES
    # later (system/developer/tool) -- a future refactor of the role
    # handling could easily special-case 'user' and silently drop this.
    flow = make_flow_raw('localhost', {'messages': [{'role': role, 'content': None}]})
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 502


def test_drop_overlapping_spans_keeps_only_non_overlapping():
    from engine.finding import Finding
    from engine.policy import Decision

    f1 = Finding(span_start=8, span_end=21, category='pii.email', confidence=0.9,
                 detector_id='x', raw_value='john@acme.com')
    f2 = Finding(span_start=5, span_end=15, category='pii.other', confidence=0.9,
                 detector_id='y', raw_value='act john@ac')  # overlaps f1
    d1 = Decision(finding=f1, action='transform', mandatory=False, transform_type='mask')
    d2 = Decision(finding=f2, action='transform', mandatory=False, transform_type='mask')

    kept = addon.drop_overlapping_spans([d1, d2])
    assert len(kept) == 1


def make_batchexecute_body(text, extra_token='FAKE_AUTH_TOKEN'):
    """Builds a form-urlencoded body matching Google's real batchexecute
    wire shape, captured live from gemini.google.com's own StreamGenerate
    endpoint: f.req is a JSON array whose second element is itself a
    JSON-encoded string wrapping the real RPC argument array, with the
    user's message text at inner[0][0]."""
    import urllib.parse
    inner = json.dumps([[text, 0, None, None, None, None, 0], ['en']])
    outer = json.dumps([None, inner])
    return f'f.req={urllib.parse.quote(outer)}&at={extra_token}&'


def test_extract_batchexecute_text_parses_real_gemini_shape():
    body = make_batchexecute_body('here is my key AKIAABCDEFGHIJKLMNOP')
    assert addon.extract_batchexecute_text(body) == ['here is my key AKIAABCDEFGHIJKLMNOP']


def test_extract_batchexecute_text_returns_empty_for_unrelated_form_body():
    assert addon.extract_batchexecute_text('foo=bar&baz=qux') == []


def test_extract_batchexecute_text_returns_empty_for_malformed_freq():
    assert addon.extract_batchexecute_text('f.req=not-valid-json-or-url-stuff&at=x') == []


def test_read_varint_single_byte():
    assert addon._read_varint(bytes([0x05]), 0) == (5, 1)


def test_read_varint_multi_byte():
    # 300 = 0b1_0010_1100 -> low 7 bits 0101100=0x2C with continuation,
    # remaining bits 10=0x02 -- real protobuf varint encoding for 300.
    data = bytes([0xAC, 0x02])
    assert addon._read_varint(data, 0) == (300, 2)


def test_read_varint_truncated_raises_value_error():
    with pytest.raises(ValueError):
        addon._read_varint(bytes([0x80]), 0)  # continuation bit set, no next byte


def test_extract_connect_proto_json_parses_real_captured_shape():
    body = _build_connect_proto_frame(json.dumps({
        'model': 'claude-opus-5',
        'messages': [{'role': 'user', 'content': 'here is my key AKIAABCDEFGHIJKLMNOP'}],
    }))
    result = addon.extract_connect_proto_json(body)
    assert result is not None
    assert result['model'] == 'claude-opus-5'
    assert result['messages'][0]['content'] == 'here is my key AKIAABCDEFGHIJKLMNOP'


def test_extract_connect_proto_json_returns_none_for_non_connect_body():
    assert addon.extract_connect_proto_json(b'just some random bytes') is None


def test_extract_connect_proto_json_returns_none_when_frame_length_mismatched():
    # A malformed/truncated frame -- the declared length doesn't match the
    # actual remaining bytes. Must fail safe (None), never guess/misparse.
    body = bytes([0x00]) + (1000).to_bytes(4, 'big') + b'too short'
    assert addon.extract_connect_proto_json(body) is None


def test_extract_connect_proto_json_returns_none_when_no_field_is_recognizable_json():
    request_id = 'b379dd44-b54a-44a5-a813-54a34e0b5cd3'
    id_field = bytes([0x0A, len(request_id)]) + request_id.encode('ascii')
    body = bytes([0x00]) + len(id_field).to_bytes(4, 'big') + id_field
    assert addon.extract_connect_proto_json(body) is None


def test_extract_connect_proto_json_ignores_json_field_without_messages_key():
    # A length-delimited field that happens to parse as JSON but isn't
    # actually the Messages-API request (no 'messages' list) must not be
    # mistaken for it.
    request_id = 'b379dd44-b54a-44a5-a813-54a34e0b5cd3'
    id_field = bytes([0x0A, len(request_id)]) + request_id.encode('ascii')
    unrelated_json = json.dumps({'status': 'ok', 'count': 3}).encode('utf-8')
    unrelated_field = bytes([0x12, len(unrelated_json)]) + unrelated_json
    message = id_field + unrelated_field
    body = bytes([0x00]) + len(message).to_bytes(4, 'big') + message
    assert addon.extract_connect_proto_json(body) is None


# Round-20 hardening, added after an independent review found the original
# version's fail-safe posture didn't match its own docstring: a wire type
# this function can't safely skip past used to `return None`, which the
# caller treats as "genuinely not this format, safe to pass through" --
# meaning a Connect-RPC frame containing ANY deprecated group-encoded field
# would silently let a real secret in a LATER field go out completely
# unscanned. Fixed to raise ConnectProtoParseError instead, once the outer
# envelope itself has already checked out (see that class's own docstring)
# -- these tests cover the specific gaps the review called out by name.
def test_extract_connect_proto_json_skips_64_bit_fixed_field_before_json():
    request_id = 'b379dd44-b54a-44a5-a813-54a34e0b5cd3'
    id_field = bytes([0x0A, len(request_id)]) + request_id.encode('ascii')
    fixed64_field = bytes([0x19]) + (12345).to_bytes(8, 'little')  # field 3, wire type 1
    json_bytes = json.dumps({'messages': [{'role': 'user', 'content': 'hi'}]}).encode('utf-8')
    json_field = bytes([0x12, len(json_bytes)]) + json_bytes
    message = id_field + fixed64_field + json_field
    body = bytes([0x00]) + len(message).to_bytes(4, 'big') + message
    result = addon.extract_connect_proto_json(body)
    assert result is not None
    assert result['messages'][0]['content'] == 'hi'


def test_extract_connect_proto_json_skips_32_bit_fixed_field_before_json():
    request_id = 'b379dd44-b54a-44a5-a813-54a34e0b5cd3'
    id_field = bytes([0x0A, len(request_id)]) + request_id.encode('ascii')
    fixed32_field = bytes([0x1D]) + (99).to_bytes(4, 'little')  # field 3, wire type 5
    json_bytes = json.dumps({'messages': [{'role': 'user', 'content': 'hi'}]}).encode('utf-8')
    json_field = bytes([0x12, len(json_bytes)]) + json_bytes
    message = id_field + fixed32_field + json_field
    body = bytes([0x00]) + len(message).to_bytes(4, 'big') + message
    result = addon.extract_connect_proto_json(body)
    assert result is not None
    assert result['messages'][0]['content'] == 'hi'


def test_extract_connect_proto_json_skips_a_well_formed_group_field():
    # Round-20 follow-up hardening: an independent review flagged that an
    # earlier version of this code hard-failed on ANY group-encoded field
    # (wire type 3), even a well-formed one -- which meant a real Claude
    # Design request using a group before its JSON field got hard-blocked
    # (502) for no real safety reason, since groups (deprecated but legal
    # protobuf) CAN be safely skipped without a schema: they're terminated
    # by an EGROUP tag carrying the same field number. Confirms the fix
    # actually recovers the JSON field after a real group.
    group_content = bytes([0x08, 0x2A])  # inside the group: field 1, varint 42
    sgroup = bytes([0x0B])  # field 1, wire type 3 (start-group)
    egroup = bytes([0x0C])  # field 1, wire type 4 (end-group), matching field number
    json_bytes = json.dumps({'messages': [{'role': 'user', 'content': 'hi'}]}).encode('utf-8')
    json_field = bytes([0x12, len(json_bytes)]) + json_bytes
    message = sgroup + group_content + egroup + json_field
    body = bytes([0x00]) + len(message).to_bytes(4, 'big') + message
    result = addon.extract_connect_proto_json(body)
    assert result is not None
    assert result['messages'][0]['content'] == 'hi'


def test_extract_connect_proto_json_raises_on_unterminated_group():
    sgroup = bytes([0x0B])  # field 1, wire type 3, no matching EGROUP ever follows
    body = bytes([0x00]) + len(sgroup).to_bytes(4, 'big') + sgroup
    with pytest.raises(addon.ConnectProtoParseError):
        addon.extract_connect_proto_json(body)


def test_extract_connect_proto_json_raises_on_mismatched_egroup():
    sgroup = bytes([0x0B])  # field 1, start-group
    wrong_egroup = bytes([0x14])  # field 2, end-group -- wrong field number
    body_msg = sgroup + wrong_egroup
    body = bytes([0x00]) + len(body_msg).to_bytes(4, 'big') + body_msg
    with pytest.raises(addon.ConnectProtoParseError):
        addon.extract_connect_proto_json(body)


def test_extract_connect_proto_json_raises_on_truly_unknown_wire_type():
    # An EGROUP with no matching SGROUP at the top level -- genuinely
    # malformed, must still fail closed.
    stray_egroup = bytes([0x0C])  # field 1, wire type 4, no opening SGROUP
    body = bytes([0x00]) + len(stray_egroup).to_bytes(4, 'big') + stray_egroup
    with pytest.raises(addon.ConnectProtoParseError):
        addon.extract_connect_proto_json(body)


def test_extract_connect_proto_json_raises_when_length_delimited_field_overruns_message():
    # Declared field length (a complete, validly-encoded varint: 127, with
    # its continuation bit clear) reaches past the end of the message -- a
    # truncated/adversarial frame, not a genuine format mismatch.
    bogus = bytes([0x0A, 0x7F])  # field 1, claims a 127-byte value that isn't there
    body = bytes([0x00]) + len(bogus).to_bytes(4, 'big') + bogus
    with pytest.raises(addon.ConnectProtoParseError):
        addon.extract_connect_proto_json(body)


def test_extract_connect_proto_json_raises_on_truncated_varint_mid_message():
    truncated = bytes([0x0A, 0x80])  # varint continuation bit set, no next byte
    body = bytes([0x00]) + len(truncated).to_bytes(4, 'big') + truncated
    with pytest.raises(addon.ConnectProtoParseError):
        addon.extract_connect_proto_json(body)


def test_extract_connect_proto_json_first_matching_field_wins():
    json_a = json.dumps({'messages': [{'role': 'user', 'content': 'first'}]}).encode('utf-8')
    json_b = json.dumps({'messages': [{'role': 'user', 'content': 'second'}]}).encode('utf-8')
    field_a = bytes([0x0A, len(json_a)]) + json_a
    field_b = bytes([0x12, len(json_b)]) + json_b
    message = field_a + field_b
    body = bytes([0x00]) + len(message).to_bytes(4, 'big') + message
    result = addon.extract_connect_proto_json(body)
    assert result['messages'][0]['content'] == 'first'


def test_extract_connect_proto_json_decompresses_valid_gzip_payload():
    request_id = 'b379dd44-b54a-44a5-a813-54a34e0b5cd3'
    id_field = bytes([0x0A, len(request_id)]) + request_id.encode('ascii')
    json_bytes = json.dumps({
        'messages': [{'role': 'user', 'content': 'here is my key AKIAABCDEFGHIJKLMNOP'}],
    }).encode('utf-8')
    json_field = bytes([0x12, len(json_bytes)]) + json_bytes
    message = id_field + json_field
    compressed = gzip.compress(message)
    body = bytes([0x01]) + len(compressed).to_bytes(4, 'big') + compressed
    result = addon.extract_connect_proto_json(body)
    assert result is not None
    assert result['messages'][0]['content'] == 'here is my key AKIAABCDEFGHIJKLMNOP'


def test_extract_connect_proto_json_raises_on_corrupt_gzip_payload():
    garbage = b'this is not gzip data at all, just plain bytes'
    body = bytes([0x01]) + len(garbage).to_bytes(4, 'big') + garbage
    with pytest.raises(addon.ConnectProtoParseError):
        addon.extract_connect_proto_json(body)


def test_extract_connect_proto_json_rejects_decompression_exceeding_cap(monkeypatch):
    # A decompression-bomb guard: a small compressed payload that would
    # expand well past the safety cap must be rejected before it's fully
    # materialized, not silently truncated or allowed through. Uses a tiny
    # monkeypatched cap so the test itself stays fast and small.
    monkeypatch.setattr(addon, 'MAX_DECOMPRESSED_CONNECT_BYTES', 100)
    big_message = b'x' * 10_000
    compressed = gzip.compress(big_message)
    body = bytes([0x01]) + len(compressed).to_bytes(4, 'big') + compressed
    with pytest.raises(addon.ConnectProtoParseError):
        addon.extract_connect_proto_json(body)


def test_gemini_batchexecute_format_blocks_a_real_secret(a):
    # Regression test for a real, confirmed-live gap: gemini.google.com is on
    # the watchlist, but its actual send endpoint (StreamGenerate) posts a
    # form-urlencoded body, not JSON -- json.loads() on it always raised
    # ValueError, which before this fix was silently treated as "not a chat
    # payload," so gemini.google.com was watched but NEVER actually scanned
    # (zero telemetry events, confirmed by sending a raw AWS key through and
    # watching it come back in Gemini's own reply unmodified).
    body = make_batchexecute_body('here is my key AKIAABCDEFGHIJKLMNOP')
    flow = FakeFlow('localhost', body)
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_gemini_batchexecute_format_warns_without_blocking_on_a_warn_category(a, monkeypatch):
    notified = []
    monkeypatch.setattr(addon, 'notify', lambda title, msg: notified.append(msg))
    body = make_batchexecute_body('here is my sentry token ' + 'a' * 64)
    flow = FakeFlow('localhost', body)
    a.request(flow)
    assert flow.response is None  # warn = pass through, never blocked
    assert any('secret.sentry_access_token' in msg for msg in notified)


def test_gemini_batchexecute_format_passthrough_when_no_secret(a):
    body = make_batchexecute_body('just a normal question about the weather')
    flow = FakeFlow('localhost', body)
    a.request(flow)
    assert flow.response is None


def test_gemini_batchexecute_branch_fails_safe_on_unexpected_exception(a, monkeypatch):
    # Regression test for a real, confirmed-live bug: the batchexecute branch
    # had no try/except of its own (unlike the plain-JSON path just below
    # it), so an unexpected exception inside it escaped request() entirely.
    # mitmproxy's default addon-error handling then left the underlying
    # connection in a broken state instead of either cleanly forwarding or
    # blocking it -- confirmed live: the browser showed a generic connection
    # error (not this addon's own 403 page), and new tabs wouldn't load at
    # all until the system proxy was toggled off and back on.
    def boom(*a, **k):
        raise RuntimeError('simulated unexpected crash')
    monkeypatch.setattr(addon, 'run_pipeline', boom)
    body = make_batchexecute_body('here is my key AKIAABCDEFGHIJKLMNOP')
    flow = FakeFlow('localhost', body)
    a.request(flow)  # must not raise
    assert flow.response is not None
    assert flow.response.status_code == 502


# Structural fallback-scan fix (external review, both auditor and threat-
# model reports independently flagged this as the top structural gap): a
# genuinely UNRECOGNIZED shape now gets scanned as raw text instead of
# passing through completely uninspected -- see
# _scan_unrecognized_body_as_fallback()'s own docstring for the full
# reasoning. Deliberately distinct from a RECOGNIZED shape with legitimately
# no scannable content (assistant-only turns), which must NEVER be scanned
# this way -- see the next test.
def test_genuinely_unrecognized_json_shape_is_still_caught_via_fallback_scan(a):
    # A body shaped nothing like any known provider (no messages/contents/
    # prompt/query_str/etc key at all) previously passed straight through
    # with zero inspection and zero log trace. Now caught at block tier.
    flow = make_flow_raw('localhost', {
        'some_future_providers_own_field_name': 'here is my key AKIAABCDEFGHIJKLMNOP',
    })
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_recognized_shape_with_only_assistant_content_is_never_fallback_scanned(a):
    # Regression guard: a RECOGNIZED shape (has a real 'input' key) whose
    # only turns are assistant-authored (already seen by the provider,
    # deliberately excluded by SCANNABLE_ROLES) must NOT be caught by the
    # fallback scan just because extract_all_user_turns() returned an empty
    # list -- an empty turns list from a recognized shape is a correct,
    # intentional outcome, not a gap. Before _body_has_a_known_shape_key()
    # existed, this exact shape (see test_responses_api_model_output_text_
    # is_not_scanned above) would have been wrongly caught and blocked here.
    flow = make_flow_raw('localhost', {'model': 'gpt-5', 'input': [
        {'type': 'message', 'role': 'assistant',
         'content': [{'type': 'output_text', 'text': 'key AKIAABCDEFGHIJKLMNOP'}]},
    ]})
    a.request(flow)
    assert flow.response is None
    assert flow.request.text is None


def test_empty_known_key_does_not_shield_a_real_secret_elsewhere_in_the_body(a):
    # Real bug found by an independent review: _body_has_a_known_shape_key()
    # originally checked key PRESENCE only, so a body like this one --
    # 'instructions' present but empty, a real secret sitting under some
    # unrelated field name -- was wrongly treated as "a recognized shape"
    # (skip the fallback scan) purely because the key existed, even though
    # extract_all_user_turns() finds zero turns in it for a totally
    # different reason (empty string, not role-filtering). That silently
    # defeated the fallback scan for a real secret in the same body --
    # exactly the bypass this mechanism exists to close.
    flow = make_flow_raw('localhost', {
        'instructions': '',
        'some_unrelated_field_a_future_provider_might_use': 'here is my key AKIAABCDEFGHIJKLMNOP',
    })
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


@pytest.mark.parametrize('known_key,empty_value', [
    ('messages', []),
    ('contents', []),
    ('system', ''),
    ('input', ''),
    ('input', []),
    ('instructions', ''),
    ('prompt', ''),
    ('query_str', ''),
])
def test_every_empty_known_key_still_falls_back_to_scanning(a, known_key, empty_value):
    # Systematic version of the test above -- every single key
    # extract_all_user_turns() recognizes must, when present but empty,
    # still allow the fallback scan to catch a real secret elsewhere in the
    # same body. Guards against the exact class of bug found above
    # recurring for any OTHER key in the future.
    flow = make_flow_raw('localhost', {
        known_key: empty_value,
        'some_unrelated_field': 'here is my key AKIAABCDEFGHIJKLMNOP',
    })
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_unrecognized_non_json_body_is_caught_via_fallback_scan(a):
    flow = FakeFlow('localhost', 'plain text body, not JSON at all: AKIAABCDEFGHIJKLMNOP')
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_unrecognized_json_array_body_is_caught_via_fallback_scan(a):
    # A top-level JSON array isn't a dict at all -- extract_all_user_turns()
    # can't even be called on it.
    flow = FakeFlow('localhost', json.dumps(['here is my key AKIAABCDEFGHIJKLMNOP']))
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_fallback_scan_passes_through_clean_unrecognized_content(a):
    flow = make_flow_raw('localhost', {
        'some_future_providers_own_field_name': 'just an ordinary message with nothing sensitive',
    })
    a.request(flow)
    assert flow.response is None


def test_fallback_scan_skips_oversized_unrecognized_body(a):
    # Above the size cap: must NOT be scanned at all (same "log and pass
    # through unscanned" behavior as before this fix existed) -- this is a
    # deliberate DoS-surface guard on the new fallback path itself, not a
    # detection gap.
    huge_secret_body = json.dumps({
        'some_future_providers_own_field_name': 'AKIAABCDEFGHIJKLMNOP ' + ('x' * 300_000),
    })
    flow = FakeFlow('localhost', huge_secret_body)
    a.request(flow)
    assert flow.response is None


def test_fallback_scan_only_applies_to_post_requests(a):
    flow = FakeFlow('localhost', 'here is my key AKIAABCDEFGHIJKLMNOP')
    flow.request.method = 'GET'
    a.request(flow)
    assert flow.response is None


def test_fallback_scan_send_anyway_override_lets_request_through(a, monkeypatch):
    monkeypatch.setattr(addon, 'ask_send_anyway', lambda category, host: True)
    flow = make_flow_raw('localhost', {
        'some_future_providers_own_field_name': 'here is my key AKIAABCDEFGHIJKLMNOP',
    })
    a.request(flow)
    assert flow.response is None
    assert flow.request.text is None


# pii.credit_card / pii.ssn end-to-end through the real addon pipeline (not
# just the detector module in isolation) -- both are policy.yaml `block,
# mandatory: true`, same tier as an API key, since a leaked full card number
# or SSN is a real identity-theft/fraud vector, not a lesser concern than a
# leaked credential.
def test_credit_card_number_is_blocked(a):
    flow = make_flow('localhost', 'here is my card 4242424242424242 for the order')
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_ssn_is_blocked(a):
    flow = make_flow('localhost', 'my ssn is 123-45-6789 for the form')
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_random_16_digit_number_is_not_blocked_as_credit_card(a):
    # No real network starts with "99" -- an ordinary long reference/order
    # number must not trip the credit-card rule.
    flow = make_flow('localhost', 'order number 9999999999999999 shipped today')
    a.request(flow)
    assert flow.response is None


def test_credit_card_send_anyway_override_lets_request_through(a, monkeypatch):
    monkeypatch.setattr(addon, 'ask_send_anyway', lambda category, host: True)
    flow = make_flow('localhost', 'here is my card 4242424242424242 for the order')
    a.request(flow)
    assert flow.response is None
    assert flow.request.text is None


# _safe_print(): regression tests for a real, confirmed-live bug found while
# manually driving a real Chrome session through the real proxy. With
# CONTEXTGUARD_DEBUG_LOG_RAW=1 set, running from source with a real console
# attached, Windows' legacy per-locale console encoding (cp1252 on this
# machine) couldn't encode some ordinary Unicode text extracted from a real
# request body -- and because that debug print() lived inside the SAME
# try/except as the actual detection logic, the resulting UnicodeEncodeError
# was indistinguishable from a genuine inspection failure: a perfectly safe
# message got hard-blocked (502) purely because of what the CONSOLE could
# display, nothing to do with its actual content. Reproduced live via
# Claude-in-Chrome's own `find` tool call (which routes through
# api.anthropic.com, itself watchlisted) before being root-caused and fixed
# here.
def test_safe_print_does_not_raise_on_unencodable_console(monkeypatch):
    def fake_print(message):
        raise UnicodeEncodeError('charmap', message, 0, 1, 'character maps to <undefined>')
    monkeypatch.setattr(addon, 'print', fake_print, raising=False)
    addon._safe_print('some message with a real problem character: ✅')  # must not raise


def test_debug_mode_unicode_content_does_not_falsely_trigger_inspection_failed_block(a, monkeypatch):
    # The exact real-world reproduction: DEBUG_LOG_RAW_CONTENT on (as it was
    # live), and the console's print() raising on non-cp1252-encodable text
    # -- a checkmark character here, standing in for the real extension
    # payload's own Unicode content. Before the _safe_print() fix, this
    # produced a 502 "inspection failed" even though nothing was actually
    # wrong with the message.
    monkeypatch.setattr(addon, 'DEBUG_LOG_RAW_CONTENT', True)
    real_print = print
    def cp1252_print(message):
        message.encode('cp1252')  # raises UnicodeEncodeError for ✅, same as the real console
        real_print(message)
    monkeypatch.setattr(addon, 'print', cp1252_print, raising=False)
    flow = make_flow('localhost', 'looks good ✅ thanks')
    a.request(flow)
    assert flow.response is None


def _build_connect_proto_frame(json_payload: str) -> bytes:
    """Approximates the real wire shape captured live from claude.ai's
    "Claude Design" feature (POST .../OmeletteService/Chat, content-type
    application/connect+proto): a Connect-RPC unary frame (1-byte flags +
    4-byte big-endian length) wrapping a protobuf message where one
    length-delimited string field's VALUE is itself a JSON-encoded string
    carrying the actual Anthropic Messages API request (model/system/
    messages) -- built to match the exact structure of a real captured
    request (a 36-char request-id field immediately followed by a
    length-prefixed JSON string starting with {"model":...)."""
    request_id = 'b379dd44-b54a-44a5-a813-54a34e0b5cd3'
    id_field = bytes([0x0A, len(request_id)]) + request_id.encode('ascii')
    json_bytes = json_payload.encode('utf-8')
    varint = bytearray()
    n = len(json_bytes)
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            varint.append(b | 0x80)
        else:
            varint.append(b)
            break
    json_field = bytes([0x12]) + bytes(varint) + json_bytes
    message = id_field + json_field
    frame_header = bytes([0x00]) + len(message).to_bytes(4, 'big')
    return frame_header + message


def test_claude_design_omelette_chat_endpoint_is_scanned(a):
    # Real, live-confirmed gap (round 19), fixed in round 20: claude.ai's
    # "Claude Design" feature (a distinct product surface from plain
    # claude.ai chat) sends its actual message via a Connect-RPC
    # binary-framed protobuf body (content-type application/connect+proto)
    # to /design/anthropic.omelette.api.v1alpha.OmeletteService/Chat -- a
    # materially different wire shape from every other claude.ai shape this
    # addon recognizes (messages/content, prompt, batchexecute). The user's
    # actual message is embedded as a JSON string inside one protobuf field.
    # json.loads() can't parse the raw bytes directly (they start with
    # Connect's own binary framing, not '{'), so this exercises
    # extract_connect_proto_json()'s generic protobuf-field walk instead.
    # Uses the RAW BYTES (not .decode()'d to a str) since that's exactly
    # what request() now reads via flow.request.content -- a lossy text
    # decode was the mistake in the original xfail version of this test,
    # and would still incorrectly show this as failing.
    body = _build_connect_proto_frame(json.dumps({
        'model': 'claude-opus-5',
        'system': [{'type': 'text', 'text': 'You are an expert designer...'}],
        'messages': [{'role': 'user', 'content': 'here is my key AKIAABCDEFGHIJKLMNOP'}],
    }))
    flow = FakeFlow('localhost', body)
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_claude_design_connect_proto_passthrough_when_no_secret(a):
    body = _build_connect_proto_frame(json.dumps({
        'model': 'claude-opus-5',
        'messages': [{'role': 'user', 'content': 'just a normal design request'}],
    }))
    flow = FakeFlow('localhost', body)
    a.request(flow)
    assert flow.response is None


def test_claude_design_connect_proto_transform_tier_degrades_to_warn(a, monkeypatch):
    # No safe in-place rewrite path for this shape (same reasoning as
    # batchexecute) -- a transform-tier finding (email) must still be
    # surfaced, never silently dropped, and must never be treated as a
    # block either.
    logged = []
    monkeypatch.setattr(addon, 'log_event', lambda **kw: logged.append(kw))
    body = _build_connect_proto_frame(json.dumps({
        'model': 'claude-opus-5',
        'messages': [{'role': 'user', 'content': 'contact me at john@acme.com thanks'}],
    }))
    flow = FakeFlow('localhost', body)
    a.request(flow)
    assert flow.response is None  # never blocked
    assert any(entry['action'] == 'warn' and entry['category'] == 'pii.email' for entry in logged)


def test_connect_proto_recognized_shape_with_only_assistant_content_is_never_raw_scanned(a, monkeypatch):
    # Real bug found by an independent review: this branch had no guard at
    # all for "connect-proto WAS recognized (has a real 'messages' key), but
    # genuinely has nothing scannable in it" (an assistant-only turn -- the
    # exact same class of case the plain-JSON path's
    # _body_has_a_known_shape_key() guard already handled). It fell through
    # to the code path meant for a truly UNRECOGNIZED shape, which ran the
    # fallback scan over body_text -- the RAW, LOSSILY-DECODED BINARY BYTES
    # of the protobuf frame, not the recovered JSON. Scanning binary framing
    # noise as if it were text risks a false-positive entropy-based
    # block/warn on entirely legitimate Claude Design traffic. Confirms both
    # that nothing is blocked AND that nothing is even logged as a warn.
    logged = []
    monkeypatch.setattr(addon, 'log_event', lambda **kw: logged.append(kw))
    body = _build_connect_proto_frame(json.dumps({
        'model': 'claude-opus-5',
        'messages': [{'role': 'assistant', 'content': 'already seen by the provider'}],
    }))
    flow = FakeFlow('localhost', body)
    a.request(flow)
    assert flow.response is None
    assert flow.request.text is None
    assert logged == []  # no warn/block from scanning raw binary framing bytes as text


def test_connect_proto_frame_with_no_recognizable_json_field_is_unrecognized(a):
    # A genuinely unrelated (or malformed) connect+proto body must not be
    # misparsed into a false match -- falls through to the same
    # "nothing to inspect" passthrough as any other unrecognized shape.
    request_id = 'b379dd44-b54a-44a5-a813-54a34e0b5cd3'
    id_field = bytes([0x0A, len(request_id)]) + request_id.encode('ascii')
    frame_header = bytes([0x00]) + len(id_field).to_bytes(4, 'big')
    flow = FakeFlow('localhost', frame_header + id_field)
    a.request(flow)
    assert flow.response is None


def test_connect_proto_frame_with_unparseable_content_fails_safe_to_502(a):
    # Round-20 hardening: a well-formed Connect envelope whose INNER content
    # can't be safely walked (here, a deprecated group-typed field) must
    # fail safe -- a 502 "inspection failed" block, the same fail-safe tier
    # as a RecursionError on deeply-nested JSON -- never a silent passthrough.
    # Before this fix, this exact shape returned None from
    # extract_connect_proto_json() and the request went out completely
    # unscanned, regardless of what a later field in the same message
    # might have carried.
    group_field = bytes([0x0B])  # field 1, wire type 3 (deprecated start-group)
    frame_header = bytes([0x00]) + len(group_field).to_bytes(4, 'big')
    flow = FakeFlow('localhost', frame_header + group_field)
    a.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 502


# _FailClosedAddon: installed instead of the real addon when module-level
# init fails (see addon.py's own _INIT_ERROR comment, right above the
# domains.yaml load, for the full "mitmproxy fails OPEN on an addon import
# error" reasoning this exists to close). Tested directly against the class
# rather than by forcing a real import failure -- the module-level wiring
# that picks between this and ContextGuardAddon is a one-line ternary
# (`addons = [_FailClosedAddon(...) if _INIT_ERROR is not None else
# ContextGuardAddon()]`); the actual protection logic worth testing is what
# this class DOES once installed.
def test_fail_closed_addon_blocks_post_to_a_known_ai_host():
    fake = FakeFlow('api.openai.com', 'irrelevant body')
    fake.request.method = 'POST'
    stub = addon._FailClosedAddon('simulated init failure')
    asyncio.run(stub.request(fake))
    assert fake.response is not None
    assert fake.response.status_code == 503


def test_fail_closed_addon_blocks_post_to_a_subdomain_of_a_known_ai_host():
    fake = FakeFlow('www.perplexity.ai', 'irrelevant body')
    fake.request.method = 'POST'
    stub = addon._FailClosedAddon('simulated init failure')
    asyncio.run(stub.request(fake))
    assert fake.response is not None
    assert fake.response.status_code == 503


def test_fail_closed_addon_ignores_get_requests():
    # GET is never a real chat-send -- same reasoning already established
    # for _log_unrecognized_shape()'s own POST-only filter. Blocking every
    # GET indiscriminately would break ordinary page loads on these sites
    # entirely while the app is already broken, for no added safety.
    fake = FakeFlow('api.openai.com', 'irrelevant body')
    fake.request.method = 'GET'
    stub = addon._FailClosedAddon('simulated init failure')
    asyncio.run(stub.request(fake))
    assert fake.response is None


def test_fail_closed_addon_ignores_unrelated_hosts():
    fake = FakeFlow('example.com', 'irrelevant body')
    fake.request.method = 'POST'
    stub = addon._FailClosedAddon('simulated init failure')
    asyncio.run(stub.request(fake))
    assert fake.response is None


def test_fail_closed_addon_logs_the_reason_it_was_installed(tmp_path, monkeypatch):
    monkeypatch.setattr(addon, 'get_writable_data_dir', lambda: tmp_path)
    addon._FailClosedAddon('simulated: PolicyIntegrityError: bad signature')
    log_path = tmp_path / 'last_addon_error.log'
    assert log_path.exists()
    assert 'bad signature' in log_path.read_text(encoding='utf-8')


# tls_clienthello(): real finding from an external threat-model review --
# without this hook, EVERY HTTPS connection this machine makes gets fully
# terminated/decrypted by this locally-generated CA, not just watchlisted
# hosts, contradicting request()'s own "do not even fully decrypt" comment.
# A minimal fake standing in for mitmproxy's real ClientHelloData -- only
# the two attributes this hook actually touches.
class _FakeClientHello:
    def __init__(self, sni):
        self.sni = sni


class _FakeClientHelloData:
    def __init__(self, sni):
        self.client_hello = _FakeClientHello(sni)
        self.ignore_connection = False


def test_tls_clienthello_ignores_connection_for_an_unwatched_sni():
    addon_instance = addon.ContextGuardAddon()
    data = _FakeClientHelloData('example.com')
    asyncio.run(addon_instance.tls_clienthello(data))
    assert data.ignore_connection is True


def test_tls_clienthello_does_not_ignore_a_watched_sni():
    addon_instance = addon.ContextGuardAddon()
    data = _FakeClientHelloData('api.openai.com')
    asyncio.run(addon_instance.tls_clienthello(data))
    assert data.ignore_connection is False


def test_tls_clienthello_does_not_ignore_a_subdomain_of_a_watched_sni():
    addon_instance = addon.ContextGuardAddon()
    data = _FakeClientHelloData('www.perplexity.ai')
    asyncio.run(addon_instance.tls_clienthello(data))
    assert data.ignore_connection is False


def test_tls_clienthello_keeps_intercepting_when_sni_is_missing():
    # Conservative default: can't identify the destination without SNI, so
    # this must NOT ignore the connection -- request()'s own host check
    # still catches it either way if it turns out to be watched.
    addon_instance = addon.ContextGuardAddon()
    data = _FakeClientHelloData(None)
    asyncio.run(addon_instance.tls_clienthello(data))
    assert data.ignore_connection is False


def test_tls_clienthello_is_case_insensitive():
    addon_instance = addon.ContextGuardAddon()
    data = _FakeClientHelloData('API.OPENAI.COM')
    asyncio.run(addon_instance.tls_clienthello(data))
    assert data.ignore_connection is False


def test_fail_closed_addon_tls_clienthello_uses_the_fallback_watchlist():
    stub = addon._FailClosedAddon('simulated init failure')
    watched = _FakeClientHelloData('api.openai.com')
    asyncio.run(stub.tls_clienthello(watched))
    assert watched.ignore_connection is False

    unwatched = _FakeClientHelloData('example.com')
    asyncio.run(stub.tls_clienthello(unwatched))
    assert unwatched.ignore_connection is True


def make_huggingchat_flow(text, host='localhost'):
    # Mirrors HuggingChat's real send: multipart/form-data, message JSON in a `data` field.
    boundary = 'hfboundary1234'
    data = json.dumps({'id': 'x', 'inputs': text, 'is_continue': False, 'is_retry': False,
                       'web_search': False, 'tools': []})
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="data"\r\n\r\n'
            f'{data}\r\n--{boundary}--\r\n').encode()
    flow = FakeFlow(host, body)
    flow.request.headers['content-type'] = f'multipart/form-data; boundary={boundary}'
    return flow


def test_extract_multipart_json_finds_the_huggingchat_data_field():
    flow = make_huggingchat_flow('hello there')
    parsed = addon.extract_multipart_json(flow.request.content, flow.request.headers['content-type'])
    assert parsed['inputs'] == 'hello there'


def test_extract_multipart_json_ignores_non_multipart_and_file_parts():
    assert addon.extract_multipart_json(b'{"inputs": "x"}', 'application/json') is None
    body = (b'--b\r\nContent-Disposition: form-data; name="f"; filename="a.json"\r\n\r\n'
            b'{"inputs": "x"}\r\n--b--\r\n')
    assert addon.extract_multipart_json(body, 'multipart/form-data; boundary=b') is None


def test_huggingchat_multipart_secret_is_blocked(a):
    flow = make_huggingchat_flow('deploy with AKIAABCDEFGHIJKLMNOP please')
    a.request(flow)
    assert flow.response is not None and flow.response.status_code == 403


def test_huggingchat_multipart_email_warns_instead_of_passing_silently(a, monkeypatch):
    logged = []
    monkeypatch.setattr(addon, 'log_event', lambda **kw: logged.append(kw))
    flow = make_huggingchat_flow('email john.smith@acmecorp.com today')
    a.request(flow)
    assert flow.response is None
    assert any(e['category'] == 'pii.email' and e['action'] == 'warn' for e in logged)


def test_huggingchat_clean_message_passes_untouched(a):
    flow = make_huggingchat_flow('what is the capital of France')
    original = flow.request.content
    a.request(flow)
    assert flow.response is None and flow.request.content == original


def test_plain_json_inputs_field_is_scanned_and_rewritten(a):
    flow = make_flow_raw('localhost', {'inputs': 'contact john@acme.com thanks'})
    a.request(flow)
    assert flow.response is None
    assert 'john@acme.com' not in (flow.request.text or '')


def test_router_huggingface_is_watched():
    assert addon.is_watched_host('router.huggingface.co')
    assert addon._is_fallback_watched_host('router.huggingface.co')


def test_warning_toast_is_throttled_per_category_and_host(a, monkeypatch):
    notified = []
    monkeypatch.setattr(addon, 'notify', lambda title, msg: notified.append(msg))
    addon._notify_warning('pii.email', 'chatgpt.com')
    addon._notify_warning('pii.email', 'chatgpt.com')  # inside the cooldown: no second toast
    addon._notify_warning('pii.email', 'claude.ai')    # a different host still gets its own
    assert len(notified) == 2


def test_fallback_scan_ignores_warn_tier_findings_in_unrecognized_bodies(a, monkeypatch):
    # Site background traffic (analytics, telemetry) is full of random-looking
    # tokens: a live session logged ~2,700 warnings in 20 minutes from it.
    notified = []
    monkeypatch.setattr(addon, 'notify', lambda title, msg: notified.append(msg))
    logged = []
    monkeypatch.setattr(addon, 'log_event', lambda **kwargs: logged.append(kwargs))
    flow = FakeFlow('localhost', json.dumps({'telemetry_blob': 'contact me at someone@example.com'}))
    a.request(flow)
    assert flow.response is None
    assert notified == []
    assert logged == []


def test_a_group_switched_off_in_settings_is_not_blocked(a):
    from engine import user_settings
    user_settings.set_group_enabled('api_keys', False)
    flow = make_flow('localhost', 'here is a key AKIAABCDEFGHIJKLMNOP')
    a.request(flow)
    assert flow.response is None  # the user chose not to check for API keys

    user_settings.set_group_enabled('api_keys', True)
    flow = make_flow('localhost', 'here is a key AKIAABCDEFGHIJKLMNOP')
    a.request(flow)
    assert flow.response.status_code == 403  # back on: takes effect on the next request


def test_switching_one_group_off_leaves_the_others_on(a):
    from engine import user_settings
    user_settings.set_group_enabled('emails', False)
    flow = make_flow('localhost', 'here is a key AKIAABCDEFGHIJKLMNOP')
    a.request(flow)
    assert flow.response.status_code == 403


def _pdf_fixture(name):
    from pathlib import Path
    return (Path(__file__).resolve().parent.parent / 'fixtures' / 'pdf' / name).read_bytes()


def _multipart_upload(pdf_bytes, chat_json=None):
    boundary = 'cgtestboundary'
    parts = []
    if chat_json is not None:
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="data"\r\n\r\n{chat_json}\r\n'.encode())
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="report.pdf"\r\n'
                 f'Content-Type: application/pdf\r\n\r\n'.encode() + pdf_bytes + b'\r\n')
    parts.append(f'--{boundary}--\r\n'.encode())
    flow = FakeFlow('localhost', b''.join(parts))
    flow.request.headers = {'content-type': f'multipart/form-data; boundary={boundary}'}
    return flow


def test_pdf_upload_with_a_key_is_blocked(a):
    flow = _multipart_upload(_pdf_fixture('key_on_one_line.pdf'))
    a.request(flow)
    assert flow.response.status_code == 403


def test_a_raw_pdf_upload_body_is_checked_too(a):
    flow = FakeFlow('localhost', _pdf_fixture('key_on_one_line.pdf'))
    flow.request.method = 'PUT'
    a.request(flow)
    assert flow.response.status_code == 403


def test_clean_pdf_upload_passes_and_the_chat_message_beside_it_is_still_checked(a):
    flow = _multipart_upload(_pdf_fixture('clean.pdf'),
                             chat_json='{"inputs": "here is my key AKIAABCDEFGHIJKLMNOP"}')
    a.request(flow)
    assert flow.response.status_code == 403  # caught in the message, not the PDF

    flow = _multipart_upload(_pdf_fixture('clean.pdf'), chat_json='{"inputs": "summarize this"}')
    a.request(flow)
    assert flow.response is None


def test_pdf_over_the_page_limit_asks_before_sending_unchecked(a, monkeypatch):
    asked = []
    monkeypatch.setattr(addon, 'ask_send_anyway', lambda category, host: asked.append(category) or False)
    flow = _multipart_upload(_pdf_fixture('fifty_one_pages.pdf'))
    a.request(flow)
    assert asked == ['file.not_scanned.too_many_pages']
    assert flow.response.status_code == 403


def test_pdf_uploads_switched_off_in_settings_are_not_checked(a):
    from engine import user_settings
    user_settings.set_group_enabled('pdf_uploads', False)
    flow = _multipart_upload(_pdf_fixture('key_on_one_line.pdf'))
    a.request(flow)
    assert flow.response is None


@pytest.mark.parametrize('upload_host', [
    'contribution-rt.usercontent.google.com', 'push.clients6.google.com', 'content-push.googleapis.com',
    'sdmntprsouthcentralus.oaiusercontent.com', 'sdmntprwestus.oaiusercontent.com'])
def test_gemini_style_upload_to_the_shared_upload_host_is_checked(a, upload_host):
    # Gemini's web app uploads an attached file as the raw request body to
    # one of Google's upload servers before the chat message is sent.
    flow = FakeFlow(upload_host, _pdf_fixture('key_on_one_line.pdf'))
    a.request(flow)
    assert flow.response.status_code == 403


def test_nothing_but_pdfs_is_inspected_on_the_shared_upload_host(a):
    # Other Google apps use this host too: a non-PDF body is never scanned there.
    flow = make_flow('contribution-rt.usercontent.google.com', 'here is my key AKIAABCDEFGHIJKLMNOP')
    a.request(flow)
    assert flow.response is None
    assert flow.request.text is None


def test_chatgpt_style_put_to_file_storage_is_checked_and_other_traffic_there_is_not(a):
    # ChatGPT uploads with a PUT of the raw PDF to sdmntpr<region>.oaiusercontent.com.
    flow = FakeFlow('sdmntprsouthcentralus.oaiusercontent.com', _pdf_fixture('key_on_one_line.pdf'))
    flow.request.method = 'PUT'
    a.request(flow)
    assert flow.response.status_code == 403
    flow = make_flow('sdmntprsouthcentralus.oaiusercontent.com', 'here is my key AKIAABCDEFGHIJKLMNOP')
    a.request(flow)
    assert flow.response is None
