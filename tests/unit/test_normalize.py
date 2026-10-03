import time

from engine.normalize import fold_confusables, normalize, strip_line_breaks_for_detection

ZERO_WIDTH_SPACE = '​'
COMBINING_ACUTE = '́'
E_ACUTE_PRECOMPOSED = 'é'


def test_strips_zero_width_chars():
    text_with_zwsp = 'se' + ZERO_WIDTH_SPACE + 'cret'
    assert normalize(text_with_zwsp) == 'secret'


def test_strips_bidi_override_characters():
    # Regression test for corpus.json bx-018: Unicode bidi-override/isolate
    # control characters (the "Trojan Source" class, CVE-2021-42574) can
    # make text render differently than its actual character order. Safe to
    # strip globally, unlike fold_confusables()/strip_*_for_detection() --
    # these characters are pure formatting with zero legitimate meaning in
    # chat text, so there's no real content that could be corrupted.
    rtl_override = '‮'
    text_with_override = 'AKIA' + rtl_override + 'ABCDEFGHIJKLMNOP'
    assert normalize(text_with_override) == 'AKIAABCDEFGHIJKLMNOP'


def test_strips_all_bidi_control_characters():
    bidi_chars = '‪‫‬‭‮⁦⁧⁨⁩'
    text = 'a' + bidi_chars + 'b'
    assert normalize(text) == 'ab'


def test_strips_expanded_invisible_format_characters():
    # Regression test for corpus.json bx-019 through bx-023: found by
    # systematically probing candidate zero-width/format characters against
    # the real pipeline (same technique as the original bidi-override find),
    # not by name recall. Each is Unicode category Cf (format) or a
    # zero-width Mn (nonspacing mark) that only modifies an adjacent
    # character's presentation, confirmed via unicodedata.category() before
    # adding -- same bar as the original INVISIBLE_CHARS set.
    word_joiner = '⁠'
    mongolian_vowel_separator = '᠎'
    soft_hyphen = '­'
    variation_selector_1 = '︀'
    variation_selector_16 = '️'
    combining_grapheme_joiner = '͏'
    for ch in (word_joiner, mongolian_vowel_separator, soft_hyphen,
               variation_selector_1, variation_selector_16, combining_grapheme_joiner):
        assert normalize('AKIA' + ch + 'ABCDEFGHIJKLMNOP') == 'AKIAABCDEFGHIJKLMNOP', (
            f'U+{ord(ch):04X} was not stripped')


def test_nfc_normalizes_unicode():
    decomposed = 'e' + COMBINING_ACUTE
    assert normalize(decomposed) == E_ACUTE_PRECOMPOSED


def test_passthrough_for_plain_ascii():
    assert normalize('hello world') == 'hello world'


def test_fold_confusables_folds_cyrillic_to_latin():
    # Regression test for a real detector gap (corpus.json bx-012/bx-013):
    # Cyrillic look-alikes defeated every ASCII-literal detector regex.
    cyrillic_akia = 'AKIA' + 'АВС' + 'DEFGHIJKLMNOP'  # А,В,С are Cyrillic U+0410/0412/0421
    assert fold_confusables(cyrillic_akia) == 'AKIAABCDEFGHIJKLMNOP'


def test_fold_confusables_folds_lowercase_cyrillic_and_greek():
    assert fold_confusables('ѕentry') == 'sentry'  # Cyrillic ѕ -> Latin s
    assert fold_confusables('ΡΙ') == 'PI'  # Greek Ρ, Ι -> Latin P, I


def test_fold_confusables_folds_accented_latin_to_ascii():
    # Regression test for a real detector gap found by probing candidate
    # evasion inputs against the real pipeline: normalize()'s NFKC step
    # COMPOSES a base letter + combining accent (e.g. "A" + combining acute)
    # into a single precomposed character ("Á") before detection ever runs
    # -- so the gap wasn't a surviving combining mark, it was that the
    # composed letter doesn't match an ASCII-only [A-Z] class, exactly like
    # a homoglyph. Different mechanism from the Cyrillic/Greek fold above,
    # same class of fix.
    text = 'AKIÁABCDEFGHIJKLMNOP'  # Á = A with acute, precomposed
    assert fold_confusables(text) == 'AKIAABCDEFGHIJKLMNOP'


def test_fold_confusables_handles_combining_accent_via_nfkc_composition():
    # End-to-end through BOTH normalize() (which composes the combining
    # accent into a precomposed letter) and fold_confusables() (which then
    # folds that composed letter to ASCII) -- the actual real-world input
    # shape (a combining mark typed/pasted right after a letter), not just
    # the already-precomposed form tested above.
    text = 'AKIA' + 'A' + '́' + 'BCDEFGHIJKLMNOP'  # A + combining acute
    result = fold_confusables(normalize(text))
    assert result == 'AKIAABCDEFGHIJKLMNOP'


def test_fold_confusables_covers_lowercase_accented_latin_too():
    assert fold_confusables('café') == 'cafe'  # é -> e


def test_fold_confusables_does_not_corrupt_real_accented_prose():
    # Same discipline as the Cyrillic-prose regression test above: real
    # accented text elsewhere in a message must survive untouched in
    # normalize()'s output (the literal text reused for anything sent
    # onward) -- fold_confusables()'s accented-Latin table is
    # DETECTION-ONLY, same as its Cyrillic/Greek entries.
    french_prose = "Bonjour, comment ça va? À bientôt, j'espère que vous allez bien."
    normalized = normalize(french_prose)
    assert 'ça' in normalized and 'À' in normalized and 'bientôt' in normalized


def test_fold_confusables_folds_dash_lookalikes_to_ascii_hyphen():
    # Regression test for a real gap: many prefix-marker rules use a literal
    # "-" as part of their anchor (xoxb-, sk-, etc.), and several Unicode
    # dash characters render visually near-identical to "-" in most fonts
    # but are NOT covered by NFKC (unlike the fullwidth hyphen, which
    # already folds). Confirmed live: U+2010 HYPHEN substituted for the
    # literal "-" in a real Slack bot token shape (xoxb-...) defeated
    # detection entirely before this fix.
    for ch in ('‐', '‑', '‒', '–', '—', '−'):
        text = 'xoxb' + ch + '1234567890123'
        assert fold_confusables(text) == 'xoxb-1234567890123', f'U+{ord(ch):04X} not folded'


def test_fold_confusables_dash_fold_does_not_break_benign_hyphenated_prose():
    # The fold must not become a new false-positive source: dense
    # hyphenated-compound-word text, page/number ranges, and negative
    # numbers using en-dash/minus-sign must stay unaffected by the fold
    # itself (the actual detection-safety check lives in
    # test_false_positive_rate.py; this just confirms the fold produces the
    # expected literal-hyphen substitution, not something unexpected).
    text = 'co‐worker, pages 10–25, temperature −40 degrees'
    assert fold_confusables(text) == 'co-worker, pages 10-25, temperature -40 degrees'


def test_fullwidth_latin_folds_via_normalize_nfkc():
    # Fullwidth Latin (a common lookalike-evasion range) is handled by
    # normalize()'s NFKC step, not fold_confusables() -- verifying the split
    # still covers both evasion styles together.
    assert normalize('ＡＫＩＡ') == 'AKIA'


def test_fold_confusables_does_not_touch_plain_ascii():
    text = 'nothing suspicious here, just ordinary English prose about cats.'
    assert fold_confusables(text) == text


def test_fold_confusables_preserves_length():
    # Load-bearing invariant, not just a nice property: proxy/addon.py relies
    # on fold_confusables() being length-preserving to reuse span offsets
    # found against the folded copy on the un-folded original (see
    # fold_confusables()'s docstring for why the fold must never touch the
    # text actually sent onward).
    text = 'ѕentry ΡΙ discord' + 'plain ascii too'
    assert len(fold_confusables(text)) == len(text)


def test_fold_confusables_never_corrupts_the_reconstruction_base():
    # Direct regression test for the real bug this split fixes: folding used
    # to happen inside normalize() itself, which proxy/addon.py reuses as the
    # literal text it rewrites and sends onward -- so real Cyrillic/Greek
    # prose anywhere in a message would have been silently mangled into
    # Latin lookalikes the moment ANY transform fired elsewhere in that same
    # message. normalize() must leave real non-Latin text untouched; only a
    # separately-folded copy is used for detection.
    russian_prose = 'Привет, как дела? Вот мой email: john@acme.com'
    normalized = normalize(russian_prose)
    assert 'Привет' in normalized and 'дела' in normalized  # untouched, not folded


def test_fold_confusables_is_linear_not_quadratic():
    # str.translate is a single linear pass -- confirms no accidental regex
    # or per-character regex-based approach snuck in that could reintroduce
    # the ReDoS class of bug found earlier this project.
    text = ('а' * 50_000) + ('e' * 50_000)  # mixed Cyrillic а and Latin e
    start = time.perf_counter()
    fold_confusables(text)
    elapsed = time.perf_counter() - start
    assert elapsed < 0.5, f'fold_confusables took {elapsed:.3f}s on 100K chars -- expected near-instant'


def test_strip_line_breaks_removes_newlines_and_carriage_returns():
    text = 'abc\ndef\r\nghi'
    stripped, _ = strip_line_breaks_for_detection(text)
    assert stripped == 'abcdefghi'


def test_strip_line_breaks_passthrough_when_no_line_breaks():
    text = 'nothing to strip here'
    stripped, index_map = strip_line_breaks_for_detection(text)
    assert stripped == text
    assert index_map == list(range(len(text)))


def test_strip_line_breaks_index_map_translates_spans_correctly():
    # Regression test for corpus.json bx-014: a value split across a line
    # break. The index map must let a span found in the stripped text map
    # back to the exact matching span in the original (with the line break
    # still inside it).
    text = 'abc\ndef'
    stripped, index_map = strip_line_breaks_for_detection(text)
    assert stripped == 'abcdef'
    # span [0,6) in stripped text ('abcdef') should map back to the full
    # original text [0,7) which includes the embedded '\n'
    orig_start = index_map[0]
    orig_end = index_map[len('abcdef') - 1] + 1
    assert text[orig_start:orig_end] == 'abc\ndef'


def test_strip_line_breaks_is_linear_not_quadratic():
    text = ('line of ordinary text\n' * 50_000)
    start = time.perf_counter()
    strip_line_breaks_for_detection(text)
    elapsed = time.perf_counter() - start
    assert elapsed < 0.5, f'strip_line_breaks_for_detection took {elapsed:.3f}s -- expected near-instant'
