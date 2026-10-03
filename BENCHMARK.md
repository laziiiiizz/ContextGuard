# Benchmark Methodology

This documents *how* ContextGuard is benchmarked, and the current real numbers from running it
locally (see "Current status" below). These are portfolio-project numbers from a local dev machine
and a hand-written corpus, not a production-scale or third-party-audited result — stated as such,
not oversold.

## Corpus format

`tests/adversarial/corpus.json` holds labeled test cases, one object per case:

| Field | Meaning |
|---|---|
| `id` | Stable identifier (`bx-NNN`), referenced in test output and PRs |
| `text` | The literal input string run through the pipeline |
| `category` | Expected detector category (must match a category in `policy/policy.yaml`) |
| `severity` | `high` / `medium` / `low`, informational only, not asserted on |
| `expected_action` | What the policy should decide: `allow` / `warn` / `transform` / `block` |
| `source` | `synthetic` (hand-written) or `synthetic-adversarial` (a deliberate bypass attempt) |
| `reviewer_status` | `reviewed` once someone with security judgment has signed off on the case |
| `known_gap` (optional) | `true` if the pipeline is expected to currently fail this case |
| `note` (optional) | Why the case exists / why it currently passes or fails |

## Running it

```
pytest tests/adversarial/
```

Cases without `known_gap` must match `expected_action` exactly or the suite fails. Cases with
`known_gap: true` are asserted with `pytest.mark.xfail(strict=True)` — if one of those starts
unexpectedly passing (a real fix landed), the suite fails until the `known_gap` flag is removed from
`corpus.json`. This keeps the corpus honest in both directions: a real regression fails loudly, and a
real fix can't quietly go unnoticed either.

## Why "100% pass" isn't the actual goal

A 100%-pass adversarial suite is a yellow flag if it means the corpus only ever tested cases the
detectors were already built to catch. That's not the case here: every case below started as a real,
found gap (`known_gap: true`, `xfail`-tracked) and only left that state once a real, scoped fix landed
and was verified against it — never by weakening the test or deleting the case. The discipline that
actually matters isn't "keep one case red forever" (a fix that makes it pass legitimately shouldn't be
treated as a problem), it's this: keep hunting for the next real evasion technique, verify it before
believing it's fixed, and never claim more coverage than the corpus actually proves. `pytest.mark.xfail
(strict=True)` still enforces the useful direction of that discipline — a fix landing without the
`known_gap` flag being removed from `corpus.json` fails the suite loudly (an unexpected pass), so a real
fix can't quietly go unverified either.

## Current status (as of 2026-09-11)

- **Detector coverage:** 115 prefix-based regex rules (114 credential/API-key + `pii.email`) + 90
  keyword-context rules (proximity-matched, see `engine/detectors/context_rules.py`; 88 credential/
  API-key + 2 non-credential — `infra.internal_ip`/`infra.internal_hostname`, a private-IP-or-hostname
  leak gated on a nearby infra keyword like "server"/"database"/"deploy"), most adapted from gitleaks'
  222-rule config, plus one Shannon-entropy backstop for anything neither catches. 201 of gitleaks' 222
  rule ids triaged into one of the two ported forms; the remaining ~60 (some 1:1, some merged/split
  differently) were deliberately skipped as too generic/noisy for a chat-text proximity scan (documented
  in `context_rules.py`'s module docstring) — this is a considered stopping point, not a claim of 100%
  gitleaks parity. `engine/normalize.py` also folds common Cyrillic/Greek homoglyphs AND accented
  Latin letters (Á/É/Ñ/etc. -> A/E/N/etc., the Latin-1 Supplement block, generated programmatically
  and verified against real French/Spanish/Portuguese/German/Italian prose for false positives), strips
  a 33-character curated set of Unicode invisible/format characters (zero-width spaces/joiners, bidi-
  override/isolate control characters -- the "Trojan Source" attack class, CVE-2021-42574 -- word
  joiner, Mongolian vowel separator, soft hyphen, all 16 variation selectors, combining grapheme
  joiner), and (inside `context_rules.py`'s bounded window, or a small anchor-bounded window
  in `regex_rules.py`, never message-wide) collapses a line break or injected space/tab splitting a
  value — the fold/strip operations are always safe to apply globally (pure invisible/formatting
  characters or a length-preserving 1:1 letter substitution, with no legitimate content destroyed --
  verified live, not assumed), the space/line-break collapses are detection-only and scoped tightly
  because applying them message-wide was tried and found to fuse unrelated text into false matches
  (see below).
- **Bypass/evasion corpus** (`tests/adversarial/corpus.json`, run via `pytest tests/adversarial/`):
  30 labeled cases, all hand-written, all currently passing. Every case was a genuine found gap first:
  Unicode-homoglyph substitution in a prefix token (bx-012) or a keyword-context keyword (bx-013) is
  caught via a homoglyph fold; a value split across a line break (bx-014) is caught via a
  bounded-window line-break collapse scoped to `context_rules.py` specifically (a message-wide version
  was tried and rejected during development — it let unrelated lines elsewhere in a long paste fuse
  together into new false matches, confirmed empirically before it shipped); a space (bx-006) or tab
  (bx-017) injected mid-token is caught via an anchor-bounded space/tab-tolerant scan covering 96 of
  115 prefix rules in `regex_rules.py`, same reasoning as the line-break fix (bx-017 itself was
  found while verifying the bx-006 fix — the first version only handled spaces, not tabs); a bidi
  Trojan-Source character injected mid-token (bx-018) is caught by the global invisible-character
  strip. A base64-encoded keyword-context phrase (bx-016) needed no fix at all — it's already caught
  by the entropy backstop, confirming the defense-in-depth holds against at least one real
  encoding-evasion attempt without any dedicated code for it. Five more invisible/format characters
  (word joiner, Mongolian vowel separator, soft hyphen, variation selectors, combining grapheme
  joiner — bx-019 through bx-023) were found by systematically probing candidate zero-width
  characters against the real pipeline rather than relying on the original curated list being
  exhaustive, and closed the same way as bx-018. A precomposed or combining-mark accented Latin
  letter mid-token (bx-024/bx-025) — a materially different mechanism from the Cyrillic/Greek
  homoglyphs: `normalize()`'s own NFKC step composes a base letter + combining accent into a single
  precomposed character (e.g. "Á") before detection ever runs, so the gap was that the composed
  letter doesn't match an ASCII-only `[A-Z]` class — was closed by extending `fold_confusables()`'s
  table, not by touching the invisible-character strip. A Unicode dash lookalike substituted for the
  literal "-" in a prefix-marker anchor (bx-026, e.g. Slack's `xoxb-`) — visually near-identical to
  ASCII "-" in most fonts but not covered by NFKC (unlike the fullwidth hyphen, which already folds)
  — was closed the same way as the accented-Latin fix, verified against dense hyphenated-compound-
  word prose and number ranges for zero false positives.
  bx-027 through bx-030 are a different kind of addition — PII-breadth coverage (credit card numbers,
  SSNs) rather than an evasion-technique fix, added deliberately paired positive/negative: bx-027 (a
  real, publicly-published Visa test number) proves detection fires, bx-028 (a same-length, wrong-BIN-
  prefix digit run) proves the network-prefix check is load-bearing, not just the Luhn checksum;
  bx-029 (a dash-separated fictional-example SSN) proves detection fires, bx-030 (a bare unseparated
  9-digit run with no SSN-related keyword nearby) proves the strict standalone rule stays narrow rather
  than flagging every 9-digit number in existence — see `engine/detectors/regex_rules.py`'s
  `find_credit_cards()`/`pii.ssn` and `context_rules.py`'s `pii.ssn_context` for the actual
  implementation and the reasoning behind each guard.
- **False-positive corpus** (`tests/adversarial/benign_corpus.json`, run via
  `pytest tests/adversarial/test_false_positive_rate.py`): 25 hand-written benign chat samples
  (ordinary prose, code, git SHAs, UUIDs-as-record-ids, service names mentioned with no adjacent
  secret, config placeholders, hash/digest mentions, plus a keyword mentioned near several unrelated
  short lines — added as a direct regression guard for the bx-014 fix above). 23/25 clean; 2
  documented, low-severity false positives from the Shannon-entropy backstop (an npm package-lock
  integrity hash, and a very long camelCase identifier) — both `warn` only, never `block`, so
  real-world impact is a single quiet toast notification, not an interrupted or corrupted message.
  Tracked as an accepted tradeoff, not hidden: a stricter entropy threshold would risk missing real
  base64/hex-encoded secrets.
- **Latency** (measured locally, `engine.detectors` + `engine.policy` pipeline only, no network/proxy
  overhead, 30 runs per case, all 205 detector rules plus the 96-rule space-tolerant scan active):

  | Input | Size | Mean | p95 | Max |
  |---|---|---|---|---|
  | Short chat message | ~100 chars | 0.3 ms | 0.3 ms | 0.3 ms |
  | Message with a real secret embedded | ~1 KB | 1.6 ms | 1.7 ms | 1.7 ms |
  | Typical code paste | ~2 KB | 4.4 ms | 5.2 ms | 6.2 ms |
  | Large paste | ~20 KB | 37 ms | 47 ms | 47 ms |
  | Very large paste | ~100 KB | 171 ms | 185 ms | 188 ms |

  **Multi-turn conversations, measured separately** (full `ContextGuardAddon.request()` including the
  fake-mitmproxy-flow overhead, not just the detection pipeline, since this dimension didn't exist
  before every scannable turn -- not just the newest one -- started getting scanned on every request):

  | User turns in the request | Mean | p95 | ms/turn |
  |---|---|---|---|
  | 1 | 0.19 ms | 0.20 ms | 0.19 |
  | 10 | 1.74 ms | 1.78 ms | 0.17 |
  | 50 | 8.96 ms | 9.07 ms | 0.18 |
  | 200 | 36.3 ms | 37.5 ms | 0.18 |

  Confirms linear scaling with turn count (~0.18ms/turn, no quadratic blowup) for ordinary-length turns.
  A long-running conversation naturally costs more per request than a fresh one -- inherent to actually
  closing the gap where only the newest turn was scanned, not a regression -- but stays imperceptible
  (tens of ms) even at hundreds of turns, since real chat-completion APIs are stateless and a client
  already has to serialize/transmit that same full history on every request regardless.

  A separate stress test (`engine/detectors/regex_rules.py`'s anchor-dense worst case: a message that's
  nothing but short anchor literals like "YC"/"SG."/"sk-" back to back) confirmed linear, not quadratic,
  scaling up to 1.5MB of adversarial input — no ReDoS reintroduced by the much larger anchor set. These
  numbers rose slightly (~10-25%) from the previous measurement after the space-tolerant scan grew from
  9 to 96 rules — still scales roughly linearly with input size, and a typical chat message or code
  paste (well under 20KB) adds single-digit milliseconds, imperceptible next to normal network
  round-trip time to an AI provider. A 100KB+ paste is the one case worth being explicit about: it adds
  a real, human-perceptible delay (~170ms) before the request goes out. See README's note on large
  pastes/documents for how this is handled (not silently dropped, not a hard multi-second stall either).

## What's not done yet

- A larger, security-reviewed corpus covering more evasion techniques — the 12 fixed gaps found so far
  (homoglyphs x2, accented-Latin letters x2, dash lookalikes, line-split values, space/tab injection,
  bidi override, 5 more invisible/format characters) are a start, not comprehensive. Encoding evasion has one real
  covered case (bx-016) but not a systematic sweep (different encodings, nested encoding, base64/hex-
  encoded whole secrets pasted directly with no dedicated decode-and-rescan step, etc.). The
  space/tab-tolerant scan in `regex_rules.py` now covers 96 of 115 prefix
  rules; the 19 deliberately excluded (see the comment above `SPACE_TOLERANT_RULES` in that file) are
  either anchored on a common English word/tech term (not worth the anchor-scan cost on ordinary
  prose), have no literal anchor at the true start of the pattern (this mechanism can't help them),
  or are normally 250+ chars and effectively always copy-pasted programmatically rather than retyped
  by hand. A residual, accepted gap even within the 96 covered: a space/tab landing *inside* the
  anchor's own literal characters (not the tail) still isn't caught — verified during development,
  not fixed, see that file's comment for why.
- Any numbers from a real proxy run against a real AI provider (this doc's latency numbers are the
  detection pipeline in isolation, not `mitmdump` + TLS + network overhead end to end).
- Any numbers from real-world traffic rather than a hand-written corpus.
