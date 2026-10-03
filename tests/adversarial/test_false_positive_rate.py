"""Measures the real false-positive rate against ordinary, non-secret chat
content -- corpus.json (test_bypass_corpus.py) only covers true-positive/
bypass cases, this covers the other direction. Every case is expected to be
'allow' unless explicitly documented as a known_false_positive (with why),
same honesty discipline as corpus.json's known_gap cases: an accepted
tradeoff is tracked, not hidden, and a NEW false positive fails the suite
immediately instead of silently degrading the false-positive rate."""
import json
import os

import pytest

from engine.context_score import adjust_confidence
from engine.detectors import allowlist, context_rules, entropy, regex_rules
from engine.normalize import fold_confusables, normalize
from engine.policy import evaluate, load_policy

CORPUS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'benign_corpus.json')
POLICY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                            'policy', 'policy.yaml')

with open(CORPUS_PATH, encoding='utf-8') as f:
    CORPUS = json.load(f)

RULES = load_policy(POLICY_PATH)


def run_case(text: str) -> list:
    # Must mirror proxy/addon.py's request() handling -- see the same note in
    # test_bypass_corpus.py.
    content = normalize(text)
    folded = fold_confusables(content)  # detection-only, see fold_confusables()'s docstring
    findings = regex_rules.run(folded) + entropy.run(folded) + context_rules.run(folded)
    findings = allowlist.filter_findings(findings, allowlist.load_allowlist())
    findings = [adjust_confidence(f, 'public-ai') for f in findings]
    return evaluate(findings, RULES, destination_class='public-ai')


@pytest.mark.parametrize('case', [c for c in CORPUS if not c.get('known_false_positive')], ids=lambda c: c['id'])
def test_benign_case_is_allowed(case):
    text = case['text'] * case.get('repeat', 1)
    decisions = run_case(text)
    non_allow = [d for d in decisions if d.action != 'allow']
    assert not non_allow, (
        f"{case['id']}: expected allow (benign text), got "
        f"{[(d.finding.category, d.action) for d in non_allow]} -- {case.get('note', '')}. "
        f"If this is a real, acceptable tradeoff (not a bug), add known_false_positive to the case "
        f"in benign_corpus.json with a fp_reason explaining why -- don't just delete or change the case."
    )


@pytest.mark.parametrize('case', [c for c in CORPUS if c.get('known_false_positive')], ids=lambda c: c['id'])
def test_known_false_positive_still_fires_as_documented(case):
    # Inverse of test_bypass_corpus.py's known_gap check: confirms an accepted
    # false positive is still exactly what was documented, not silently worse
    # (a different category/action) or silently fixed (which would mean the
    # known_false_positive flag should be removed, not left stale).
    text = case['text'] * case.get('repeat', 1)
    decisions = run_case(text)
    matching = [d for d in decisions if d.finding.category == case['fp_category']]
    assert matching, f"{case['id']}: documented false positive category {case['fp_category']!r} did not fire at all -- update or remove the known_false_positive entry."
    assert matching[0].action == case['actual_action'], (
        f"{case['id']}: documented action was {case['actual_action']!r}, now {matching[0].action!r} -- "
        f"update benign_corpus.json to match (worse if now 'block', otherwise the fix should remove this entry)."
    )


def test_false_positive_rate_summary():
    total = len(CORPUS)
    known_fp = len([c for c in CORPUS if c.get('known_false_positive')])
    clean = total - known_fp
    print(f'\nFalse-positive corpus: {total} benign cases, {clean} clean, '
          f'{known_fp} documented low-severity false positives (all warn-only, none block).')
    assert known_fp <= 2, (
        'more than the 2 currently-accepted false positives are documented -- '
        'this is a real regression in FP rate, not just a number to bump.'
    )
