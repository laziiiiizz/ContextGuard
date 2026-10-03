"""Runs corpus.json through the real pipeline; known_gap cases must still fail, not be hidden."""
import json
import os

import pytest

from engine.context_score import adjust_confidence
from engine.detectors import allowlist, context_rules, entropy, regex_rules
from engine.normalize import fold_confusables, normalize
from engine.policy import evaluate, load_policy

CORPUS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'corpus.json')
POLICY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                            'policy', 'policy.yaml')

with open(CORPUS_PATH, encoding='utf-8') as f:
    CORPUS = json.load(f)

RULES = load_policy(POLICY_PATH)


def run_case(text: str) -> list:
    # Must mirror proxy/addon.py's request() handling exactly -- this
    # duplication already caused a real bug once (context_rules was added to
    # the real pipeline but not here, so the whole adversarial suite silently
    # never exercised it). Keep the two in sync whenever either one changes.
    content = normalize(text)
    folded = fold_confusables(content)  # detection-only, see fold_confusables()'s docstring
    findings = regex_rules.run(folded) + entropy.run(folded) + context_rules.run(folded)
    findings = allowlist.filter_findings(findings, allowlist.load_allowlist())
    findings = [adjust_confidence(f, 'public-ai') for f in findings]
    return evaluate(findings, RULES, destination_class='public-ai')


def get_action_for_category(decisions, category: str):
    for d in decisions:
        if d.finding.category == category:
            return d.action
    return 'allow'


@pytest.mark.parametrize('case', [c for c in CORPUS if not c.get('known_gap')], ids=lambda c: c['id'])
def test_corpus_case_matches_expected_action(case):
    decisions = run_case(case['text'])
    actual = get_action_for_category(decisions, case['category'])
    assert actual == case['expected_action'], (
        f"{case['id']}: expected {case['expected_action']!r}, got {actual!r} -- {case.get('note', '')}")


def test_known_gap_cases_still_fail_as_documented():
    # A known_gap case that starts passing means the gap was fixed, so its
    # flag must be removed. Passes trivially when no known gaps remain.
    fixed = [c['id'] for c in CORPUS if c.get('known_gap')
             and get_action_for_category(run_case(c['text']), c['category']) == c['expected_action']]
    assert not fixed, f'these known_gap cases now pass; remove their known_gap flag: {fixed}'
