"""Guards against a real gap found during development: a detector category
with no matching policy.yaml row silently falls through evaluate() as
'allow' (see engine/policy.py) -- the finding is detected but nothing is
ever done about it. Every category a detector can produce must have a
policy row, for every destination_class the row set uses, or new secrets
ship fail-open by omission."""
import yaml

from engine.detectors.context_rules import CONTEXT_RULES
from engine.detectors.regex_rules import PYTHON_VALIDATED_CATEGORIES, RULES
from engine.policy import POLICY_PATH


def _policy_rows():
    with open(POLICY_PATH, encoding='utf-8') as f:
        return yaml.safe_load(f) or []


def test_every_regex_rule_category_has_a_policy_row():
    rows = _policy_rows()
    policy_cats = {r['category'] for r in rows}
    regex_cats = {category for category, _ in RULES}
    missing = regex_cats - policy_cats
    assert not missing, f'regex_rules categories with no policy.yaml row: {missing}'


def test_every_python_validated_category_has_a_policy_row():
    # Categories like pii.credit_card aren't produced by a plain RULES tuple
    # (find_credit_cards() does its own two-stage shape+Luhn check), so the
    # test above can't see them -- covered separately here for exactly that
    # reason.
    rows = _policy_rows()
    policy_cats = {r['category'] for r in rows}
    missing = PYTHON_VALIDATED_CATEGORIES - policy_cats
    assert not missing, f'Python-validated categories with no policy.yaml row: {missing}'


def test_every_context_rule_category_has_a_policy_row():
    rows = _policy_rows()
    policy_cats = {r['category'] for r in rows}
    context_cats = {category for category, _, _ in CONTEXT_RULES}
    missing = context_cats - policy_cats
    assert not missing, f'context_rules categories with no policy.yaml row: {missing}'


def test_no_duplicate_category_rows_for_the_same_destination_class():
    rows = _policy_rows()
    seen = set()
    dupes = set()
    for r in rows:
        key = (r['category'], r.get('destination_class'))
        if key in seen:
            dupes.add(key)
        seen.add(key)
    assert not dupes, f'duplicate policy rows (category, destination_class): {dupes}'
