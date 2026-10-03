from engine.finding import Finding
from engine.policy import evaluate

RULES = [
    {'category': 'secret.aws_key', 'min_confidence': 0.6, 'destination_class': 'public-ai',
     'action': 'block', 'mandatory': True},
    {'category': 'pii.email', 'min_confidence': 0.5, 'destination_class': 'public-ai',
     'action': 'transform', 'transform_type': 'mask', 'mandatory': False},
]


def make_finding(category, confidence):
    return Finding(span_start=0, span_end=5, category=category, confidence=confidence,
                    detector_id='test', raw_value='x')


def test_high_confidence_match_triggers_configured_action():
    findings = [make_finding('secret.aws_key', 0.9)]
    decisions = evaluate(findings, RULES, destination_class='public-ai')
    assert decisions[0].action == 'block'
    assert decisions[0].mandatory is True


def test_below_min_confidence_allows_instead():
    findings = [make_finding('secret.aws_key', 0.3)]
    decisions = evaluate(findings, RULES, destination_class='public-ai')
    assert decisions[0].action == 'allow'


def test_no_matching_rule_allows_by_default():
    findings = [make_finding('some.unlisted_category', 0.99)]
    decisions = evaluate(findings, RULES, destination_class='public-ai')
    assert decisions[0].action == 'allow'


def test_transform_rule_carries_transform_type():
    findings = [make_finding('pii.email', 0.7)]
    decisions = evaluate(findings, RULES, destination_class='public-ai')
    assert decisions[0].action == 'transform'
    assert decisions[0].transform_type == 'mask'
