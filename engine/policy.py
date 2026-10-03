# Loads + verifies policy.yaml, evaluates findings against it into decisions.
import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from engine.finding import Finding
from engine.policy_signing import verify_policy_signature

POLICY_PATH = os.path.join('policy', 'policy.yaml')


@dataclass
class Decision:
    finding: Finding
    action: str  # allow | warn | transform | block
    mandatory: bool
    transform_type: str | None = None


def load_policy(path: str = POLICY_PATH) -> list[dict]:
    verify_policy_signature(Path(path))  # raises PolicyIntegrityError, fail-safe
    with open(path, encoding='utf-8') as f:
        return yaml.safe_load(f) or []  # safe_load only -- never yaml.load


def evaluate(findings: list[Finding], rules: list[dict], destination_class: str) -> list[Decision]:
    decisions = []
    for finding in findings:
        rule = next(
            (r for r in rules
             if r['category'] == finding.category
             and r.get('destination_class', destination_class) == destination_class),
            None,
        )
        if rule is None or finding.confidence < rule['min_confidence']:
            decisions.append(Decision(finding=finding, action='allow', mandatory=False))
            continue
        decisions.append(Decision(
            finding=finding,
            action=rule['action'],
            mandatory=rule.get('mandatory', False),
            transform_type=rule.get('transform_type'),
        ))
    return decisions
