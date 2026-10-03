"""Filters out findings whose raw value is in policy/allowlist.yaml."""
import os
from pathlib import Path

import yaml

from engine.finding import Finding
from engine.policy_signing import verify_policy_signature

ALLOWLIST_PATH = os.path.join('policy', 'allowlist.yaml')


def load_allowlist(path: str = ALLOWLIST_PATH) -> set[str]:
    if not os.path.exists(path):
        return set()
    # Signed like policy.yaml/domains.yaml -- an unsigned allowlist is a
    # silent way to suppress real findings, so a present-but-unsigned or
    # tampered file fails closed (raises PolicyIntegrityError) rather than
    # being trusted.
    verify_policy_signature(Path(path))
    with open(path, encoding='utf-8') as f:
        entries = yaml.safe_load(f) or []
    return {entry['value'] for entry in entries}


def filter_findings(findings: list[Finding], allowlist: set[str]) -> list[Finding]:
    return [f for f in findings if f.raw_value not in allowlist]
