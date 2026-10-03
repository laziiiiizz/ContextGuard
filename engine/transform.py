"""One function per policy action (mask/tokenize/generalize/remove)."""
from engine.alias_vault import AliasVault
from engine.finding import Finding


def mask(finding: Finding) -> str:
    return f'[{finding.category.split(".")[-1].upper()}]'


def tokenize(finding: Finding, vault: AliasVault, session_id: str) -> str:
    return vault.get_or_create(session_id, finding.raw_value, finding.category)


def generalize(finding: Finding, buckets: list | None = None) -> str:
    # buckets: [(threshold, label), ...], set per category. None if unconfigured.
    if not buckets:
        return f'[GENERALIZED {finding.category.split(".")[-1].upper()}]'
    for threshold, label in buckets:
        try:
            if float(finding.raw_value) >= threshold:
                return label
        except ValueError:
            break
    return f'[GENERALIZED {finding.category.split(".")[-1].upper()}]'


def remove(finding: Finding) -> str:
    return ''
