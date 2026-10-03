"""The user's own on/off choices for each kind of detection, set from the
Settings window. Kept apart from policy/policy.yaml on purpose: the policy
file is signed and ships with the app, while this is a plain preference the
user changes at runtime.

The GUI writes settings.json; the proxy addon (a separate process) reads it
on each request, re-parsing only when the file has changed. A missing or
unreadable file means every group is on, so a damaged settings file can
never switch protection off.
"""
import json
import os
from dataclasses import dataclass

from proxy.paths import get_writable_data_dir


@dataclass(frozen=True)
class Group:
    key: str
    label: str
    description: str


GROUPS = (
    Group('api_keys', 'API keys and access tokens',
          'AWS, GitHub, OpenAI, Stripe, private keys and 200+ other known formats. Blocked.'),
    Group('unknown_secrets', 'Unknown-format secrets',
          'Random-looking strings that match no known key format. Warning only.'),
    Group('credit_cards', 'Credit card numbers',
          'Card numbers that pass checksum and issuer checks. Blocked.'),
    Group('ssn', 'Social Security numbers',
          'US SSNs in a valid format. Blocked.'),
    Group('emails', 'Email addresses',
          'Masked before sending where the site allows it, otherwise a warning.'),
    Group('internal_network', 'Internal IPs and hostnames',
          'Private network addresses and internal server names. Warning only.'),
    Group('pdf_uploads', 'PDF uploads',
          'Checks the text of PDFs you upload, up to 50 pages. A PDF that cannot be checked '
          '(bigger, locked or images only) asks you to double-check it first.'),
)
GROUP_KEYS = tuple(group.key for group in GROUPS)

_EXACT_CATEGORY_GROUPS = {
    'secret.high_entropy_token': 'unknown_secrets',
    'pii.credit_card': 'credit_cards',
    'pii.ssn': 'ssn',
    'pii.ssn_context': 'ssn',
    'pii.email': 'emails',
}


def group_for_category(category: str) -> str | None:
    if category in _EXACT_CATEGORY_GROUPS:
        return _EXACT_CATEGORY_GROUPS[category]
    if category.startswith('secret.'):
        return 'api_keys'
    if category.startswith('infra.'):
        return 'internal_network'
    if category.startswith('file.'):
        return 'pdf_uploads'
    return None


def settings_path():
    return get_writable_data_dir() / 'settings.json'


_cache = {'stamp': None, 'disabled': frozenset()}


def disabled_groups() -> frozenset:
    path = settings_path()
    try:
        stat = path.stat()
    except OSError:
        return frozenset()
    stamp = (stat.st_mtime_ns, stat.st_size)
    if _cache['stamp'] != stamp:
        try:
            raw = json.loads(path.read_text(encoding='utf-8'))
            disabled = frozenset(key for key in raw.get('disabled_groups', []) if key in GROUP_KEYS)
        except (OSError, ValueError, AttributeError, TypeError):
            disabled = frozenset()
        _cache['stamp'], _cache['disabled'] = stamp, disabled
    return _cache['disabled']


def is_category_enabled(category: str) -> bool:
    return group_for_category(category) not in disabled_groups()


def set_group_enabled(key: str, enabled: bool) -> None:
    if key not in GROUP_KEYS:
        raise ValueError(f'unknown settings group: {key}')
    disabled = set(disabled_groups())
    if enabled:
        disabled.discard(key)
    else:
        disabled.add(key)
    path = settings_path()
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(json.dumps({'disabled_groups': sorted(disabled)}), encoding='utf-8')
    os.replace(tmp, path)  # atomic: the proxy never reads a half-written file
