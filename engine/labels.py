"""Plain-language names for the internal category and action ids, for the
window and the Don't Send popup. The ids themselves (e.g.
`secret.aws_access_token`) stay unchanged in the policy and the event log.
"""
from datetime import datetime

ACTION_LABELS = {
    'block': 'Blocked',
    'send_anyway': 'Sent anyway',
    'transform': 'Masked',
    'warn': 'Warned',
}

_CONTROL_LABELS = {
    'pause': 'Protection paused',
    'resume': 'Protection turned on',
    'quit': 'ContextGuard closed',
    'crash_recovered': 'Protection stopped unexpectedly',
    'auth_failed': 'Dashboard login refused',
}

_CATEGORY_LABELS = {
    'secret.high_entropy_token': 'Unknown-format secret',
    'secret.github_pat': 'GitHub access token',
    'secret.gitlab_pat': 'GitLab access token',
    'pii.credit_card': 'Credit card number',
    'pii.ssn': 'Social Security number',
    'pii.ssn_context': 'Social Security number',
    'pii.email': 'Email address',
    'infra.internal_ip': 'Internal IP address',
    'infra.internal_hostname': 'Internal hostname',
}

_WORDS = {
    'aws': 'AWS', 'api': 'API', 'github': 'GitHub', 'gitlab': 'GitLab', 'openai': 'OpenAI',
    'npm': 'npm', 'ssh': 'SSH', 'jwt': 'JWT', 'gcp': 'GCP', 'id': 'ID', 'oauth': 'OAuth',
    'url': 'URL', 'pat': 'access token', 'pypi': 'PyPI',
}


# Why a PDF was not checked: (short form for lists, sentence for the popup).
NOT_SCANNED_REASONS = {
    'too_large': ('over 25 MB', 'is larger than 25 MB'),
    'too_many_pages': ('over 50 pages', 'has more than 50 pages'),
    'locked': ('password-protected', 'is password-protected'),
    'no_text': ('images only', 'contains only images, so there is no text to check'),
    'unreadable': ('could not be read', 'could not be read'),
    'timeout': ('too slow to read', 'took too long to read'),
}


def not_scanned_reason(category: str) -> tuple[str, str] | None:
    if not category.startswith('file.not_scanned.'):
        return None
    return NOT_SCANNED_REASONS.get(category.rsplit('.', 1)[1], ('not checked', 'could not be checked'))


def friendly_category(category: str) -> str:
    """'secret.aws_access_token' -> 'AWS access token'."""
    reason = not_scanned_reason(category)
    if reason:
        return f'PDF not checked ({reason[0]})'
    if category in _CATEGORY_LABELS:
        return _CATEGORY_LABELS[category]
    words = category.split('.', 1)[-1].split('_')
    named = [_WORDS.get(word, word) for word in words]
    if named and named[0] == words[0]:
        named[0] = named[0].capitalize()
    return ' '.join(named)


def friendly_time(timestamp: str, now: datetime | None = None) -> str:
    """The log stores UTC ISO timestamps; show local clock time, with the
    date only when the event was not today."""
    try:
        local = datetime.fromisoformat(timestamp).astimezone()
    except ValueError:
        return timestamp
    now = now or datetime.now().astimezone()
    clock = local.strftime('%I:%M %p').lstrip('0')
    if local.date() == now.date():
        return clock
    return f'{local.strftime("%b")} {local.day}, {clock}'


# Upload servers whose names mean nothing to a user (see proxy/domains.yaml).
_HOST_LABELS = {
    'contribution-rt.usercontent.google.com': 'Gemini (file upload)',
    'push.clients6.google.com': 'Gemini (file upload)',
    'content-push.googleapis.com': 'Gemini (file upload)',
}


def friendly_host(host: str) -> str:
    host = host.lower()
    if host == 'oaiusercontent.com' or host.endswith('.oaiusercontent.com'):
        return 'ChatGPT (file upload)'
    return _HOST_LABELS.get(host, host)


def describe_event(category: str, action: str, host: str) -> tuple[str, str, str]:
    """(what happened, what it was, where) for one event-log row."""
    if category == 'contextguard.control':
        return _CONTROL_LABELS.get(action, action), '', ''
    return ACTION_LABELS.get(action, action), friendly_category(category), friendly_host(host)
