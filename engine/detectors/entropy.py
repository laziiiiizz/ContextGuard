"""Shannon-entropy backstop for secret-shaped tokens no regex matches."""
import math
import re

from engine.finding import Finding

TOKEN_PATTERN = re.compile(r'[A-Za-z0-9+/=_\-]{20,}')
MIN_LENGTH = 20
MIN_ENTROPY = 4.0


def shannon_entropy(token: str) -> float:
    if not token:
        return 0.0
    counts = {}
    for ch in token:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(token)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def run(text: str) -> list[Finding]:
    findings = []
    for match in TOKEN_PATTERN.finditer(text):
        token = match.group(0)
        if len(token) < MIN_LENGTH:
            continue
        entropy = shannon_entropy(token)
        if entropy < MIN_ENTROPY:
            continue
        findings.append(Finding(
            span_start=match.start(),
            span_end=match.end(),
            category='secret.high_entropy_token',
            confidence=min(0.5 + (entropy - MIN_ENTROPY) * 0.1, 0.85),
            detector_id='entropy.shannon_v1',
            raw_value=token,
        ))
    return findings
