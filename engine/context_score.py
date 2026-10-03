"""Adjusts finding confidence per destination class, without touching detectors."""
from engine.finding import Finding

DESTINATION_MULTIPLIER = {
    'public-ai': 1.0,
    'internal-ai': 0.7,
}


def adjust_confidence(finding: Finding, destination_class: str) -> Finding:
    multiplier = DESTINATION_MULTIPLIER.get(destination_class, 1.0)
    finding.confidence = min(finding.confidence * multiplier, 1.0)
    return finding
