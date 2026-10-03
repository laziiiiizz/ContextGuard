from dataclasses import dataclass


@dataclass
class Finding:
    span_start: int
    span_end: int
    category: str
    confidence: float
    detector_id: str
    raw_value: str  # in-memory only, never persisted/logged
