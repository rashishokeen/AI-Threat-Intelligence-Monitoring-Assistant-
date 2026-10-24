from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

Confidence = Literal["High", "Medium", "Low"]


@dataclass
class Finding:
    """One normalized advisory. Retrieval and extraction code should return this shape."""

    cve_id: str
    title: str
    products: list[str]
    affected_versions: list[str]
    fixed_versions: list[str]
    severity: float | None          # CVSS-like value on a 0-10 scale
    known_exploited: bool | None    # None means unknown, not false
    published_at: str | None        # ISO date/time string
    source_url: str
    fetched_at: str                 # ISO date/time string
    stack_match: float | None       # 0-10; None means not assessed
    score: float | None             # 0-10; None means not scored
    confidence: Confidence
    suggested_fix: str | None
    evidence: str                   # Short excerpt or explanation from the source

    def to_dict(self) -> dict:
        return asdict(self)
