from __future__ import annotations

from datetime import date, datetime, timezone
from urllib.parse import urlparse


def recency_score(published_at: str) -> float | None:
    """Convert publication age into the formula's 0-10 recency component."""
    published = None
    for parser in (
        lambda value: datetime.fromisoformat(value.replace("Z", "+00:00")).date(),
        lambda value: date.fromisoformat(value[:10]),
        lambda value: datetime.strptime(value, "%m/%d/%Y").date(),
    ):
        try:
            published = parser(published_at)
            break
        except (AttributeError, TypeError, ValueError):
            continue
    if published is None:
        return None

    age = (datetime.now(timezone.utc).date() - published).days
    if age < 0:
        return None
    if age <= 30:
        return 10.0
    if age <= 90:
        return 8.0
    if age <= 180:
        return 6.0
    if age <= 365:
        return 4.0
    if age <= 730:
        return 2.0
    return 0.0


def _is_primary_source(url: str, products: list[str]) -> bool:
    host = (urlparse(url).hostname or "").casefold()
    if host.endswith(".gov") or host in {"cve.org", "www.cve.org", "nvd.nist.gov"}:
        return True
    host_words = set(host.replace("-", ".").split("."))
    product_words = {
        word.casefold()
        for product in products
        for word in product.replace("-", " ").split()
        if len(word) > 2
    }
    return bool(host_words & product_words)


def score_finding(finding: dict, stack_match: dict) -> dict:
    """Score supported inputs; partial scores are normalized provisional estimates."""
    missing = []
    estimated = []
    components: dict[str, float] = {}
    weights = {"severity": 0.40, "known_exploited": 0.25, "stack_match": 0.25, "recency": 0.10}

    severity = finding.get("severity_cvss")
    if isinstance(severity, (int, float)) and not isinstance(severity, bool) and 0 <= severity <= 10:
        components["severity"] = float(severity)
    else:
        severity_bands = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.0}
        severity_text = str(finding.get("severity_text") or "").casefold().strip()
        estimated_severity = severity_bands.get(severity_text)
        if estimated_severity is not None:
            components["severity"] = estimated_severity
            estimated.append("severity (estimated from category)")
        else:
            missing.append("CVSS severity")

    exploited = finding.get("known_exploited")
    if isinstance(exploited, bool):
        components["known_exploited"] = 10.0 if exploited else 0.0
    else:
        missing.append("known-exploited status")

    products = finding.get("products") or []
    stack_component = stack_match.get("stack_match")
    if products and isinstance(stack_component, (int, float)):
        components["stack_match"] = float(stack_component)
    else:
        missing.append("product details for stack matching")

    freshness = recency_score(finding.get("published_at") or "")
    if freshness is not None:
        components["recency"] = freshness
    else:
        missing.append("valid publication date")
    if not finding.get("evidence_quote_verified"):
        missing.append("verified source evidence")

    sources = finding.get("supporting_sources") or [
        {"source_url": finding.get("source_url", ""), "products": products}
    ]
    unique_sources = {
        source["source_url"]: source
        for source in sources
        if source.get("source_url")
    }
    source_count = max(1, len(unique_sources))
    primary_count = sum(
        _is_primary_source(url, source.get("products") or products)
        for url, source in unique_sources.items()
    )
    if len(components) < 4:
        confidence = "Low"
    elif source_count >= 3 and primary_count >= 2:
        confidence = "High"
    elif source_count >= 2 and primary_count >= 1:
        confidence = "Medium"
    else:
        confidence = "Low"

    if len(components) < 2 or not finding.get("evidence_quote_verified"):
        return {
            "score": None,
            "confidence": "Low",
            "missing_evidence": missing or ["at least two supported scoring factors"],
        }

    available_weight = sum(weights[name] for name in components)
    score = sum(weights[name] * value for name, value in components.items()) / available_weight
    return {
        "score": round(score, 1),
        "confidence": confidence,
        "provisional": len(components) < 4 or bool(estimated),
        "available_factor_count": len(components),
        "estimated_factors": estimated,
        "missing_evidence": missing,
        "components": {name: round(value, 1) for name, value in components.items()},
        "source_count": source_count,
        "primary_source_count": primary_count,
    }
