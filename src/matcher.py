from __future__ import annotations

import re


_GENERIC_PRODUCT_WORDS = {
    "app",
    "apps",
    "application",
    "applications",
    "client",
    "clients",
    "com",
    "product",
    "products",
    "software",
    "version",
    "versions",
    "workplace",
}


def _tokens(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9]+", value.casefold())
        if token not in _GENERIC_PRODUCT_WORDS
    }


def match_advisory_to_stack(advisory: dict, stack: list[str]) -> dict:
    """Compare advisory product names to the saved stack; this does not check versions."""
    products = advisory.get("products") or []
    candidates = [name for name in products if isinstance(name, str) and name.strip()]
    if not candidates and advisory.get("title"):
        candidates = [str(advisory["title"])]

    scores: list[tuple[str, float]] = []
    for stack_item in stack:
        wanted = _tokens(stack_item)
        if not wanted:
            continue
        score = max(
            (
                10 * len(wanted & _tokens(product)) / len(wanted)
                for product in candidates
                if _tokens(product)
            ),
            default=0.0,
        )
        scores.append((stack_item, round(score, 1)))

    matches = [name for name, score in scores if score >= 8]
    possible = [name for name, score in scores if 0 < score < 8]
    best_score = max((score for _, score in scores), default=0.0)
    status = "matched" if matches else "review" if possible else "no_match"
    return {
        "stack_match": best_score,
        "stack_match_status": status,
        "matched_stack_items": matches,
        "possible_stack_items": possible,
    }
