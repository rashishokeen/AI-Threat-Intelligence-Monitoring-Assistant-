from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

SEARCH_URL = "https://api.search.tinyfish.ai"
FETCH_URL = "https://api.fetch.tinyfish.ai"
MAX_RESULTS_PER_PRODUCT = 3
MAX_FETCH_URLS = 10


class TinyFishError(RuntimeError):
    """A short, user-readable TinyFish integration error."""


def _api_error(response: requests.Response, action: str) -> TinyFishError:
    if response.status_code == 401:
        return TinyFishError("TinyFish rejected the API key. Check .streamlit/secrets.toml.")
    if response.status_code == 429:
        return TinyFishError("TinyFish rate limit reached. Wait briefly, then try again.")
    if response.status_code == 402:
        return TinyFishError("TinyFish daily allowance is exhausted for this API key.")
    return TinyFishError(f"TinyFish {action} failed (HTTP {response.status_code}).")


def _normalise_url(value: str) -> str | None:
    value = (value or "").strip()
    if not value:
        return None
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return value


def search_advisories(products: list[str], api_key: str) -> list[dict]:
    """Search each stack product and return a small set of source leads."""
    headers = {"X-API-Key": api_key}
    found: list[dict] = []
    seen_urls: set[str] = set()

    for product in products:
        query = f'"{product}" security advisory CVE vulnerability patch'
        try:
            response = requests.get(
                SEARCH_URL,
                headers=headers,
                params={
                    "query": query,
                    "purpose": f"Find public security advisories relevant to {product} and their vendor sources.",
                    "language": "en",
                },
                timeout=30,
            )
        except requests.RequestException as exc:
            raise TinyFishError(f"Could not reach TinyFish Search: {exc}") from exc

        if not response.ok:
            raise _api_error(response, "Search")
        try:
            payload = response.json()
        except ValueError as exc:
            raise TinyFishError("TinyFish Search returned an unreadable response.") from exc

        product_count = 0
        for item in payload.get("results", []):
            url = _normalise_url(item.get("url", ""))
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            found.append(
                {
                    "product": product,
                    "title": item.get("title") or url,
                    "site_name": item.get("site_name") or "",
                    "snippet": item.get("snippet") or "",
                    "url": url,
                    "search_query": query,
                }
            )
            product_count += 1
            if product_count >= MAX_RESULTS_PER_PRODUCT:
                break

    return found[:MAX_FETCH_URLS]


def fetch_pages(search_results: list[dict], api_key: str) -> tuple[list[dict], list[dict]]:
    """Fetch source pages in one bounded request and attach a fetch timestamp."""
    unique_results: list[dict] = []
    seen_urls: set[str] = set()
    for item in search_results:
        url = _normalise_url(item.get("url", ""))
        if url and url not in seen_urls:
            seen_urls.add(url)
            unique_results.append({**item, "url": url})
        if len(unique_results) >= MAX_FETCH_URLS:
            break

    if not unique_results:
        return [], []

    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    try:
        response = requests.post(
            FETCH_URL,
            headers=headers,
            json={
                "urls": [item["url"] for item in unique_results],
                "format": "markdown",
                "purpose": "Read public security advisory pages and preserve evidence for triage.",
                "per_url_timeout_ms": 45000,
            },
            timeout=120,
        )
    except requests.RequestException as exc:
        raise TinyFishError(f"Could not reach TinyFish Fetch: {exc}") from exc

    if not response.ok:
        raise _api_error(response, "Fetch")
    try:
        payload = response.json()
    except ValueError as exc:
        raise TinyFishError("TinyFish Fetch returned an unreadable response.") from exc

    result_by_url = {item["url"]: item for item in unique_results}
    fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    fetched_pages: list[dict] = []
    for item in payload.get("results", []):
        requested_url = _normalise_url(item.get("url", ""))
        if not requested_url:
            continue
        search_item = result_by_url.get(requested_url, {})
        fetched_pages.append(
            {
                **search_item,
                "requested_url": requested_url,
                "final_url": item.get("final_url") or requested_url,
                "title": item.get("title") or search_item.get("title") or requested_url,
                "text": item.get("text") or "",
                "fetched_at": fetched_at,
            }
        )

    errors = payload.get("errors", [])
    return fetched_pages, errors if isinstance(errors, list) else []
