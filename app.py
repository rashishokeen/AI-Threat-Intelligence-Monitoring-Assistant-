import re
from hashlib import sha1

import streamlit as st
from src.extractor import DEFAULT_LLM_BASE_URL, DEFAULT_LLM_MODEL, ExtractionError, extract_advisories
from src.matcher import match_advisory_to_stack
from src.scoring import score_finding
from src.tinyfish_client import TinyFishError, fetch_pages, linked_advisory_detail_url, search_advisories

st.set_page_config(page_title="ZeroDay Threat Monitor", page_icon="🛡️", layout="wide")
st.title("AI Threat Intelligence Monitoring Assistant")
st.caption("Search public security advisories for software in your stack.")

with st.form("stack_form"):
    stack_text = st.text_area(
        "What software do you run?",
        placeholder="nginx, WordPress, Okta",
        help="Enter comma-separated product names for the MVP.",
    )
    submitted = st.form_submit_button("Save stack")

if submitted:
    stack = [item.strip() for item in stack_text.split(",") if item.strip()]
    if stack != st.session_state.get("tech_stack", []):
        for key in ("advisory_search_results", "advisory_fetched_pages", "advisory_fetch_errors", "advisory_has_searched", "advisory_extractions"):
            st.session_state.pop(key, None)
    st.session_state["tech_stack"] = stack

stack = st.session_state.get("tech_stack", [])
if stack:
    st.subheader("MVP stack")
    st.write(stack)
    try:
        api_key = st.secrets.get("TINYFISH_API_KEY", "")
        llm_api_key = st.secrets.get("LLM_API_KEY", "")
        llm_base_url = st.secrets.get("LLM_BASE_URL", DEFAULT_LLM_BASE_URL)
        llm_model = st.secrets.get("LLM_MODEL", DEFAULT_LLM_MODEL)
    except Exception:
        api_key = ""
        llm_api_key = ""
        llm_base_url = DEFAULT_LLM_BASE_URL
        llm_model = DEFAULT_LLM_MODEL

    if not api_key:
        st.warning("Add your TinyFish API key to .streamlit/secrets.toml to enable live search.")
        st.code('TINYFISH_API_KEY = "paste-your-key-here"', language="toml")
    elif st.button("Search advisories", type="primary"):
        try:
            with st.spinner("Searching for advisories and fetching source pages..."):
                search_results = search_advisories(stack, api_key)
                fetched_pages, fetch_errors = fetch_pages(search_results, api_key)
            st.session_state["advisory_search_results"] = search_results
            st.session_state["advisory_fetched_pages"] = fetched_pages
            st.session_state["advisory_fetch_errors"] = fetch_errors
            st.session_state["advisory_has_searched"] = True
        except TinyFishError as exc:
            st.error(str(exc))

    search_results = st.session_state.get("advisory_search_results", [])
    fetched_pages = st.session_state.get("advisory_fetched_pages", [])
    fetch_errors = st.session_state.get("advisory_fetch_errors", [])

    if search_results:
        st.subheader(f"Search results ({len(search_results)})")
        st.caption("Risk score: 40% severity, 25% known exploitation, 25% stack match, 10% recency.")
        fetched_by_url = {page.get("requested_url"): page for page in fetched_pages}

        for index, result in enumerate(search_results, start=1):
            page = fetched_by_url.get(result["url"])
            with st.container(border=True):
                st.markdown(f"**{index}. {result['title']}**")
                st.caption(f"For: {result['product']} · {result.get('site_name') or 'Source'}")
                st.write(result.get("snippet") or "No search snippet was returned.")
                st.link_button("Open source", result["url"])
                if page:
                    st.caption(f"Fetched at: {page['fetched_at']}")
                    extraction_key = page["requested_url"]
                    extraction_id = sha1(extraction_key.encode("utf-8")).hexdigest()[:12]
                    if llm_api_key:
                        st.caption("Sends this fetched page's text to Gemini to extract the stated advisory facts.")
                        if st.button("Extract advisory details", key=f"extract_{extraction_id}"):
                            try:
                                with st.spinner("Opening the detailed bulletin and extracting stated facts..."):
                                    result_context = " ".join(
                                        (result.get("title", ""), result.get("snippet", ""), page.get("text", ""))
                                    )
                                    cve_match = re.search(r"CVE-\d{4}-\d{4,}", result_context, re.IGNORECASE)
                                    detail_url = linked_advisory_detail_url(
                                        page.get("text", ""), cve_match.group(0) if cve_match else None
                                    )
                                    extraction_page = page
                                    if detail_url and detail_url != page.get("requested_url"):
                                        detail_pages, _ = fetch_pages(
                                            [{"url": detail_url, "title": result["title"], "product": result["product"]}],
                                            api_key,
                                        )
                                        if detail_pages:
                                            extraction_page = detail_pages[0]
                                    extraction = extract_advisories(
                                        page_title=extraction_page.get("title", result["title"]),
                                        source_url=extraction_page.get("final_url", extraction_page["requested_url"]),
                                        page_text=extraction_page.get("text", ""),
                                        api_key=llm_api_key,
                                        target_cve_id=cve_match.group(0) if cve_match else None,
                                        model=llm_model,
                                        base_url=llm_base_url,
                                    )
                                    for finding in extraction["advisories"]:
                                        finding.update(match_advisory_to_stack(finding, stack))
                                st.session_state.setdefault("advisory_extractions", {})[extraction_key] = extraction
                            except (ExtractionError, TinyFishError) as exc:
                                st.error(str(exc))

                    extractions = st.session_state.get("advisory_extractions", {})
                    extraction = extractions.get(extraction_key)
                    if extraction:
                        st.markdown("**Extracted advisory details**")
                        if not extraction["advisories"]:
                            st.info(extraction["page_summary"] or "No clear advisory details were found on this page.")
                        else:
                            if extraction["page_summary"]:
                                st.caption(extraction["page_summary"])
                            for finding_number, finding in enumerate(extraction["advisories"], start=1):
                                with st.container(border=True):
                                    match = match_advisory_to_stack(finding, stack)
                                    heading = finding.get("cve_id") or f"Advisory {finding_number}"
                                    st.markdown(f"**{heading}: {finding.get('title') or 'Untitled advisory'}**")
                                    if match["stack_match_status"] == "matched":
                                        st.success(
                                            f"Product-name match: {', '.join(match['matched_stack_items'])} "
                                            f"(name overlap {match['stack_match']:.0f}/10)"
                                        )
                                    elif match["stack_match_status"] == "review":
                                        st.warning(
                                            f"Possible product-name match: {', '.join(match['possible_stack_items'])} "
                                            f"(name overlap {match['stack_match']:.0f}/10). Review the product manually."
                                        )
                                    else:
                                        st.caption("No saved stack product name matched this advisory.")
                                    if finding.get("source_url"):
                                        st.link_button(
                                            "Open extracted source",
                                            finding["source_url"],
                                            key=f"source_{extraction_id}_{finding_number}",
                                        )
                                    st.write("Products:", ", ".join(finding.get("products") or []) or "Not stated")
                                    st.write("Affected versions:", ", ".join(finding.get("affected_versions") or []) or "Not stated")
                                    st.write("Fixed versions:", ", ".join(finding.get("fixed_versions") or []) or "Not stated")
                                    severity = finding.get("severity_cvss")
                                    severity_text = finding.get("severity_text")
                                    st.write("Severity:", f"{severity}/10" if severity is not None else (severity_text or "Not stated"))
                                    st.write("Published:", finding.get("published_at") or "Not stated")
                                    exploited = finding.get("known_exploited")
                                    exploited_text = "Yes" if exploited is True else "No" if exploited is False else "Not stated"
                                    st.write("Known exploited:", exploited_text)
                                    quote = finding.get("evidence_quote") or ""
                                    if quote and finding.get("evidence_quote_verified"):
                                        st.caption(f"Evidence from source: “{quote}”")
                                    elif quote:
                                        st.warning("The extracted evidence quote did not exactly match the fetched page. Check the source before relying on these details.")
                                    related_sources = []
                                    current_cve = finding.get("cve_id")
                                    if current_cve:
                                        for saved_extraction in st.session_state.get("advisory_extractions", {}).values():
                                            for related in saved_extraction.get("advisories", []):
                                                if (
                                                    related.get("cve_id") == current_cve
                                                    and related.get("source_url")
                                                    and related.get("evidence_quote_verified")
                                                ):
                                                    related_sources.append(
                                                        {
                                                            "source_url": related["source_url"],
                                                            "products": related.get("products") or [],
                                                        }
                                                    )
                                    assessment = score_finding(
                                        {**finding, "supporting_sources": related_sources}, match
                                    )
                                    with st.container(border=True):
                                        score_col, detail_col = st.columns([1, 3])
                                        with score_col:
                                            st.caption("RISK SCORE")
                                            st.markdown(
                                                f"### {'~' if assessment.get('provisional') else ''}{assessment['score']}/10"
                                                if assessment["score"] is not None
                                                else "### — / 10"
                                            )
                                        with detail_col:
                                            if assessment["score"] is None:
                                                st.markdown(
                                                    f"**Not enough evidence · Confidence: {assessment['confidence']}**"
                                                )
                                                with st.expander("Why no score?"):
                                                    for missing_item in assessment["missing_evidence"]:
                                                        st.write(missing_item)
                                            else:
                                                st.markdown(f"**Confidence: {assessment['confidence']}**")
                                                st.caption(
                                                    (
                                                        f"Provisional · {assessment['available_factor_count']}/4 factors available."
                                                        if assessment.get("provisional")
                                                        else f"{assessment['source_count']} verified source(s), "
                                                        f"{assessment['primary_source_count']} identified as primary."
                                                    )
                                                )
                                                if assessment.get("missing_evidence") or assessment.get("estimated_factors"):
                                                    with st.expander("Score assumptions"):
                                                        for estimate in assessment.get("estimated_factors", []):
                                                            st.write(estimate)
                                                        for missing_item in assessment.get("missing_evidence", []):
                                                            st.write(f"Missing: {missing_item}")
                                                with st.expander("Score breakdown"):
                                                    components = assessment["components"]
                                                    weights = {
                                                        "severity": 40,
                                                        "known_exploited": 25,
                                                        "stack_match": 25,
                                                        "recency": 10,
                                                    }
                                                    for name, value in components.items():
                                                        st.write(f"{name.replace('_', ' ').title()}: {value}/10 · {weights[name]}% weight")
                                                    if assessment.get("provisional"):
                                                        st.caption("Available factor weights are normalized to a 0–10 provisional score.")
                    elif not llm_api_key:
                        st.caption("Phase 3 extraction needs a Gemini API key saved as LLM_API_KEY in .streamlit/secrets.toml.")
                    with st.expander("Fetched page content"):
                        st.markdown(page.get("text") or "The page returned no readable text.")
    elif st.session_state.get("advisory_has_searched"):
        st.info("No search results were returned for this stack. Try a more specific product name.")

    if fetch_errors:
        with st.expander(f"Pages that could not be fetched ({len(fetch_errors)})"):
            for item in fetch_errors:
                st.write(f"{item.get('url', 'Unknown URL')}: {item.get('error', 'Fetch failed')}")
else:
    st.info("Enter a small demo stack, then save it.")

with st.expander("Finding format for the team"):
    st.code(
        "cve_id, title, products, affected_versions, fixed_versions, "
        "severity, known_exploited, published_at, source_url, fetched_at, "
        "stack_match, score, confidence, suggested_fix, evidence",
        language="text",
    )
