import csv
import io
import re
from hashlib import sha1

import streamlit as st
from src.extractor import DEFAULT_LLM_BASE_URL, DEFAULT_LLM_MODEL, ExtractionError, extract_advisories
from src.matcher import match_advisory_to_stack
from src.scoring import score_finding
from src.tinyfish_client import TinyFishError, fetch_pages, linked_advisory_detail_url, search_advisories

st.set_page_config(page_title="ZeroDay Threat Monitor", page_icon="🛡️", layout="wide")
st.markdown(":orange-badge[THREAT INTELLIGENCE] :green-badge[SOURCE-FIRST]")
st.title("ZeroDay Threat Monitor", icon=":material/radar:")
st.caption("A focused radar for vulnerabilities affecting the software your team runs.")

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

search_clicked = False
with st.container(border=True):
    stack_col, action_col = st.columns([1.6, 1], vertical_alignment="center")
    with stack_col:
        st.subheader("Your software stack", icon=":material/dns:")
        st.caption("Add the products and services you want to monitor, separated by commas.")
        with st.form("stack_form"):
            stack_text = st.text_input(
                "Products to monitor",
                value=", ".join(st.session_state.get("tech_stack", [])),
                placeholder="nginx, WordPress, Okta",
                help="Use the product names your team recognizes. You can add versions later.",
            )
            submitted = st.form_submit_button("Save stack", type="primary", icon=":material/save:")
    if submitted:
        stack = [item.strip() for item in stack_text.split(",") if item.strip()]
        if stack != st.session_state.get("tech_stack", []):
            for key in (
                "advisory_search_results",
                "advisory_fetched_pages",
                "advisory_fetch_errors",
                "advisory_has_searched",
                "advisory_extractions",
            ):
                st.session_state.pop(key, None)
        st.session_state["tech_stack"] = stack

    stack = st.session_state.get("tech_stack", [])
    with stack_col:
        if stack:
            st.caption("MONITORING")
            with st.container(horizontal=True):
                for product in stack:
                    st.badge(product, color="green", icon=":material/inventory_2:")
    with action_col:
        st.markdown("**Live monitoring**")
        if not stack:
            st.info("Save your software stack to begin.", icon=":material/arrow_back:")
        elif api_key:
            st.badge("Search connected", color="green", icon=":material/radar:")
            st.caption("Search public advisories and fetch their source pages.")
            search_clicked = st.button(
                "Search advisories", type="primary", icon=":material/search:", width="stretch"
            )
        else:
            st.badge("Setup needed", color="orange", icon=":material/key_off:")
            st.caption("Connect TinyFish to search live sources.")
            with st.expander("Configure search access"):
                st.caption("Add this setting to `.streamlit/secrets.toml`:")
                st.code('TINYFISH_API_KEY = "paste-your-key-here"', language="toml")

if search_clicked:
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

if stack:

    search_results = st.session_state.get("advisory_search_results", [])
    fetched_pages = st.session_state.get("advisory_fetched_pages", [])
    fetch_errors = st.session_state.get("advisory_fetch_errors", [])

    if search_results:
        st.header("Advisory results", icon=":material/travel_explore:")
        st.caption(f"{len(search_results)} source pages found · review extracted details before acting.")
        fetched_by_url = {page.get("requested_url"): page for page in fetched_pages}
        report_rows = []

        for index, result in enumerate(search_results, start=1):
            page = fetched_by_url.get(result["url"])
            report_rows_before_result = len(report_rows)
            with st.container(border=True):
                st.markdown(f"**{index}. {result['title']}**")
                st.caption(f":material/inventory_2: {result['product']}  ·  :material/language: {result.get('site_name') or 'Source'}")
                st.write(result.get("snippet") or "No search snippet was returned.")
                st.link_button("Open source page", result["url"], icon=":material/open_in_new:")
                if page:
                    st.caption(f"Source fetched {page['fetched_at']}")
                    extraction_key = page["requested_url"]
                    extraction_id = sha1(extraction_key.encode("utf-8")).hexdigest()[:12]
                    if llm_api_key:
                        st.caption("AI extraction reads the fetched page and reports details stated in the source.")
                        if st.button("Extract advisory details", key=f"extract_{extraction_id}", icon=":material/auto_awesome:"):
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
                                            "View source evidence",
                                            finding["source_url"],
                                            key=f"source_{extraction_id}_{finding_number}",
                                            icon=":material/open_in_new:",
                                        )
                                    product_col, affected_col, fixed_col = st.columns(3)
                                    with product_col:
                                        st.caption("PRODUCTS")
                                        st.write(", ".join(finding.get("products") or []) or "Not stated")
                                    with affected_col:
                                        st.caption("AFFECTED VERSIONS")
                                        st.write(", ".join(finding.get("affected_versions") or []) or "Not stated")
                                    with fixed_col:
                                        st.caption("FIXED VERSIONS")
                                        st.write(", ".join(finding.get("fixed_versions") or []) or "Not stated")
                                    severity = finding.get("severity_cvss")
                                    severity_text = finding.get("severity_text")
                                    status_col, date_col, exploited_col = st.columns(3)
                                    with status_col:
                                        st.caption("SEVERITY")
                                        st.write(f"{severity}/10" if severity is not None else (severity_text or "Not stated"))
                                    with date_col:
                                        st.caption("PUBLISHED")
                                        st.write(finding.get("published_at") or "Not stated")
                                    exploited = finding.get("known_exploited")
                                    exploited_text = "Yes" if exploited is True else "No" if exploited is False else "Not stated"
                                    with exploited_col:
                                        st.caption("KNOWN EXPLOITATION")
                                        st.write(exploited_text)
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
                                    confidence_reason = assessment.get("confidence_reason")
                                    if not confidence_reason:
                                        confidence_reason = (
                                            "The source quote could not be verified."
                                            if not finding.get("evidence_quote_verified")
                                            else "Some evidence is missing; confidence is Low until the finding is verified."
                                        )
                                    report_score = assessment["score"]
                                    report_score_text = (
                                        f"~{report_score}/10 (provisional)"
                                        if report_score is not None and assessment.get("provisional")
                                        else f"{report_score}/10"
                                        if report_score is not None
                                        else "Not enough evidence"
                                    )
                                    report_rows.append(
                                        {
                                            "CVE": finding.get("cve_id") or "Not stated",
                                            "Finding": finding.get("title") or "Untitled advisory",
                                            "Products": ", ".join(finding.get("products") or []) or "Not stated",
                                            "Severity": (
                                                f"{severity}/10" if severity is not None else severity_text or "Not stated"
                                            ),
                                            "Stack match": match["stack_match_status"].replace("_", " ").title(),
                                            "Risk score": report_score_text,
                                            "Confidence": assessment.get("confidence") or "Low",
                                            "Confidence basis": confidence_reason,
                                            "Source": finding.get("source_url") or result["url"],
                                            "Evidence": quote if finding.get("evidence_quote_verified") else "Not verified",
                                        }
                                    )
                                    score_col, detail_col = st.columns([1, 3])
                                    with score_col:
                                        display_score = (
                                            f"{'~' if assessment.get('provisional') else ''}{assessment['score']}/10"
                                            if assessment["score"] is not None
                                            else "— / 10"
                                        )
                                        st.metric("Risk score", display_score, border=True)
                                    with detail_col:
                                        if assessment["score"] is None:
                                            st.markdown(
                                                f"**Not enough evidence · Confidence: {assessment['confidence']}**"
                                            )
                                            st.caption(confidence_reason)
                                            with st.expander("Why no score?"):
                                                for missing_item in assessment["missing_evidence"]:
                                                    st.write(missing_item)
                                        else:
                                            st.markdown(f"**Confidence: {assessment['confidence']}**")
                                            if assessment.get("provisional"):
                                                st.caption(
                                                    f"Provisional · {assessment['available_factor_count']}/4 factors. "
                                                    + confidence_reason
                                                )
                                            else:
                                                st.caption(confidence_reason)
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
            if len(report_rows) == report_rows_before_result:
                lead_match = match_advisory_to_stack(
                    {"products": [result.get("product", "")]}, stack
                )
                cve_match = re.search(
                    r"CVE-\d{4}-\d{4,}",
                    f"{result.get('title', '')} {result.get('snippet', '')}",
                    re.IGNORECASE,
                )
                report_rows.append(
                    {
                        "CVE": cve_match.group(0).upper() if cve_match else "Not extracted",
                        "Finding": result.get("title") or "Untitled search result",
                        "Products": result.get("product") or "Not stated",
                        "Severity": "Not extracted",
                        "Stack match": lead_match["stack_match_status"].replace("_", " ").title(),
                        "Risk score": "Not assessed",
                        "Confidence": "Not assessed",
                        "Confidence basis": "Not extracted from a source yet.",
                        "Source": result.get("url", ""),
                        "Evidence": "Unverified search lead: " + (result.get("snippet") or "No snippet returned."),
                    }
                )
        if report_rows:
            with st.expander("Evidence report · all search results", icon=":material/description:"):
                st.caption("Includes extracted findings and unverified search leads.")
                stack_matches = sum(row["Stack match"] == "Matched" for row in report_rows)
                scored_findings = sum(
                    row["Risk score"] not in {"Not enough evidence", "Not assessed"}
                    for row in report_rows
                )
                high_findings = 0
                for row in report_rows:
                    severity_value = str(row["Severity"]).casefold()
                    try:
                        severity_value = float(severity_value.split("/")[0])
                    except ValueError:
                        severity_value = 9.5 if severity_value == "critical" else 8.0 if severity_value == "high" else 0.0
                    high_findings += severity_value >= 7
                metric_cols = st.columns(4)
                metric_cols[0].metric("Search leads", len(report_rows), border=True)
                metric_cols[1].metric("Stack matches", stack_matches, border=True)
                metric_cols[2].metric("High / critical", high_findings, border=True)
                metric_cols[3].metric("Scored", scored_findings, border=True)
                st.dataframe(
                    report_rows,
                    width="stretch",
                    hide_index=True,
                    column_config={"Source": st.column_config.LinkColumn("Source", display_text="Open source")},
                )
                csv_buffer = io.StringIO()
                writer = csv.DictWriter(csv_buffer, fieldnames=report_rows[0].keys())
                writer.writeheader()
                writer.writerows(report_rows)
                st.download_button(
                    "Download report",
                    data=csv_buffer.getvalue(),
                    file_name="zeroday-evidence-report.csv",
                    mime="text/csv",
                    icon=":material/download:",
                )
    elif st.session_state.get("advisory_has_searched"):
        st.info("No search results were returned for this stack. Try a more specific product name.")

    if fetch_errors:
        with st.expander(f"Pages that could not be fetched ({len(fetch_errors)})"):
            for item in fetch_errors:
                st.write(f"{item.get('url', 'Unknown URL')}: {item.get('error', 'Fetch failed')}")
else:
    st.info("Enter a small demo stack, then save it.")

with st.expander("About this report", icon=":material/info:"):
    st.caption("Risk scores use evidence from the advisory. Search results without verified extracted details remain unassessed.")
    st.caption("Score weights: 40% severity, 25% known exploitation, 25% stack match, and 10% recency.")
    st.markdown("**Finding fields**")
    st.code(
        "cve_id, title, products, affected_versions, fixed_versions, "
        "severity, known_exploited, published_at, source_url, fetched_at, "
        "stack_match, score, confidence, suggested_fix, evidence",
        language="text",
    )
