import streamlit as st
from src.tinyfish_client import TinyFishError, fetch_pages, search_advisories

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
        for key in ("advisory_search_results", "advisory_fetched_pages", "advisory_fetch_errors", "advisory_has_searched"):
            st.session_state.pop(key, None)
    st.session_state["tech_stack"] = stack

stack = st.session_state.get("tech_stack", [])
if stack:
    st.subheader("MVP stack")
    st.write(stack)
    try:
        api_key = st.secrets.get("TINYFISH_API_KEY", "")
    except Exception:
        api_key = ""

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
        st.caption("Search results are leads for review. CVE extraction and stack matching come in later phases.")
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
